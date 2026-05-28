"""E2E tests for Ghidra GUI features: server info, project binaries, tools.

Requires: xvfb-run, bwrap, pyghidra, Ghidra 12.0.4+
Uses fully isolated Ghidra GUI via tests/e2e/ghidra_gui_helper.py

The test fixture auto-launches Ghidra GUI under Xvfb+bwrap with
git-committed project state (restored before each run for consistency).
Skips if prerequisites are missing.
"""
from __future__ import annotations

import json

import anyio
import pytest
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession

from tests.e2e.ghidra_gui_helper import (
    _check_prerequisites,
    TEST_MCP_PORT,
)

_skip_reason = _check_prerequisites()
pytestmark = pytest.mark.skipif(_skip_reason is not None, reason=_skip_reason or '')

MCP_CALL_TIMEOUT = 30


@pytest.fixture(scope='module', autouse=True)
def gui_server():
    """Launch Ghidra GUI MCP server under Xvfb+bwrap.

    Uses a shell script to fully isolate from pytest's process group.
    Fixture files are restored to git-committed state before launch.
    """
    import os
    import signal
    import socket
    import subprocess as sp
    import time
    from pathlib import Path
    from tests.e2e.ghidra_gui_helper import _kill_port, FIXTURE_DIR

    err = _check_prerequisites()
    if err:
        pytest.skip(err)

    # Reuse existing server if already running
    try:
        with socket.create_connection(('127.0.0.1', TEST_MCP_PORT), timeout=2):
            yield {'host': '127.0.0.1', 'port': TEST_MCP_PORT}
            return
    except (ConnectionRefusedError, OSError):
        pass

    _kill_port(TEST_MCP_PORT)

    # Launch via shell script — fully detached from pytest's process group
    script = Path(__file__).parent / 'start_gui_server.sh'
    log_file = FIXTURE_DIR / 'server_stdout.log'
    log_fd = open(log_file, 'w')
    proc = sp.Popen(
        [str(script)],
        stdout=log_fd,
        stderr=sp.STDOUT,
        start_new_session=True,
    )

    def _stash_log() -> None:
        """Copy log to /tmp before any failure path / git restore destroys it."""
        try:
            log_fd.flush()
        except Exception:
            pass
        try:
            import shutil
            shutil.copy(log_file, '/tmp/server_stdout.log')
        except Exception:
            pass

    # Wait for server
    deadline = time.monotonic() + 120
    server_up = False
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', TEST_MCP_PORT), timeout=1):
                server_up = True
                break
        except (ConnectionRefusedError, OSError):
            pass
        if proc.poll() is not None:
            _stash_log()
            pytest.fail(f'GUI server script exited with code {proc.returncode}')
        time.sleep(2)

    if not server_up:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait()
        _stash_log()
        pytest.fail(f'GUI server did not start on port {TEST_MCP_PORT} within 120s')

    try:
        yield {'host': '127.0.0.1', 'port': TEST_MCP_PORT}
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            proc.wait(timeout=5)
        except sp.TimeoutExpired:
            proc.kill()
            proc.wait()
        _kill_port(TEST_MCP_PORT)
        log_fd.close()
        _stash_log()
        # Restore fixture files (skip in CI where git checkout is a no-op
        # against a non-pristine container — the container is throwaway).
        if os.environ.get('MCPYGHIDRA_GUI_NO_BWRAP') != '1':
            sp.run(
                ['git', 'checkout', '--', 'tests/fixtures/ghidra_gui_test/'],
                cwd=str(Path(__file__).parent.parent.parent),
                capture_output=True,
            )


def _mcp_call_sync(server, tool_name, args, timeout=MCP_CALL_TIMEOUT):
    """Call an MCP tool synchronously."""
    async def _call():
        url = f"http://{server['host']}:{server['port']}/mcp"
        async with streamablehttp_client(url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                with anyio.fail_after(timeout):
                    return await session.call_tool(tool_name, args)
    return anyio.run(_call)


def _mcp_read_resource_sync(server, uri):
    """Read an MCP resource synchronously."""
    from pydantic import AnyUrl
    async def _call():
        url = f"http://{server['host']}:{server['port']}/mcp"
        async with streamablehttp_client(url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                with anyio.fail_after(MCP_CALL_TIMEOUT):
                    return await session.read_resource(AnyUrl(uri))
    return anyio.run(_call)


class TestServerInfo:
    """Test server://info resource in GUI mode."""

    def test_server_info_returns_json(self, gui_server):
        result = _mcp_read_resource_sync(gui_server, 'server://info')
        assert len(result.contents) > 0
        data = json.loads(result.contents[0].text)
        required = {'tool', 'version', 'mode', 'binary', 'binary_path',
                    'architecture', 'analysis_status', 'port'}
        assert required <= set(data.keys()), f'Missing: {required - set(data.keys())}'

    def test_server_info_mode_is_gui(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'server://info').contents[0].text)
        assert data['mode'] == 'gui'

    def test_server_info_has_binary(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'server://info').contents[0].text)
        assert data['binary'] is not None
        assert 'crackme' in data['binary'].lower()

    def test_server_info_has_port(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'server://info').contents[0].text)
        assert data['port'] == TEST_MCP_PORT


class TestProjectBinaries:
    """Test project://binaries resource in GUI mode."""

    def test_project_binaries_returns_json(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'project://binaries').contents[0].text)
        assert 'project_name' in data
        assert 'binaries' in data

    def test_project_binaries_lists_crackme(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'project://binaries').contents[0].text)
        names = [b['name'] for b in data['binaries']]
        assert any('crackme' in n.lower() for n in names)

    def test_project_binaries_shows_open_status(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'project://binaries').contents[0].text)
        crackme = [b for b in data['binaries'] if 'crackme' in b['name'].lower()]
        assert len(crackme) > 0
        assert crackme[0]['is_open'] is True

    def test_project_binaries_shows_mcp_port(self, gui_server):
        data = json.loads(_mcp_read_resource_sync(gui_server, 'project://binaries').contents[0].text)
        crackme = [b for b in data['binaries'] if 'crackme' in b['name'].lower()]
        assert len(crackme) > 0
        assert crackme[0]['has_mcp_server'] is True
        assert crackme[0]['mcp_port'] == TEST_MCP_PORT


class TestGUITools:
    """Test GUI-only tools are available and work."""

    def test_open_program_tool_listed(self, gui_server):
        async def _check():
            url = f"http://{gui_server['host']}:{gui_server['port']}/mcp"
            async with streamablehttp_client(url) as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    return [t.name for t in tools.tools]
        names = anyio.run(_check)
        assert 'open_program' in names

    def test_cfg_tool_works(self, gui_server):
        result = _mcp_call_sync(gui_server, 'cfg', {'address': 'main'})
        assert not result.isError
        data = json.loads(result.content[0].text)
        assert 'blocks' in data
        assert data['block_count'] > 0

    def test_decompile_works(self, gui_server):
        result = _mcp_call_sync(gui_server, 'decompile', {'items': [{'name': 'main'}]})
        assert not result.isError

    @pytest.mark.skip(reason='Requires manual GUI interaction (analysis dialog) — run with pre-started server')
    def test_open_program_launches_new_server(self, gui_server):
        """open_program imports a binary and launches a new CodeBrowser with its own MCP server."""
        import socket
        from pathlib import Path

        typed_fixture = str(Path(__file__).parent.parent / 'fixtures' / 'typed_fixture.elf')

        # Call open_program with typed_fixture.elf — needs long timeout for import+analysis+server start
        result = _mcp_call_sync(gui_server, 'open_program', {
            'path_or_name': typed_fixture,
            'wait': True,
            'timeout': 120,
        }, timeout=180)
        assert not result.isError, f'open_program failed: {result.content[0].text}'
        data = json.loads(result.content[0].text)

        assert data['status'] == 'ready', f'Expected ready, got: {data}'
        assert data['binary'] is not None
        assert 'typed_fixture' in data['binary'].lower()
        assert data['new_server'] is not None, 'No new server info returned'
        assert data['new_server']['port'] is not None, 'No port assigned'

        new_port = data['new_server']['port']
        assert new_port != TEST_MCP_PORT, f'New server should be on a different port than {TEST_MCP_PORT}'

        # Verify the new server is actually responding
        try:
            with socket.create_connection(('127.0.0.1', new_port), timeout=5):
                pass
        except (ConnectionRefusedError, OSError):
            pytest.fail(f'New MCP server on port {new_port} is not responding')

        # Connect to the new server and verify it has the right binary
        new_server = {'host': '127.0.0.1', 'port': new_port}
        info = json.loads(
            _mcp_read_resource_sync(new_server, 'server://info').contents[0].text
        )
        assert 'typed_fixture' in info['binary'].lower(), (
            f'New server has wrong binary: {info["binary"]}'
        )

        # Verify the new server has tools and they work
        new_tools_result = _mcp_call_sync(new_server, 'cfg', {'address': 'main'})
        assert not new_tools_result.isError, 'cfg on new server failed'
        new_cfg = json.loads(new_tools_result.content[0].text)
        assert new_cfg['block_count'] > 0

        # Verify original server is still running with crackme.elf
        original_info = json.loads(
            _mcp_read_resource_sync(gui_server, 'server://info').contents[0].text
        )
        assert 'crackme' in original_info['binary'].lower(), (
            'Original server should still have crackme.elf'
        )
