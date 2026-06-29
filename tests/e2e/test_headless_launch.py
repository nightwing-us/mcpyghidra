"""E2E test: prove that headless launch works.

This test IS the contract for MCP client integration.
If it passes, any MCP client can launch mcpyghidra-headless
and connect to the server.

Uses the MCP client library (mcp package) for proper protocol-level
communication, not raw HTTP POST.
"""
import json

import anyio

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Timeout for individual MCP tool calls (seconds)
MCP_CALL_TIMEOUT = 30


def _parse_payload(text: str):
    """Parse an MCP tool's text payload as JSON (the dual tools return JSON).

    Returns the parsed object (dict for a single/flat call, list for a batch
    call) so tests can assert the return *shape*, not just substring content.
    """
    return json.loads(text)


class TestHeadlessLaunch:
    """Validate the headless launch contract."""

    def test_server_reports_ready(self, headless_server):
        """Server process launched and reported ready with valid status."""
        assert headless_server['status'] == 'ready'
        assert headless_server['port'] > 0
        assert headless_server['host'] == '127.0.0.1'
        assert 'crackme' in headless_server['binary']

    def test_mcp_endpoint_reachable(self, headless_server):
        """MCP endpoint responds to client initialize."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 1,
        })
        # If we got here without exception, the endpoint is reachable
        assert result is not None

    def test_list_functions_finds_main(self, headless_server):
        """Can call 'list' tool and find 'main' in our test binary."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 100,
        })
        assert 'main' in result, (
            f'Expected "main" in function list, got: {result[:500]}'
        )

    def test_decompile_main(self, headless_server):
        """Can decompile 'main' and see call to check_password."""
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'main'}],
        })
        assert 'check_password' in result, (
            f'Expected "check_password" in decompilation, got: {result[:500]}'
        )

    def test_decompile_single_flat_call(self, headless_server):
        """Flat single call (name=) works end-to-end and yields one result object.

        NOTE: the exact single->dict vs batch->list *unwrap* is proven directly by
        the unit tests (tests/unit/test_dispatch.py). The MCP text layer emits one
        content block per list element, so a 1-element list flattens to the same
        payload as a dict — the precise shape is therefore asserted at the unit
        layer; here we assert the single call works and returns one object.
        """
        result = mcp_call(headless_server, 'decompile', {'name': 'main'})
        assert 'check_password' in result, (
            f'Expected "check_password" in single decompile of main, got: {result[:500]}'
        )
        assert isinstance(_parse_payload(result), dict), (
            f'Single flat call should yield one object, got: {result[:200]}'
        )

    def test_decompile_batch_two_items_returns_both(self, headless_server):
        """Batch call with two items returns BOTH results — proves batch multiplicity.

        (A single flat call can only ever produce one result, so two results back
        is the observable end-to-end signature of the batch path.)
        """
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'main'}, {'name': 'check_password'}],
        })
        # Each result dict carries an 'entrypoint' field; two results -> >=2.
        assert result.count('entrypoint') >= 2, (
            f'Expected two decompilation results, got: {result[:600]}'
        )
        assert 'main' in result and 'check_password' in result

    def test_funcs_bare_call_hints_list(self, headless_server):
        """Bare funcs() returns instructive error, not a schema 'items required' error."""
        try:
            mcp_call(headless_server, 'funcs', {})
            msg = ''
        except AssertionError as e:
            msg = str(e)
        assert 'list(entry_type="function")' in msg or 'provide target' in msg, (
            f'Expected instructive hint in error, got: {msg[:500]}'
        )

    def test_parallel_servers_get_distinct_ports(self, tmp_path):
        """Two headless servers on the default range bind distinct ports (no collision)."""
        import subprocess
        import sys

        from tests.conftest import CRACKME_ELF
        from tests.e2e.conftest import LAUNCH_TIMEOUT, _wait_for_ready

        # Each server gets its own project dir so they don't collide on the
        # Ghidra project lock (and don't conflict with the module-scoped
        # headless_server fixture which also has crackme open).
        def launch(proj_name):
            return subprocess.Popen(
                [sys.executable, '-m', 'mcpyghidra.headless', CRACKME_ELF,
                 '--project-dir', str(tmp_path), '--project-name', proj_name],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )

        p1 = launch('crackme_parallel_1')
        try:
            s1 = _wait_for_ready(p1, LAUNCH_TIMEOUT)
            p2 = launch('crackme_parallel_2')
            try:
                s2 = _wait_for_ready(p2, LAUNCH_TIMEOUT)
                assert 6050 <= s1['port'] <= 6059
                assert 6050 <= s2['port'] <= 6059
                assert s1['port'] != s2['port']
            finally:
                p2.terminate()
                p2.wait(timeout=30)
        finally:
            p1.terminate()
            p1.wait(timeout=30)

    def test_busy_single_port_is_port_unavailable(self, tmp_path):
        """A bare busy --port yields a port_unavailable JSON line + exit 6."""
        import json
        import socket
        import subprocess
        import sys

        from tests.conftest import CRACKME_ELF

        busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(('127.0.0.1', 0))
        busy.listen(1)
        taken = busy.getsockname()[1]
        try:
            proc = subprocess.run(
                [sys.executable, '-m', 'mcpyghidra.headless', CRACKME_ELF,
                 '--host', '127.0.0.1', '--port', str(taken),
                 '--project-dir', str(tmp_path), '--project-name', 'busy_test'],
                capture_output=True, text=True, timeout=300,
            )
        finally:
            busy.close()
        assert proc.returncode == 6, f'stdout={proc.stdout[-500:]} stderr={proc.stderr[-300:]}'
        last = json.loads(proc.stdout.strip().splitlines()[-1])
        assert last['reason'] == 'port_unavailable'

    def test_bad_port_spec_exits_nonzero(self):
        """A malformed --port exits non-zero before starting the JVM."""
        import subprocess
        import sys

        from tests.conftest import CRACKME_ELF

        proc = subprocess.run(
            [sys.executable, '-m', 'mcpyghidra.headless', CRACKME_ELF,
             '--port', 'not-a-port'],
            capture_output=True, text=True, timeout=30,
        )
        import json
        last = json.loads(proc.stdout.strip().splitlines()[-1])
        assert proc.returncode == 5
        assert last['reason'] == 'bad_port'

    def test_config_echo_on_stderr(self, tmp_path):
        """Startup echoes the resolved Ghidra install + binary to stderr."""
        import subprocess
        import sys

        from tests.conftest import CRACKME_ELF
        from tests.e2e.conftest import LAUNCH_TIMEOUT, _wait_for_ready

        proc = subprocess.Popen(
            [sys.executable, '-m', 'mcpyghidra.headless', CRACKME_ELF,
             '--project-dir', str(tmp_path), '--project-name', 'echo_test', '--port', '0'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            _wait_for_ready(proc, LAUNCH_TIMEOUT)
            proc.terminate()
            _, err = proc.communicate(timeout=30)
            assert 'Using Ghidra' in err and 'crackme.elf' in err
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


async def _mcp_call(url: str, tool_name: str, arguments: dict) -> str:
    """Call an MCP tool via the streamable HTTP transport and return text content.

    Uses anyio.fail_after for timeout protection — prevents tests from
    hanging indefinitely if the server accepts the connection but stalls.

    Raises AssertionError (with error text) when the MCP tool returns an error.
    The error is raised *outside* all TaskGroup contexts to avoid anyio wrapping
    it in an ExceptionGroup.
    """
    error_msg: str | None = None
    text_result: str = ''

    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                result = await session.call_tool(tool_name, arguments)
            # Collect result or error — raise outside the TaskGroup context
            if result.isError:
                error_texts = [
                    item.text for item in result.content if hasattr(item, 'text')
                ]
                error_msg = f"MCP tool '{tool_name}' returned error: {' '.join(error_texts)}"
            else:
                texts = [
                    item.text
                    for item in result.content
                    if hasattr(item, 'text')
                ]
                text_result = '\n'.join(texts)

    # Raise outside all async context managers so anyio does not wrap in ExceptionGroup
    if error_msg:
        raise AssertionError(error_msg)
    return text_result


def mcp_call(server_status: dict, tool_name: str, arguments: dict) -> str:
    """Synchronous wrapper around _mcp_call for use in pytest test methods."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call, url, tool_name, arguments)
