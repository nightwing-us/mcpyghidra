"""Unit tests for MCPPortManager range-based port management.

Mirrors the sys.modules Ghidra-stub preamble from test_server_branches.py so
mcpserver can be imported without a JVM.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ghidra stubs — same set as test_server_branches.py
# ---------------------------------------------------------------------------

_GHIDRA_STUBS = [
    'ghidra',
    'ghidra.app',
    'ghidra.app.services',
    'ghidra.program',
    'ghidra.program.model',
    'ghidra.program.model.address',
    'ghidra.program.model.listing',
    'ghidra.program.model.mem',
    'ghidra.program.model.symbol',
    'ghidra.program.util',
    'java',
    'java.io',
    'java.io.File',
]

for _mod in _GHIDRA_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

_mock_application = MagicMock()
_mock_application.getName.return_value = 'Ghidra'
_mock_application.getApplicationVersion.return_value = '11.0'
_mock_ghidra_framework = MagicMock()
_mock_ghidra_framework.Application = _mock_application
sys.modules['ghidra.framework'] = _mock_ghidra_framework


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

from mcpyghidra.mcpserver import (  # noqa: E402
    GhidraMcpServer,
    GhidraMcpServerState,
    MCPPortManager,
    PORT_SPAN,
)


def _prog(path: str):
    p = MagicMock()
    p.getDomainFile.return_value.getPathname.return_value = path
    return p


def _mgr(port_start=6050):
    return MCPPortManager(MagicMock(), MagicMock(), port_start=port_start)


def test_span_default():
    assert PORT_SPAN == 10


def test_candidate_ports_full_range_when_empty():
    m = _mgr()
    assert m.candidate_ports(_prog('/a')) == list(range(6050, 6060))


def test_record_and_used_ports():
    m = _mgr()
    m.record(_prog('/a'), 6050)
    assert m.used_ports() == {6050}


def test_candidate_ports_excludes_other_programs():
    m = _mgr()
    m.record(_prog('/a'), 6050)
    # program /b must not be offered 6050 (held by /a)
    assert 6050 not in m.candidate_ports(_prog('/b'))
    assert m.candidate_ports(_prog('/b'))[0] == 6051


def test_candidate_ports_prefers_prior_port_for_same_program():
    m = _mgr()
    m.record(_prog('/a'), 6055)
    cands = m.candidate_ports(_prog('/a'))
    assert cands[0] == 6055  # reuse its own port first


def test_get_port_by_path():
    MCPPortManager._instance = None
    m = _mgr()
    MCPPortManager._instance = m
    m.record(_prog('/a'), 6051)
    assert MCPPortManager.get_port_by_path('/a') == 6051


# ---------------------------------------------------------------------------
# Fix 3 (Minor) — PORT_SPAN <-> DEFAULT_PORT_SPEC agreement
# ---------------------------------------------------------------------------


def test_port_span_matches_default_spec():
    from mcpyghidra.portspec import DEFAULT_PORT_SPEC, parse_port_spec

    assert len(parse_port_spec(DEFAULT_PORT_SPEC)) == PORT_SPAN


# ---------------------------------------------------------------------------
# Fix 2 (Important) — GhidraMcpServer.start() bind/ERROR/record orchestration
# ---------------------------------------------------------------------------


class TestGhidraMcpServerStart:
    """Unit tests for start() covering the OSError path and the record-after-bind path.

    Uses create_headless() to construct a GhidraMcpServer without a real JVM.
    _Msg, create_mcp_app, bind_listen_socket, uvicorn, ThreadedServer, and Thread
    are all patched so no networking or GUI machinery runs.
    """

    def setup_method(self):
        MCPPortManager._instance = None

    def teardown_method(self):
        MCPPortManager._instance = None

    def test_start_oserror_sets_error_state_and_no_thread(self):
        """All bind candidates fail -> state is ERROR and no server thread is started."""
        backend = MagicMock()
        backend.program = _prog('/test/path')
        srv = GhidraMcpServer.create_headless(backend)

        with (
            patch('mcpyghidra.mcpserver._Msg', return_value=MagicMock()),
            patch('mcpyghidra.server.create_mcp_app', return_value=(MagicMock(), MagicMock())),
            patch(
                'mcpyghidra.portspec.bind_listen_socket',
                side_effect=OSError('all ports busy'),
            ),
        ):
            srv.start()

        assert srv.state == GhidraMcpServerState.ERROR
        assert srv._server_thread is None

    def test_start_success_records_port_in_manager(self):
        """Successful bind -> self.port is set and port manager records the bound port."""
        backend = MagicMock()
        prog = _prog('/fw/path')
        backend.program = prog
        backend.is_headless = False

        srv = GhidraMcpServer.create_headless(backend)
        srv._port_manager = MCPPortManager(MagicMock(), MagicMock(), port_start=6050)

        fake_sock = MagicMock()
        mock_thread_instance = MagicMock()

        with (
            patch('mcpyghidra.mcpserver._Msg', return_value=MagicMock()),
            patch('mcpyghidra.server.create_mcp_app', return_value=(MagicMock(), MagicMock())),
            patch(
                'mcpyghidra.portspec.bind_listen_socket',
                return_value=(fake_sock, 6053),
            ),
            patch('mcpyghidra.mcpserver.uvicorn'),
            patch('mcpyghidra.mcpserver.ThreadedServer') as mock_ts,
            patch('mcpyghidra.mcpserver.Thread', return_value=mock_thread_instance),
        ):
            mock_ts_instance = MagicMock()
            mock_ts_instance.started = True  # prevent busy-wait loop
            mock_ts.return_value = mock_ts_instance
            srv.start()

        assert srv.port == 6053
        assert srv._port_manager._program_path_to_port.get('/fw/path') == 6053
