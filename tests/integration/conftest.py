"""Integration test fixtures — loads binary via pyghidra, provides backend and server."""
from __future__ import annotations

import pytest

from tests.conftest import CRACKME_ELF


@pytest.fixture(scope='session')
def ghidra_program():
    """Load crackme.elf once for all integration tests."""
    pyghidra = pytest.importorskip('pyghidra')
    pyghidra.start()

    with pyghidra.open_program(CRACKME_ELF, analyze=True) as flat_api:
        yield flat_api.getCurrentProgram()


@pytest.fixture(scope='session')
def backend(ghidra_program):
    """Create HeadlessBackend instance for direct tool function calls."""
    from mcpyghidra.backend import HeadlessBackend
    return HeadlessBackend(ghidra_program)


@pytest.fixture(scope='session')
def server(ghidra_program):
    """Backward-compat fixture: wraps backend in GhidraMcpServer.

    New tests should use the ``backend`` fixture and call tool functions directly.
    """
    from mcpyghidra.backend import HeadlessBackend
    from mcpyghidra.mcpserver import GhidraMcpServer

    be = HeadlessBackend(ghidra_program)
    srv = GhidraMcpServer.create_headless(be)
    return srv
