"""Integration test fixtures — loads binary via pyghidra, provides backend and server."""
from __future__ import annotations

import pytest

from tests.conftest import CRACKME_ELF, TYPED_FIXTURE_ELF
from tests.integration.helpers import open_analyzed_program


@pytest.fixture(scope='session')
def ghidra_program(tmp_path_factory):
    """Load crackme.elf once for all integration tests."""
    pyghidra = pytest.importorskip('pyghidra')
    pyghidra.start()

    project_dir = str(tmp_path_factory.mktemp('ghidra_proj'))
    with open_analyzed_program(pyghidra, CRACKME_ELF, project_dir) as program:
        yield program


@pytest.fixture(scope='session')
def backend(ghidra_program):
    """Create HeadlessBackend instance for direct tool function calls."""
    from mcpyghidra.backend import HeadlessBackend
    return HeadlessBackend(ghidra_program)


@pytest.fixture(scope='session')
def typed_program(tmp_path_factory):
    """Load typed_fixture.elf once for all typed-fixture integration tests."""
    pyghidra = pytest.importorskip('pyghidra')
    pyghidra.start()

    project_dir = str(tmp_path_factory.mktemp('ghidra_typed_proj'))
    with open_analyzed_program(pyghidra, TYPED_FIXTURE_ELF, project_dir) as program:
        yield program


@pytest.fixture(scope='session')
def typed_backend(typed_program):
    """HeadlessBackend wrapping typed_fixture.elf."""
    from mcpyghidra.backend import HeadlessBackend
    return HeadlessBackend(typed_program)


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
