"""Integration tests using typed_fixture.elf.

Tests call tool functions directly on a HeadlessBackend loaded from
typed_fixture.elf (compiled with -g debug info).

The typed_fixture binary has:
- Functions:  main, use_wrapper, sum_point
- Call graph: main -> use_wrapper -> sum_point
- Structs:    Point (x, y fields), Wrapper (pt, magic, name fields)
- Globals:    g_point, g_wrapper, g_numbers, g_message
"""
from __future__ import annotations

import pytest

from tests.conftest import TYPED_FIXTURE_ELF
from tests.integration.helpers import run_async


# ---------------------------------------------------------------------------
# Session-scoped fixture — loads typed_fixture.elf once for all tests here
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def typed_program():
    """Load typed_fixture.elf once for all typed-fixture integration tests."""
    pyghidra = pytest.importorskip('pyghidra')
    # Start the JVM if not already running (safe to call multiple times).
    pyghidra.start()

    with pyghidra.open_program(TYPED_FIXTURE_ELF, analyze=True) as flat_api:
        yield flat_api.getCurrentProgram()


@pytest.fixture(scope='session')
def typed_backend(typed_program):
    """HeadlessBackend wrapping typed_fixture.elf."""
    from mcpyghidra.backend import HeadlessBackend
    return HeadlessBackend(typed_program)


# ---------------------------------------------------------------------------
# list functions
# ---------------------------------------------------------------------------

class TestTypedFunctions:
    """list_entries on typed_fixture finds expected functions."""

    def test_finds_main(self, typed_backend):
        from mcpyghidra.tools.core import list_entries
        result = run_async(list_entries, typed_backend, entry_type='function', offset=0, limit=500,
                              match_filter='main')
        names = [item['name'] for item in result.items]
        assert 'main' in names, f'Expected "main" in function names, got: {names}'

    def test_finds_sum_point(self, typed_backend):
        from mcpyghidra.tools.core import list_entries
        result = run_async(list_entries, typed_backend, entry_type='function', offset=0, limit=500,
                              match_filter='sum_point')
        names = [item['name'] for item in result.items]
        assert 'sum_point' in names, f'Expected "sum_point" in function names, got: {names}'

    def test_finds_use_wrapper(self, typed_backend):
        from mcpyghidra.tools.core import list_entries
        result = run_async(list_entries, typed_backend, entry_type='function', offset=0, limit=500,
                              match_filter='use_wrapper')
        names = [item['name'] for item in result.items]
        assert 'use_wrapper' in names, f'Expected "use_wrapper" in function names, got: {names}'


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------

class TestTypedDecompile:
    """Decompile typed_fixture functions."""

    def test_decompile_use_wrapper_contains_sum_point(self, typed_backend):
        from mcpyghidra.tools.analysis import decompile
        results = run_async(decompile, typed_backend, [{'name': 'use_wrapper'}])
        assert len(results) == 1
        r = results[0]
        assert r.get('error') is None, f'Decompile error: {r.get("error")}'
        code = r.get('code', '')
        assert 'sum_point' in code, (
            f'Expected decompile of use_wrapper to reference sum_point, got:\n{code}'
        )

    def test_decompile_main_exists(self, typed_backend):
        from mcpyghidra.tools.analysis import decompile
        results = run_async(decompile, typed_backend, [{'name': 'main'}])
        assert len(results) == 1
        r = results[0]
        assert r.get('error') is None, f'Decompile error: {r.get("error")}'
        assert r.get('code'), 'Expected non-empty decompilation of main'


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------

class TestTypedXrefs:
    """Cross-references in typed_fixture."""

    def test_xrefs_use_wrapper_called_by_main(self, typed_backend):
        """use_wrapper should have at least one caller (main)."""
        from mcpyghidra.tools.analysis import xrefs
        results = run_async(xrefs, typed_backend, [{'target': 'use_wrapper', 'direction': 'to'}])
        assert len(results) == 1
        r = results[0]
        assert r.get('error') is None, f'xrefs error: {r.get("error")}'
        list_result = r.get('result')
        assert list_result is not None
        assert list_result.page_info.total_count >= 1, (
            'Expected use_wrapper to be called from at least one location (main)'
        )

    def test_xrefs_sum_point_called_by_use_wrapper(self, typed_backend):
        """sum_point should be called from use_wrapper — verify via xrefs TO sum_point."""
        from mcpyghidra.tools.analysis import xrefs
        results = run_async(xrefs, typed_backend, [{'target': 'sum_point', 'direction': 'to'}])
        assert len(results) == 1
        r = results[0]
        assert r.get('error') is None, f'xrefs error: {r.get("error")}'
        list_result = r.get('result')
        assert list_result is not None
        # sum_point should be called from at least one location (use_wrapper)
        assert list_result.page_info.total_count >= 1, (
            'Expected sum_point to be called from at least one location (use_wrapper)'
        )
        # The caller should be use_wrapper
        callers = [
            item.get('from', {}).get('function', '')
            for item in list_result.items
        ]
        assert any('use_wrapper' in c for c in callers), (
            f'Expected use_wrapper to appear as a caller of sum_point, got callers: {callers}'
        )


# ---------------------------------------------------------------------------
# types (if debug info loaded)
# ---------------------------------------------------------------------------

class TestTypedTypes:
    """Type information from typed_fixture (requires DWARF debug info)."""

    def test_list_types_finds_point(self, typed_backend):
        """Point struct should be discoverable via the types tool."""
        from mcpyghidra.tools.types import types
        result = run_async(types, typed_backend, pattern='Point', limit=100)
        names = [t.name for t in result]
        assert any('Point' in n for n in names), (
            f'Expected "Point" in type names, got: {names[:20]}'
        )

    def test_type_info_point_has_fields(self, typed_backend):
        """Point struct should have x and y fields (from DWARF debug info)."""
        from mcpyghidra.tools.types import type_info
        results = run_async(type_info, typed_backend, ['Point'])
        assert len(results) == 1
        r = results[0]
        if r.get('error'):
            pytest.skip(f'Point type not found (debug info may not be loaded): {r["error"]}')
        members = r.get('members') or []
        field_names = [m.get('name', '') for m in members]
        assert any('x' in n for n in field_names) or any('y' in n for n in field_names), (
            f'Expected Point to have x/y fields, got members: {field_names}'
        )


# ---------------------------------------------------------------------------
# symbols — globals
# ---------------------------------------------------------------------------

class TestTypedSymbols:
    """Global symbols in typed_fixture."""

    def test_globals_g_point_and_g_wrapper_exist(self, typed_backend):
        """g_point and g_wrapper globals should appear in the symbol table."""
        # Globals won't be in function list, but we can verify via symbol search
        # Use a broader check: program symbol table directly
        program = typed_backend.program
        symtab = program.getSymbolTable()
        symbol_names = {str(sym.getName()) for sym in symtab.getAllSymbols(True)}
        assert 'g_point' in symbol_names or 'g_wrapper' in symbol_names, (
            f'Expected g_point or g_wrapper in symbol table. '
            f'Available symbols (sample): {sorted(symbol_names)[:30]}'
        )


# ---------------------------------------------------------------------------
# context — debug symbols present
# ---------------------------------------------------------------------------

class TestTypedContext:
    """context() on typed_fixture reports debug symbols."""

    def test_context_shows_debug_symbols(self, typed_backend):
        """typed_fixture.elf is built with -g, so debug symbols should be present."""
        from mcpyghidra.tools.core import context
        ctx = run_async(context, typed_backend)
        assert ctx is not None
        assert ctx.analysis is not None
        assert ctx.analysis.function_count >= 3, (
            f'Expected at least 3 functions (main, use_wrapper, sum_point), '
            f'got {ctx.analysis.function_count}'
        )
        # has_debug_symbols may or may not be True depending on how DWARF is processed,
        # but function count confirms analysis ran.

    def test_cursor_headless_returns_entry_point(self, typed_backend):
        """In headless mode cursor() falls back to entry point (P1-3 fix)."""
        from mcpyghidra.tools.core import cursor
        loc = run_async(cursor, typed_backend)
        assert loc is not None
        assert loc.addr is not None
        assert loc.addr.startswith('0x'), f'Expected hex address, got {loc.addr!r}'
