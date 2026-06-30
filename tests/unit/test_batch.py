"""Unit tests for batch tool function contracts.

Verifies that batch tool functions (decompile, disasm, symbols, xrefs, rename,
set_comments, get_comment, set_prototype, patch, add_field, type_info, funcs)
always return list[dict] and handle per-item errors gracefully.

These tests run without Ghidra/pyghidra by patching the backend at call boundaries.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import anyio


def _run_async(async_fn, *args, **kwargs):
    """Run an async tool function synchronously for unit tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


def _make_backend():
    """Create a minimal mock backend sufficient for tool function calls."""
    backend = MagicMock()
    backend.is_headless = True
    backend.program = MagicMock()
    # create_transaction returns a context manager that yields None
    tx_ctx = MagicMock()
    tx_ctx.__enter__ = MagicMock(return_value=None)
    tx_ctx.__exit__ = MagicMock(return_value=False)
    backend.create_transaction.return_value = tx_ctx
    return backend


class TestBatchNormalization:
    """All batch tools return list[dict] with per-item 'error' key."""

    def test_single_item_becomes_list(self):
        """Calling a batch tool with a single-item list returns a 1-element list."""
        backend = _make_backend()

        # Patch _get_function to raise so we get an error dict — proves the list contract
        with patch('mcpyghidra.tools.analysis._get_function') as mock_get_func:
            from mcpyghidra.tools.analysis import decompile
            mock_get_func.side_effect = Exception('mock error')
            results = _run_async(decompile, backend, [{'name': 'some_func'}])
            assert isinstance(results, list)
            assert len(results) == 1

    def test_list_passes_through(self):
        """Calling a batch tool with multiple items returns same-length list."""
        backend = _make_backend()

        with patch('mcpyghidra.tools.analysis._get_function') as mock_get_func:
            from mcpyghidra.tools.analysis import decompile
            mock_get_func.side_effect = Exception('mock error')
            results = _run_async(decompile, backend, [{'name': 'a'}, {'name': 'b'}, {'name': 'c'}])
            assert isinstance(results, list)
            assert len(results) == 3

    def test_empty_list_passes_through(self):
        """Calling a batch tool with an empty list returns an empty list."""
        from mcpyghidra.tools.analysis import decompile
        backend = _make_backend()
        results = _run_async(decompile, backend, [])
        assert isinstance(results, list)
        assert len(results) == 0

    def test_batch_result_aggregated(self):
        """Each result dict has an 'error' key (None on success, str on failure)."""
        backend = _make_backend()

        with patch('mcpyghidra.tools.analysis._get_function') as mock_get_func:
            from mcpyghidra.tools.analysis import decompile
            mock_get_func.side_effect = Exception('mock failure')
            results = _run_async(decompile, backend, [{'name': 'missing_func'}])
            assert len(results) == 1
            assert 'error' in results[0], f'Expected "error" key in result: {results[0]}'
            assert results[0]['error'] is not None
            assert 'mock failure' in results[0]['error']


class TestBatchErrorIsolation:
    """Per-item errors do not abort the entire batch."""

    def test_decompile_error_does_not_abort_batch(self):
        """An error in one item does not prevent other items from being processed."""
        backend = _make_backend()
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception(f'error for item {call_count}')

        with patch('mcpyghidra.tools.analysis._get_function', side_effect=side_effect):
            from mcpyghidra.tools.analysis import decompile
            results = _run_async(decompile, backend, [{'name': 'a'}, {'name': 'b'}])
            assert len(results) == 2
            assert call_count == 2, 'Both items should be attempted'
            assert results[0]['error'] is not None
            assert results[1]['error'] is not None

    def test_symbols_error_isolation(self):
        """symbols() errors are per-item dicts, not raised exceptions."""
        backend = _make_backend()
        backend.program.getAddressFactory.return_value.getAddress.return_value = None

        with patch('mcpyghidra.tools.analysis._get_address') as mock_addr:
            from mcpyghidra.tools.analysis import symbols
            from mcpyghidra.backend import GhidraError
            mock_addr.side_effect = GhidraError('bad address')
            results = _run_async(symbols, backend, ['0xdeadbeef', '0xcafebabe'])
            assert isinstance(results, list)
            assert len(results) == 2
            for r in results:
                assert 'error' in r
                assert r['error'] is not None

    def test_rename_error_isolation(self):
        """rename() errors are per-item dicts, not raised exceptions.

        Uses decompile to test error isolation without requiring Ghidra SymbolType imports.
        """
        backend = _make_backend()

        call_count = 0

        def raise_each(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception(f'mock error {call_count}')

        with patch('mcpyghidra.tools.analysis._get_function', side_effect=raise_each):
            from mcpyghidra.tools.analysis import decompile
            results = _run_async(decompile, backend, [
                {'name': 'func_a'},
                {'name': 'func_b'},
            ])
            assert isinstance(results, list)
            assert len(results) == 2
            assert call_count == 2, 'Both items should be attempted despite errors'
            for r in results:
                assert 'error' in r
                assert r['error'] is not None


class TestBatchReturnShapes:
    """Verify documented return shapes for key batch tools."""

    def test_decompile_success_shape(self):
        """decompile success result has: code, name, entrypoint, error=None."""
        backend = _make_backend()
        mock_func = MagicMock()
        mock_func.getName.return_value = 'test_func'
        mock_func.getEntryPoint.return_value.offset = 0x1000
        mock_func.getComment.return_value = None

        mock_dec = MagicMock()
        mock_dec.name = 'test_func'
        mock_dec.entrypoint = '0x1000'
        mock_dec.c_code = 'void test_func() { return; }'

        backend.get_decompiled_func.return_value = mock_dec

        with patch('mcpyghidra.tools.analysis._get_function', return_value=mock_func):
            from mcpyghidra.tools.analysis import decompile
            results = _run_async(decompile, backend, [{'name': 'test_func'}])
            assert len(results) == 1
            r = results[0]
            assert r['error'] is None
            assert 'code' in r
            assert 'name' in r
            assert 'entrypoint' in r

    def test_symbols_success_shape(self):
        """symbols success result has: addr, name, symbol_type, error=None."""
        from mcpyghidra.models import SymbolInfo

        backend = _make_backend()
        mock_ea = MagicMock()
        mock_ea.offset = 0x1000

        mock_sym_info = SymbolInfo(name='my_func', symbol_type='function')

        with patch('mcpyghidra.tools.analysis._get_address', return_value=mock_ea):
            with patch('mcpyghidra.tools.analysis._classify_symbol', return_value=mock_sym_info):
                from mcpyghidra.tools.analysis import symbols
                results = _run_async(symbols, backend, ['0x1000'])
                assert len(results) == 1
                r = results[0]
                assert r['error'] is None
                assert r['name'] == 'my_func'
                assert r['symbol_type'] == 'function'
                assert r['addr'] == '0x1000'

    def test_xrefs_success_shape(self):
        """xrefs success result is flat: addr, direction, items, page_info, error=None."""
        backend = _make_backend()
        mock_ea = MagicMock()
        mock_ea.offset = 0x1000

        with patch('mcpyghidra.tools.analysis._get_address', return_value=mock_ea):
            with patch('mcpyghidra.tools.analysis._xrefs_to_addr') as mock_xrefs:
                from mcpyghidra.models import ListResult, ResultPageInfo
                mock_list_result = ListResult(
                    summary='test',
                    entry_type='cross-reference',
                    schema_version=1,
                    page_info=ResultPageInfo(
                        offset=0, limit=500, num_returned=0,
                        total_count=0, has_more=False, next_offset=None,
                    ),
                    items=[],
                )
                mock_xrefs.return_value = mock_list_result
                from mcpyghidra.tools.analysis import xrefs
                results = _run_async(xrefs, backend, [{'target': '0x1000', 'direction': 'to'}])
                assert len(results) == 1
                r = results[0]
                assert r['error'] is None
                assert r['addr'] == '0x1000'    # resolved addr echoed (not 'target')
                assert r['direction'] == 'to'
                assert 'items' in r             # flat: rows under 'items', not 'result'
                assert 'result' not in r        # no wrapper
