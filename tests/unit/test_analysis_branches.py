"""Unit tests for defensive / error branches in tools/analysis.py.

These tests run without Ghidra/pyghidra by mocking GhidraBackend and all
Java-type dependencies via sys.modules stubs.  Each test targets exactly
ONE branch that integration tests cannot reach.

Coverage goal: tools/analysis.py from 30% line / 5% branch → 80%+ line / ~95% branch.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import anyio
import pytest

from mcpyghidra.backend import GhidraError


# ---------------------------------------------------------------------------
# Ghidra stub installation — must happen before any mcpyghidra import
# ---------------------------------------------------------------------------

_GHIDRA_STUBS = [
    'ghidra',
    'ghidra.app',
    'ghidra.app.util',
    'ghidra.app.services',
    'ghidra.framework',
    'ghidra.program',
    'ghidra.program.database',
    'ghidra.program.database.code',
    'ghidra.program.model',
    'ghidra.program.model.address',
    'ghidra.program.model.listing',
    'ghidra.program.model.mem',
    'ghidra.program.model.symbol',
    'ghidra.program.util',
    'java',
    'java.io',
]

for _mod in _GHIDRA_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# ghidra.framework.Application must return real strings so Pydantic is happy.
_mock_application = MagicMock()
_mock_application.getName.return_value = 'Ghidra'
_mock_application.getApplicationVersion.return_value = '11.0'
_mock_ghidra_framework = MagicMock()
_mock_ghidra_framework.Application = _mock_application
sys.modules['ghidra.framework'] = _mock_ghidra_framework


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_backend() -> MagicMock:
    """Minimal mock GhidraBackend sufficient for analysis tool helpers."""
    backend = MagicMock()
    backend.is_headless = True
    backend.program = MagicMock()
    backend.flat_api = MagicMock()
    return backend


def _run_async(async_fn, *args, **kwargs):
    """Run an async tool function synchronously for unit tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


def _make_mock_addr(offset: int = 0x1000) -> MagicMock:
    """Return a mock Ghidra GenericAddress with sensible defaults."""
    addr = MagicMock()
    addr.offset = offset
    addr.__gt__ = MagicMock(return_value=False)
    addr.__le__ = MagicMock(return_value=True)
    addr.getOffset.return_value = offset
    addr.getAddressSpace.return_value.getAddress.return_value = addr
    return addr


# ---------------------------------------------------------------------------
# Branch 1: _disasm_addr — block is None (past memory end)
# Lines ~142–146
# ---------------------------------------------------------------------------


class TestDisasmAddrBlockNone:
    """_disasm_addr: memory.getBlock(cur) returns None → out-of-mapped-memory message."""

    def test_block_none_appends_boundary_message_and_breaks(self):
        """When getBlock returns None on the first iteration, output has boundary message."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        # memory.getBlock returns None → triggers the boundary branch
        backend.program.getMemory.return_value.getBlock.return_value = None

        with patch.dict(sys.modules, {
            'ghidra.app.util': MagicMock(),
        }):
            result = _disasm_addr(backend, ea, count=5)

        assert 'Out of mapped memory' in result or 'block boundary' in result

    def test_block_none_count_zero_produces_empty(self):
        """count=0 → max(0, count)=0 so loop body never executes → empty string."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock()}):
            result = _disasm_addr(backend, ea, count=0)

        assert result == ''

    def test_block_none_negative_count_produces_empty(self):
        """count=-3 → max(0, -3)=0 so loop never runs → empty string."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock()}):
            result = _disasm_addr(backend, ea, count=-3)

        assert result == ''


# ---------------------------------------------------------------------------
# Branch 2: _disasm_addr — listing.getInstructionAt() returns None, pseudo also None
# Lines ~149–154
# ---------------------------------------------------------------------------


class TestDisasmAddrInstrNone:
    """_disasm_addr: getInstructionAt returns None and pseudo.disassemble also None."""

    def test_both_none_appends_failed_to_decode_and_breaks(self):
        """listing.getInstructionAt → None, pseudo.disassemble → None → failure line."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        # Block exists (not None)
        mock_block = MagicMock()
        backend.program.getMemory.return_value.getBlock.return_value = mock_block

        # Both instruction lookups return None
        backend.program.getListing.return_value.getInstructionAt.return_value = None

        mock_pseudo_cls = MagicMock()
        mock_pseudo_cls.return_value.disassemble.return_value = None

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock(PseudoDisassembler=mock_pseudo_cls)}):
            result = _disasm_addr(backend, ea, count=3)

        assert 'Failed to decode instruction' in result

    def test_instr_none_pseudo_returns_valid_instr(self):
        """listing.getInstructionAt → None but pseudo.disassemble → valid instr."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        mock_block = MagicMock()
        backend.program.getMemory.return_value.getBlock.return_value = mock_block
        backend.program.getListing.return_value.getInstructionAt.return_value = None

        mock_instr = MagicMock()
        mock_instr.toString.return_value = 'NOP'
        mock_instr.getLength.return_value = 1

        mock_pseudo_cls = MagicMock()
        mock_pseudo_cls.return_value.disassemble.return_value = mock_instr

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock(PseudoDisassembler=mock_pseudo_cls)}):
            result = _disasm_addr(backend, ea, count=1)

        assert 'NOP' in result

    def test_instr_toString_empty_appends_could_not_generate(self):
        """instr.toString() returns '' → 'Could not generate disassembly' line."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        mock_block = MagicMock()
        backend.program.getMemory.return_value.getBlock.return_value = mock_block

        mock_instr = MagicMock()
        mock_instr.toString.return_value = ''
        mock_instr.getLength.return_value = 1

        backend.program.getListing.return_value.getInstructionAt.return_value = mock_instr

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock()}):
            result = _disasm_addr(backend, ea, count=2)

        assert 'Could not generate disassembly' in result

    def test_zero_length_instr_appends_zero_length_message(self):
        """instr.getLength() returns 0 → 'zero-length instruction' stop message."""
        from mcpyghidra.tools.analysis import _disasm_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        mock_block = MagicMock()
        backend.program.getMemory.return_value.getBlock.return_value = mock_block

        mock_instr = MagicMock()
        mock_instr.toString.return_value = 'SOME_INSN'
        mock_instr.getLength.return_value = 0

        backend.program.getListing.return_value.getInstructionAt.return_value = mock_instr

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock()}):
            result = _disasm_addr(backend, ea, count=3)

        assert 'zero-length instruction' in result


# ---------------------------------------------------------------------------
# Branch 3: xrefs — negative offset and zero limit validation
# Lines ~445–458
# ---------------------------------------------------------------------------


class TestXrefsValidation:
    """_xrefs_sync early-return paths for invalid offset/limit."""

    def test_negative_offset_returns_error_dict(self):
        """offset < 0 → result dict has 'error' about offset."""
        from mcpyghidra.tools.analysis import _xrefs_sync

        backend = _make_backend()
        result = _xrefs_sync(backend, [{'target': '0x1000', 'direction': 'to', 'offset': -1}])

        assert len(result) == 1
        assert 'error' in result[0]
        assert 'offset' in result[0]['error']

    def test_negative_limit_returns_error_dict(self):
        """limit=-1 → int(-1 or 500) = -1 ≤ 0 → result dict has 'error' about limit.

        Note: limit=0 is coalesced to 500 by 'or 500' on line 443 of _xrefs_sync,
        so only a negative value actually reaches the item_limit <= 0 guard.
        """
        from mcpyghidra.tools.analysis import _xrefs_sync

        backend = _make_backend()
        result = _xrefs_sync(backend, [{'target': '0x1000', 'direction': 'to', 'limit': -1}])

        assert len(result) == 1
        assert 'error' in result[0]
        assert 'limit' in result[0]['error']

    def test_very_negative_limit_returns_error_dict(self):
        """limit=-999 → still ≤ 0 → error dict."""
        from mcpyghidra.tools.analysis import _xrefs_sync

        backend = _make_backend()
        result = _xrefs_sync(backend, [{'target': '0x1000', 'direction': 'to', 'limit': -999}])

        assert len(result) == 1
        assert 'error' in result[0]
        assert 'limit' in result[0]['error']

    def test_empty_xrefs_to_addr_returns_list_result(self):
        """xrefs 'to' with no references returns a ListResult (empty, not error)."""
        from mcpyghidra.tools.analysis import _xrefs_to_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = []

        result = _xrefs_to_addr(backend, ea, offset=0, limit=500)
        assert result.page_info.num_returned == 0

    def test_empty_xrefs_from_addr_returns_list_result(self):
        """xrefs 'from' with no references returns a ListResult (empty, not error)."""
        from mcpyghidra.tools.analysis import _xrefs_from_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        backend.program.getReferenceManager.return_value.getReferencesFrom.return_value = []

        result = _xrefs_from_addr(backend, ea, offset=0, limit=500)
        assert result.page_info.num_returned == 0

    def test_xrefs_to_addr_with_ref_no_containing_func(self):
        """getReferencesTo has one ref, no function at from_addr → 'function' key absent."""
        from mcpyghidra.tools.analysis import _xrefs_to_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        from_addr = _make_mock_addr(0x900)
        mock_ref = MagicMock()
        mock_ref.getFromAddress.return_value = from_addr
        mock_ref.getReferenceType.return_value = MagicMock(__str__=lambda s: 'CALL')

        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = [mock_ref]
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = _xrefs_to_addr(backend, ea, offset=0, limit=500)
        assert result.page_info.num_returned == 1
        assert 'function' not in result.items[0]['from']

    def test_xrefs_to_addr_with_ref_with_containing_func(self):
        """getReferencesTo has one ref with function → 'function' key present in 'from'."""
        from mcpyghidra.tools.analysis import _xrefs_to_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        from_addr = _make_mock_addr(0x900)
        mock_ref = MagicMock()
        mock_ref.getFromAddress.return_value = from_addr
        mock_ref.getReferenceType.return_value = MagicMock(__str__=lambda s: 'CALL')

        mock_func = MagicMock()
        mock_func.name = 'caller_func'

        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = [mock_ref]
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = mock_func

        result = _xrefs_to_addr(backend, ea, offset=0, limit=500)
        assert result.items[0]['from']['function'] == 'caller_func'

    def test_xrefs_from_addr_with_ref_with_containing_func(self):
        """getReferencesFrom has one ref with function → 'function' key present in 'to'."""
        from mcpyghidra.tools.analysis import _xrefs_from_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        to_addr = _make_mock_addr(0x2000)
        mock_ref = MagicMock()
        mock_ref.getToAddress.return_value = to_addr
        mock_ref.getReferenceType.return_value = MagicMock(__str__=lambda s: 'CALL')

        mock_func = MagicMock()
        mock_func.name = 'callee_func'

        backend.program.getReferenceManager.return_value.getReferencesFrom.return_value = [mock_ref]
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = mock_func

        result = _xrefs_from_addr(backend, ea, offset=0, limit=500)
        assert result.items[0]['to']['function'] == 'callee_func'

    def test_xrefs_invalid_direction_returns_error(self):
        """direction='sideways' → GhidraError → error dict returned."""
        from mcpyghidra.tools.analysis import _xrefs_sync

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea

        result = _xrefs_sync(backend, [{'target': '0x1000', 'direction': 'sideways'}])

        assert len(result) == 1
        assert 'error' in result[0]
        assert 'direction' in result[0]['error']

    def test_xrefs_function_name_not_found_returns_error(self):
        """Non-0x target treated as function name → getFunction returns None → error."""
        from mcpyghidra.tools.analysis import _xrefs_sync

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        result = _xrefs_sync(backend, [{'target': 'missing_func', 'direction': 'to'}])

        assert len(result) == 1
        assert 'error' in result[0]
        assert 'not found' in result[0]['error']

    def test_xrefs_function_name_resolved_to_entry_point(self):
        """Non-0x target resolved via flat_api.getFunction → xrefs call succeeds."""
        from mcpyghidra.tools.analysis import _xrefs_sync

        backend = _make_backend()
        ea = _make_mock_addr(0x2000)

        mock_func = MagicMock()
        mock_func.getEntryPoint.return_value = ea
        backend.flat_api.getFunction.return_value = mock_func

        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = []

        result = _xrefs_sync(backend, [{'target': 'some_func', 'direction': 'to'}])

        assert len(result) == 1
        assert result[0]['error'] is None

    def test_xrefs_non_list_items_coerced(self):
        """xrefs() with non-list items → isinstance branch coerces to list."""
        from mcpyghidra.tools.analysis import xrefs

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        result = _run_async(xrefs, backend, {'target': 'missing', 'direction': 'to'})

        assert isinstance(result, list)
        assert len(result) == 1
        assert 'error' in result[0]


# ---------------------------------------------------------------------------
# Branch 4: _classify_symbol — unknown SymbolType (not LABEL/GLOBAL/DATA/FUNCTION)
# Lines ~275–302
# ---------------------------------------------------------------------------


class TestClassifySymbolUnknownType:
    """_classify_symbol: SymbolType not matching known cases → symbol_type='unknown'."""

    def _make_symbol_backend(self, symbol_type_value) -> MagicMock:
        """Backend with no function at ea but a symbol with given type."""
        backend = _make_backend()
        ea = _make_mock_addr(0x3000)

        # No function at this address
        backend.program.getListing.return_value.getFunctionAt.return_value = None

        mock_sym = MagicMock()
        mock_sym.name = 'some_sym'
        mock_sym.getSymbolType.return_value = symbol_type_value

        backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = mock_sym
        return backend, ea

    def test_unrecognised_symbol_type_returns_unknown(self):
        """SymbolType not in known set → SymbolInfo with symbol_type='unknown'."""
        from mcpyghidra.tools.analysis import _classify_symbol

        # Build a sentinel that won't match LABEL, GLOBAL, DATA, or FUNCTION
        unrecognised_type = object()
        backend, ea = self._make_symbol_backend(unrecognised_type)

        # Patch the lazy import inside _classify_symbol
        mock_sym_type_mod = MagicMock()
        mock_sym_type_mod.SymbolType.LABEL = object()
        mock_sym_type_mod.SymbolType.GLOBAL = object()
        mock_sym_type_mod.SymbolType.DATA = object()
        mock_sym_type_mod.SymbolType.FUNCTION = object()

        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            info = _classify_symbol(backend, ea)

        assert info.symbol_type == 'unknown'
        assert info.name == 'some_sym'

    def test_label_symbol_type_returns_code_label(self):
        """SymbolType.LABEL → symbol_type='code_label'."""
        from mcpyghidra.tools.analysis import _classify_symbol

        sentinel = object()
        backend, ea = self._make_symbol_backend(sentinel)

        mock_sym_type_mod = MagicMock()
        mock_sym_type_mod.SymbolType.LABEL = sentinel
        mock_sym_type_mod.SymbolType.GLOBAL = object()
        mock_sym_type_mod.SymbolType.DATA = object()
        mock_sym_type_mod.SymbolType.FUNCTION = object()

        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            info = _classify_symbol(backend, ea)

        assert info.symbol_type == 'code_label'

    def test_global_symbol_type_returns_global_variable(self):
        """SymbolType.GLOBAL → symbol_type='global_variable'."""
        from mcpyghidra.tools.analysis import _classify_symbol

        sentinel = object()
        backend, ea = self._make_symbol_backend(sentinel)

        mock_sym_type_mod = MagicMock()
        mock_sym_type_mod.SymbolType.LABEL = object()
        mock_sym_type_mod.SymbolType.GLOBAL = sentinel
        mock_sym_type_mod.SymbolType.DATA = object()
        mock_sym_type_mod.SymbolType.FUNCTION = object()

        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            info = _classify_symbol(backend, ea)

        assert info.symbol_type == 'global_variable'

    def test_data_symbol_type_returns_data_label(self):
        """SymbolType.DATA → symbol_type='data_label'."""
        from mcpyghidra.tools.analysis import _classify_symbol

        sentinel = object()
        backend, ea = self._make_symbol_backend(sentinel)

        mock_sym_type_mod = MagicMock()
        mock_sym_type_mod.SymbolType.LABEL = object()
        mock_sym_type_mod.SymbolType.GLOBAL = object()
        mock_sym_type_mod.SymbolType.DATA = sentinel
        mock_sym_type_mod.SymbolType.FUNCTION = object()

        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            info = _classify_symbol(backend, ea)

        assert info.symbol_type == 'data_label'

    def test_function_symbol_type_returns_function(self):
        """SymbolType.FUNCTION (sym, not func at listing) → symbol_type='function'."""
        from mcpyghidra.tools.analysis import _classify_symbol

        sentinel = object()
        backend, ea = self._make_symbol_backend(sentinel)

        mock_sym_type_mod = MagicMock()
        mock_sym_type_mod.SymbolType.LABEL = object()
        mock_sym_type_mod.SymbolType.GLOBAL = object()
        mock_sym_type_mod.SymbolType.DATA = object()
        mock_sym_type_mod.SymbolType.FUNCTION = sentinel

        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            info = _classify_symbol(backend, ea)

        assert info.symbol_type == 'function'

    def test_no_symbol_at_ea_raises_ghidra_error(self):
        """getPrimarySymbol returns None → GhidraError raised."""
        from mcpyghidra.tools.analysis import _classify_symbol

        backend = _make_backend()
        ea = _make_mock_addr(0x3000)

        backend.program.getListing.return_value.getFunctionAt.return_value = None
        backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = None

        mock_sym_type_mod = MagicMock()
        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            with pytest.raises(GhidraError, match='No symbol found'):
                _classify_symbol(backend, ea)

    def test_function_at_listing_short_circuits(self):
        """getFunctionAt returns a function → SymbolInfo(function) without symbol table lookup."""
        from mcpyghidra.tools.analysis import _classify_symbol

        backend = _make_backend()
        ea = _make_mock_addr(0x4000)

        mock_func = MagicMock()
        mock_func.name = 'real_func'
        backend.program.getListing.return_value.getFunctionAt.return_value = mock_func

        mock_sym_type_mod = MagicMock()
        with patch.dict(sys.modules, {'ghidra.program.model.symbol': mock_sym_type_mod}):
            info = _classify_symbol(backend, ea)

        assert info.symbol_type == 'function'
        assert info.name == 'real_func'
        # Symbol table should NOT have been consulted
        backend.program.getSymbolTable.return_value.getPrimarySymbol.assert_not_called()


# ---------------------------------------------------------------------------
# Branch 5: decompile — function comment prepend
# Lines ~80–83
# ---------------------------------------------------------------------------


class TestDecompileCommentPrepend:
    """_decompile_sync: func.getComment() truthy → code prefixed with /* comment */."""

    def _make_decompile_backend(self, comment: str | None) -> MagicMock:
        backend = _make_backend()

        mock_func = MagicMock()
        mock_func.getComment.return_value = comment

        # _get_function will resolve via flat_api.getFunction(name)
        backend.flat_api.getFunction.return_value = mock_func

        mock_dec = MagicMock()
        mock_dec.name = 'my_func'
        mock_dec.entrypoint = '0x1000'
        mock_dec.c_code = 'void my_func() {}'
        backend.get_decompiled_func.return_value = mock_dec

        return backend

    def test_with_comment_prepends_block_comment(self):
        """func.getComment() returns non-empty string → code starts with /* ... */."""
        from mcpyghidra.tools.analysis import _decompile_sync

        backend = self._make_decompile_backend(comment='Entry point function')
        results = _decompile_sync(backend, [{'name': 'my_func'}])

        assert len(results) == 1
        assert results[0]['error'] is None
        code = results[0]['code']
        assert code.startswith('/* Entry point function */')
        assert 'void my_func()' in code

    def test_without_comment_no_prepend(self):
        """func.getComment() returns None → code is unchanged (no block comment)."""
        from mcpyghidra.tools.analysis import _decompile_sync

        backend = self._make_decompile_backend(comment=None)
        results = _decompile_sync(backend, [{'name': 'my_func'}])

        assert len(results) == 1
        assert results[0]['error'] is None
        code = results[0]['code']
        assert not code.startswith('/*')
        assert code == 'void my_func() {}'

    def test_empty_string_comment_no_prepend(self):
        """func.getComment() returns '' (falsy) → code is unchanged."""
        from mcpyghidra.tools.analysis import _decompile_sync

        backend = self._make_decompile_backend(comment='')
        results = _decompile_sync(backend, [{'name': 'my_func'}])

        assert len(results) == 1
        code = results[0]['code']
        assert not code.startswith('/*')

    def test_decompile_exception_appends_error_dict(self):
        """_get_function raises → result dict has 'error' key."""
        from mcpyghidra.tools.analysis import _decompile_sync

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        results = _decompile_sync(backend, [{'name': 'ghost_func'}])

        assert len(results) == 1
        assert results[0]['error'] is not None

    def test_decompile_non_list_items_coerced(self):
        """decompile() with non-list items → isinstance branch coerces to list."""
        from mcpyghidra.tools.analysis import decompile

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        result = _run_async(decompile, backend, {'name': 'ghost_func'})

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['error'] is not None


# ---------------------------------------------------------------------------
# Branch 6: _tool_result_list_formatter — _Skip exception in analysis context
# Verified via xrefs helpers that pass through _tool_result_list_formatter
# ---------------------------------------------------------------------------


class TestToolResultListFormatterSkipInAnalysis:
    """_Skip exception path reached via analysis._xrefs_to_addr when entry_proc raises _Skip."""

    def test_skip_via_xrefs_call_produces_empty_items(self):
        """If all xref refs raise _Skip, result has num_returned=0."""
        from mcpyghidra.tools.core import _tool_result_list_formatter, _Skip

        # Directly test _tool_result_list_formatter with a proc that always skips
        def always_skip(entry):
            raise _Skip

        result = _tool_result_list_formatter(
            results_heading='Cross-references to 0x1000',
            entry_type='cross-reference',
            entry_proc=always_skip,
            entries=['ref_a', 'ref_b'],
            offset=0,
            limit=500,
        )
        # Both skipped: num_returned should be 0
        assert result.page_info.num_returned == 0
        assert result.items == []

    def test_skip_mixed_with_success_in_analysis_context(self):
        """_Skip for some entries, success for others → only non-skipped appear."""
        from mcpyghidra.tools.core import _tool_result_list_formatter, _Skip

        call_count = {'n': 0}

        def skip_every_other(entry):
            call_count['n'] += 1
            if call_count['n'] % 2 == 0:
                raise _Skip
            return {'type': 'cross-reference', 'from': {'addr': '0x900'}, 'xref-type': 'CALL'}

        result = _tool_result_list_formatter(
            results_heading='Cross-references',
            entry_type='cross-reference',
            entry_proc=skip_every_other,
            entries=['a', 'b', 'c', 'd'],
            offset=0,
            limit=500,
        )
        # entries a, c succeed; b, d skip → 2 items returned
        assert len(result.items) == 2


# ---------------------------------------------------------------------------
# Branch: symbols async wrapper — non-list items coerced
# ---------------------------------------------------------------------------


class TestSymbolsAsyncWrapper:
    """symbols() with non-list items → coerced to list."""

    def test_non_list_items_coerced(self):
        """Passing a plain string exercises the isinstance branch."""
        from mcpyghidra.tools.analysis import symbols

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea

        mock_func = MagicMock()
        mock_func.name = 'some_func'
        backend.program.getListing.return_value.getFunctionAt.return_value = mock_func

        result = _run_async(symbols, backend, '0x1000')  # type: ignore[arg-type]

        assert isinstance(result, list)
        assert len(result) == 1

    def test_address_parse_failure_returns_error_dict(self):
        """_get_address returns None → GhidraError → error dict in result."""
        from mcpyghidra.tools.analysis import _symbols_sync

        backend = _make_backend()
        # getAddress returns None → _get_address still returns it;
        # ea is None → GhidraError raised at the None check
        backend.program.getAddressFactory.return_value.getAddress.return_value = None

        results = _symbols_sync(backend, ['0xDEAD'])

        assert len(results) == 1
        assert 'error' in results[0]


# ---------------------------------------------------------------------------
# Branch: disasm async wrapper — non-list items coerced; addr not in function
# ---------------------------------------------------------------------------


class TestDisasmSync:
    """_disasm_sync: addr-only path where addr is not inside any function."""

    def test_addr_not_in_function_falls_back_to_address_mode(self):
        """getFunctionContaining returns None → fallback to _disasm_addr with count=20."""
        from mcpyghidra.tools.analysis import _disasm_sync

        backend = _make_backend()
        ea = _make_mock_addr(0x5000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea

        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        # _disasm_addr will be called; memory.getBlock returns None → boundary message
        backend.program.getMemory.return_value.getBlock.return_value = None

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock()}):
            results = _disasm_sync(backend, [{'addr': '0x5000'}])

        assert len(results) == 1
        assert results[0]['mode'] == 'address'
        assert results[0]['count'] == 20
        assert results[0]['error'] is None

    def test_addr_inside_function_uses_function_mode(self):
        """getFunctionContaining returns func → function mode result."""
        from mcpyghidra.tools.analysis import _disasm_sync

        backend = _make_backend()
        ea = _make_mock_addr(0x5100)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea

        func_entry = _make_mock_addr(0x5000)
        func_body = MagicMock()
        func_body.getMaxAddress.return_value = _make_mock_addr(0x5200)

        mock_func = MagicMock()
        mock_func.getEntryPoint.return_value = func_entry
        mock_func.getBody.return_value = func_body
        mock_func.getName.return_value = 'containing_func'

        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = mock_func

        # listing.getInstructions must return something iterable
        mock_instr = MagicMock()
        mock_instr.getAddress.return_value = _make_mock_addr(0x5000)
        mock_instr.getAddress.return_value.__gt__ = lambda s, o: False
        mock_instr.getBytes.return_value = b'\x90'
        mock_instr.toString.return_value = 'NOP'

        # getAddress() > end_addr → True on second call to break the loop
        exit_instr = MagicMock()
        exit_addr = MagicMock()
        exit_addr.__gt__ = MagicMock(return_value=True)
        exit_instr.getAddress.return_value = exit_addr

        mock_instr_seq = MagicMock()
        mock_instr_seq.__iter__ = MagicMock(return_value=iter([exit_instr]))

        backend.program.getListing.return_value.getInstructions.return_value = mock_instr_seq

        with patch.dict(sys.modules, {
            'ghidra.program.model.listing': MagicMock(),
        }):
            results = _disasm_sync(backend, [{'addr': '0x5100'}])

        assert len(results) == 1
        assert results[0]['mode'] == 'function'
        assert results[0]['name'] == 'containing_func'
        assert results[0]['error'] is None

    def test_no_addr_no_name_returns_error(self):
        """Both addr and name empty → GhidraError → error dict."""
        from mcpyghidra.tools.analysis import _disasm_sync

        backend = _make_backend()
        results = _disasm_sync(backend, [{}])

        assert len(results) == 1
        assert results[0]['error'] is not None

    def test_count_without_addr_returns_error(self):
        """count set but addr empty → GhidraError → error dict."""
        from mcpyghidra.tools.analysis import _disasm_sync

        backend = _make_backend()
        results = _disasm_sync(backend, [{'count': 5}])

        assert len(results) == 1
        assert results[0]['error'] is not None

    def test_disasm_non_list_items_coerced(self):
        """disasm() with non-list items → isinstance branch coerces to list."""
        from mcpyghidra.tools.analysis import disasm

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        result = _run_async(disasm, backend, {'name': 'ghost'})  # type: ignore[arg-type]

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['error'] is not None

    def test_disasm_list_items_not_coerced(self):
        """disasm() with items already a list → isinstance True branch (no coercion)."""
        from mcpyghidra.tools.analysis import disasm

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        result = _run_async(disasm, backend, [{'name': 'ghost'}])

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['error'] is not None

    def test_disasm_by_name_success(self):
        """disasm with name provided → function mode, _disasm_function called."""
        from mcpyghidra.tools.analysis import _disasm_sync

        backend = _make_backend()

        func_entry = _make_mock_addr(0x6000)
        func_body = MagicMock()
        end_addr = _make_mock_addr(0x6100)
        func_body.getMaxAddress.return_value = end_addr

        mock_func = MagicMock()
        mock_func.getEntryPoint.return_value = func_entry
        mock_func.getBody.return_value = func_body
        mock_func.getName.return_value = 'named_func'

        backend.flat_api.getFunction.return_value = mock_func

        # listing.getInstructions returns empty iterable (no instructions)
        backend.program.getListing.return_value.getInstructions.return_value = iter([])

        with patch.dict(sys.modules, {
            'ghidra.program.model.listing': MagicMock(),
        }):
            results = _disasm_sync(backend, [{'name': 'named_func'}])

        assert len(results) == 1
        assert results[0]['mode'] == 'function'
        assert results[0]['name'] == 'named_func'
        assert results[0]['error'] is None

    def test_disasm_with_count_and_addr_success(self):
        """count + addr → address mode with _disasm_addr; block=None → boundary msg."""
        from mcpyghidra.tools.analysis import _disasm_sync

        backend = _make_backend()
        ea = _make_mock_addr(0x7000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea
        backend.program.getMemory.return_value.getBlock.return_value = None

        with patch.dict(sys.modules, {'ghidra.app.util': MagicMock()}):
            results = _disasm_sync(backend, [{'addr': '0x7000', 'count': 3}])

        assert len(results) == 1
        assert results[0]['mode'] == 'address'
        assert results[0]['count'] == 3
        assert results[0]['error'] is None


# ---------------------------------------------------------------------------
# Branch: async wrappers — items already a list (False branch of isinstance)
# ---------------------------------------------------------------------------


class TestAsyncWrapperListBranch:
    """Async wrappers when items is already a list → isinstance False branch not taken."""

    def test_decompile_list_items_not_coerced(self):
        """decompile() with items already a list → isinstance True → no coercion."""
        from mcpyghidra.tools.analysis import decompile

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        result = _run_async(decompile, backend, [{'name': 'ghost'}])

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['error'] is not None

    def test_symbols_list_items_not_coerced(self):
        """symbols() with items already a list → isinstance True → no coercion."""
        from mcpyghidra.tools.analysis import symbols

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea

        mock_func = MagicMock()
        mock_func.name = 'some_func'
        backend.program.getListing.return_value.getFunctionAt.return_value = mock_func

        result = _run_async(symbols, backend, ['0x1000'])

        assert isinstance(result, list)
        assert len(result) == 1

    def test_xrefs_list_items_not_coerced(self):
        """xrefs() with items already a list → isinstance True → no coercion."""
        from mcpyghidra.tools.analysis import xrefs

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea
        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = []

        result = _run_async(xrefs, backend, [{'target': '0x1000', 'direction': 'to'}])

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['error'] is None

    def test_xrefs_from_direction_via_list(self):
        """xrefs with direction='from' reaches _xrefs_from_addr (line 474)."""
        from mcpyghidra.tools.analysis import xrefs

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)
        backend.program.getAddressFactory.return_value.getAddress.return_value = ea
        backend.program.getReferenceManager.return_value.getReferencesFrom.return_value = []

        result = _run_async(xrefs, backend, [{'target': '0x1000', 'direction': 'from'}])

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]['direction'] == 'from'
        assert result[0]['error'] is None

    def test_xrefs_from_addr_ref_no_containing_func(self):
        """_xrefs_from_addr: getFunctionContaining returns None → 'function' key absent (False branch of if ref_func)."""
        from mcpyghidra.tools.analysis import _xrefs_from_addr

        backend = _make_backend()
        ea = _make_mock_addr(0x1000)

        to_addr = _make_mock_addr(0x2000)
        mock_ref = MagicMock()
        mock_ref.getToAddress.return_value = to_addr
        mock_ref.getReferenceType.return_value = MagicMock(__str__=lambda s: 'DATA')

        backend.program.getReferenceManager.return_value.getReferencesFrom.return_value = [mock_ref]
        # No function at the target address
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = _xrefs_from_addr(backend, ea, offset=0, limit=500)
        assert result.page_info.num_returned == 1
        assert 'function' not in result.items[0]['to']


# ---------------------------------------------------------------------------
# Branch: _disasm_function body — EOL comment path
# Lines 117-123
# ---------------------------------------------------------------------------


class TestDisasmFunction:
    """_disasm_function: instruction loop with bytes/comment branches."""

    def _make_function_backend(self, *, with_comment: bool, with_bytes: bool) -> tuple:
        """Backend wired with one instruction that doesn't exceed end_addr."""
        backend = _make_backend()

        func_entry = _make_mock_addr(0x8000)
        end_addr = _make_mock_addr(0x8100)

        func_body = MagicMock()
        func_body.getMaxAddress.return_value = end_addr

        mock_func = MagicMock()
        mock_func.getEntryPoint.return_value = func_entry
        mock_func.getBody.return_value = func_body

        instr_addr = _make_mock_addr(0x8000)
        instr_addr.__gt__ = MagicMock(return_value=False)  # not > end_addr

        mock_instr = MagicMock()
        mock_instr.getAddress.return_value = instr_addr
        mock_instr.getAddress.return_value.__gt__ = MagicMock(return_value=False)
        mock_instr.toString.return_value = 'MOV EAX, EBX'

        if with_bytes:
            mock_instr.getBytes.return_value = b'\x89\xc3'
        else:
            mock_instr.getBytes.return_value = None

        # Sentinel for getAddress().offset
        instr_addr.offset = 0x8000

        # Make exit instruction to stop loop
        exit_addr = MagicMock()
        exit_addr.__gt__ = MagicMock(return_value=True)
        exit_instr = MagicMock()
        exit_instr.getAddress.return_value = exit_addr

        if with_comment:
            backend.program.getListing.return_value.getComment.return_value = 'my comment'
        else:
            backend.program.getListing.return_value.getComment.return_value = None

        backend.program.getListing.return_value.getInstructions.return_value = iter([
            mock_instr, exit_instr,
        ])

        return backend, mock_func

    def test_instruction_with_bytes_and_comment(self):
        """Instruction with bytes and EOL comment → both hex_bytes and comment_str set."""
        from mcpyghidra.tools.analysis import _disasm_function

        backend, mock_func = self._make_function_backend(with_comment=True, with_bytes=True)

        with patch.dict(sys.modules, {'ghidra.program.model.listing': MagicMock()}):
            result = _disasm_function(backend, mock_func)

        assert '89 C3' in result or '89' in result
        assert '; my comment' in result

    def test_instruction_no_bytes_no_comment(self):
        """Instruction with no bytes and no comment → hex_bytes='' and comment_str=''."""
        from mcpyghidra.tools.analysis import _disasm_function

        backend, mock_func = self._make_function_backend(with_comment=False, with_bytes=False)

        with patch.dict(sys.modules, {'ghidra.program.model.listing': MagicMock()}):
            result = _disasm_function(backend, mock_func)

        # Should have 'MOV EAX, EBX' but no ';' and empty byte column
        assert 'MOV EAX, EBX' in result
        assert '; ' not in result


# ---------------------------------------------------------------------------
# Branch: xrefs flat contract — addr/name (+aliases), no 'result' wrapper
# ---------------------------------------------------------------------------


class TestXrefsFlatContract:
    """xrefs returns a flat per-item dict: rows under 'items', no 'result' wrapper,
    addr/name/direction echoed, error present. Input accepts addr/name + aliases."""

    def _patch_xrefs(self, monkeypatch, list_result):
        """Stub _xrefs_to_addr/_xrefs_from_addr to return a ListResult."""
        import mcpyghidra.tools.analysis as analysis
        monkeypatch.setattr(analysis, '_xrefs_to_addr', lambda *a, **k: list_result)
        monkeypatch.setattr(analysis, '_xrefs_from_addr', lambda *a, **k: list_result)

    def test_success_is_flat_with_items_no_result_wrapper(self, monkeypatch):
        """Successful xref returns flat dict: 'items' lifted, no 'result' wrapper."""
        from mcpyghidra.models import ListResult, ResultPageInfo
        import mcpyghidra.tools.analysis as analysis

        lr = ListResult(
            summary='Cross-references to 0x1000 0-0 of 1',
            entry_type='cross-reference', schema_version=1,
            page_info=ResultPageInfo(offset=0, limit=500, num_returned=1,
                                     total_count=1, has_more=False, next_offset=None),
            items=[{'type': 'Cross-Reference to Address', 'from': {'addr': '0x2000'}}],
        )
        self._patch_xrefs(monkeypatch, lr)
        backend = _make_backend()
        backend.program.getAddressFactory.return_value.getAddress.return_value = _make_mock_addr(0x1000)

        out = analysis._xrefs_sync(backend, [{'addr': '0x1000', 'direction': 'to'}])
        item = out[0]

        assert 'result' not in item            # wrapper dropped
        assert item['items'] == lr.items       # rows lifted under 'items'
        assert item['error'] is None
        assert item['direction'] == 'to'
        assert item['addr']                    # resolved addr echoed
        assert 'page_info' in item             # ListResult fields lifted

    def test_target_alias_still_accepted(self, monkeypatch):
        """'target' key (legacy alias) is accepted and resolves correctly."""
        from mcpyghidra.models import ListResult, ResultPageInfo
        import mcpyghidra.tools.analysis as analysis

        lr = ListResult(
            summary='s', entry_type='cross-reference', schema_version=1,
            page_info=ResultPageInfo(offset=0, limit=500, num_returned=0,
                                     total_count=0, has_more=False, next_offset=None),
            items=[],
        )
        self._patch_xrefs(monkeypatch, lr)
        backend = _make_backend()
        backend.program.getAddressFactory.return_value.getAddress.return_value = _make_mock_addr(0x1000)

        out = analysis._xrefs_sync(backend, [{'target': '0x1000'}])  # legacy alias
        assert out[0]['error'] is None
        assert out[0]['items'] == []

    def test_ea_alias_accepted(self, monkeypatch):
        """'ea' key is accepted as an alias for addr."""
        from mcpyghidra.models import ListResult, ResultPageInfo
        import mcpyghidra.tools.analysis as analysis

        lr = ListResult(
            summary='s', entry_type='cross-reference', schema_version=1,
            page_info=ResultPageInfo(offset=0, limit=500, num_returned=0,
                                     total_count=0, has_more=False, next_offset=None),
            items=[],
        )
        self._patch_xrefs(monkeypatch, lr)
        backend = _make_backend()
        backend.program.getAddressFactory.return_value.getAddress.return_value = _make_mock_addr(0x2000)

        out = analysis._xrefs_sync(backend, [{'ea': '0x2000', 'direction': 'from'}])
        assert out[0]['error'] is None
        assert out[0]['direction'] == 'from'

    def test_function_alias_accepted(self, monkeypatch):
        """'function' key is accepted as an alias for addr (hex) or name (plain)."""
        from mcpyghidra.models import ListResult, ResultPageInfo
        import mcpyghidra.tools.analysis as analysis

        lr = ListResult(
            summary='s', entry_type='cross-reference', schema_version=1,
            page_info=ResultPageInfo(offset=0, limit=500, num_returned=0,
                                     total_count=0, has_more=False, next_offset=None),
            items=[],
        )
        self._patch_xrefs(monkeypatch, lr)
        backend = _make_backend()
        backend.program.getAddressFactory.return_value.getAddress.return_value = _make_mock_addr(0x1000)

        out = analysis._xrefs_sync(backend, [{'function': '0x1000', 'direction': 'from'}])
        assert out[0]['error'] is None
        assert out[0]['direction'] == 'from'
        assert out[0]['items'] == []

    def test_name_key_echoed_in_output(self, monkeypatch):
        """When 'name' is provided, it is echoed in the output dict."""
        from mcpyghidra.models import ListResult, ResultPageInfo
        import mcpyghidra.tools.analysis as analysis

        lr = ListResult(
            summary='s', entry_type='cross-reference', schema_version=1,
            page_info=ResultPageInfo(offset=0, limit=500, num_returned=0,
                                     total_count=0, has_more=False, next_offset=None),
            items=[],
        )
        self._patch_xrefs(monkeypatch, lr)
        backend = _make_backend()
        mock_func = MagicMock()
        mock_func.getEntryPoint.return_value = _make_mock_addr(0x3000)
        backend.flat_api.getFunction.return_value = mock_func

        out = analysis._xrefs_sync(backend, [{'name': 'my_func', 'direction': 'to'}])
        assert out[0]['error'] is None
        assert out[0]['name'] == 'my_func'
        assert 'items' in out[0]

    def test_error_path_no_result_wrapper(self):
        """Error items have 'error' key but no 'result' wrapper."""
        import mcpyghidra.tools.analysis as analysis

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        out = analysis._xrefs_sync(backend, [{'name': 'ghost_func', 'direction': 'to'}])
        item = out[0]
        assert 'error' in item
        assert 'result' not in item
        assert item['error'] is not None
