"""Unit tests targeting error / defensive branches in tools/modify.py.

Goal: push modify.py from ~5% line / 0% branch to 70%+ line / ~100% branch.

All tests run without Ghidra/pyghidra by stubbing Java imports via sys.modules
and using MagicMock for the backend.

One branch per test, single assertion preferred.
"""
from __future__ import annotations

import sys
from contextlib import contextmanager
from types import ModuleType
from unittest.mock import MagicMock, patch

import anyio
import pytest

from mcpyghidra.backend import GhidraError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_async(async_fn, *args, **kwargs):
    """Run an async tool function synchronously for unit tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


def _make_backend():
    """Minimal mock backend with transaction context manager support."""
    backend = MagicMock()
    backend.is_headless = True
    backend.program = MagicMock()
    tx_ctx = MagicMock()
    tx_ctx.__enter__ = MagicMock(return_value=None)
    tx_ctx.__exit__ = MagicMock(return_value=False)
    backend.create_transaction.return_value = tx_ctx
    return backend


@contextmanager
def _stub_ghidra_symbol_types():
    """Inject a fake ghidra.program.model.symbol module with SourceType and SymbolType."""
    source_type_mock = MagicMock()
    source_type_mock.USER_DEFINED = 'USER_DEFINED'
    source_type_mock.IMPORTED = 'IMPORTED'
    source_type_mock.ANALYSIS = 'ANALYSIS'
    source_type_mock.AI = 'AI'

    symbol_type_mock = MagicMock()
    symbol_type_mock.FUNCTION = 'FUNCTION'
    symbol_type_mock.LABEL = 'LABEL'
    symbol_type_mock.GLOBAL = 'GLOBAL'

    symbol_mod = ModuleType('ghidra.program.model.symbol')
    symbol_mod.SourceType = source_type_mock  # type: ignore[attr-defined]
    symbol_mod.SymbolType = symbol_type_mock  # type: ignore[attr-defined]

    sys.modules.setdefault('ghidra', MagicMock())
    sys.modules.setdefault('ghidra.program', MagicMock())
    sys.modules.setdefault('ghidra.program.model', MagicMock())
    sys.modules['ghidra.program.model.symbol'] = symbol_mod

    try:
        yield source_type_mock, symbol_type_mock
    finally:
        # Restore only what we explicitly set
        sys.modules['ghidra.program.model.symbol'] = symbol_mod  # leave as-is


# ---------------------------------------------------------------------------
# _is_higher_priority_source
# ---------------------------------------------------------------------------


class TestIsHigherPrioritySource:
    def test_user_defined_is_higher_priority(self):
        with _stub_ghidra_symbol_types() as (src_type, _):
            from mcpyghidra.tools.modify import _is_higher_priority_source
            assert _is_higher_priority_source(src_type.USER_DEFINED) is True

    def test_imported_is_higher_priority(self):
        with _stub_ghidra_symbol_types() as (src_type, _):
            from mcpyghidra.tools.modify import _is_higher_priority_source
            assert _is_higher_priority_source(src_type.IMPORTED) is True

    def test_analysis_is_not_higher_priority(self):
        with _stub_ghidra_symbol_types() as (src_type, _):
            from mcpyghidra.tools.modify import _is_higher_priority_source
            assert _is_higher_priority_source(src_type.ANALYSIS) is False

    def test_ai_source_is_not_higher_priority(self):
        with _stub_ghidra_symbol_types() as (src_type, _):
            from mcpyghidra.tools.modify import _is_higher_priority_source
            assert _is_higher_priority_source(src_type.AI) is False


# ---------------------------------------------------------------------------
# _rename_sync — name-mismatch path (function branch)
# ---------------------------------------------------------------------------


class TestRenameSyncNameMismatch:
    def test_function_name_mismatch_produces_error(self):
        """When name='foo' but actual function name is 'bar', produce error dict."""
        with _stub_ghidra_symbol_types() as (src_type, sym_type):
            backend = _make_backend()

            mock_func = MagicMock()
            mock_func.getName.return_value = 'bar'
            mock_func.getEntryPoint.return_value.offset = 0x1000
            mock_func.getSymbol.return_value.getSource.return_value = src_type.ANALYSIS

            mock_ea = MagicMock()
            mock_ea.offset = 0x1000

            backend.program.getListing.return_value.getFunctionAt.return_value = mock_func
            backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = None

            with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
                from mcpyghidra.tools.modify import _rename_sync
                results = _rename_sync(
                    backend,
                    [{'new_name': 'new_foo', 'addr': '0x1000', 'name': 'foo'}],
                )

            assert results[0]['error'] is not None
            assert 'mismatch' in results[0]['error']

    def test_symbol_name_mismatch_produces_error(self):
        """When sym branch: name='foo' but symbol.getName()='bar' → error dict."""
        with _stub_ghidra_symbol_types() as (src_type, sym_type):
            backend = _make_backend()

            mock_sym = MagicMock()
            mock_sym.getName.return_value = 'bar'
            mock_sym.getSource.return_value = src_type.ANALYSIS

            mock_ea = MagicMock()
            mock_ea.offset = 0x2000

            backend.program.getListing.return_value.getFunctionAt.return_value = None
            backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = mock_sym

            with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
                from mcpyghidra.tools.modify import _rename_sync
                results = _rename_sync(
                    backend,
                    [{'new_name': 'new_foo', 'addr': '0x2000', 'name': 'foo'}],
                )

            assert results[0]['error'] is not None
            assert 'mismatch' in results[0]['error']


# ---------------------------------------------------------------------------
# _rename_sync — confirm_overwrite returns False ("skipped" outcome)
# ---------------------------------------------------------------------------


class TestRenameSyncConfirmOverwrite:
    def test_function_skipped_when_confirm_overwrite_returns_false(self):
        """When symbol is USER_DEFINED and backend.confirm_overwrite returns False,
        result should have 'skipped' in error message."""
        with _stub_ghidra_symbol_types() as (src_type, sym_type):
            backend = _make_backend()
            backend.confirm_overwrite.return_value = False

            mock_func = MagicMock()
            mock_func.getName.return_value = 'real_name'
            mock_func.getEntryPoint.return_value.offset = 0x3000
            mock_func.getSymbol.return_value.getSource.return_value = src_type.USER_DEFINED

            mock_ea = MagicMock()
            mock_ea.offset = 0x3000

            backend.program.getListing.return_value.getFunctionAt.return_value = mock_func
            backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = None

            with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
                from mcpyghidra.tools.modify import _rename_sync
                results = _rename_sync(
                    backend,
                    [{'new_name': 'attempted_name', 'addr': '0x3000', 'name': ''}],
                )

            assert 'skipped' in results[0]['error']

    def test_symbol_skipped_when_confirm_overwrite_returns_false(self):
        """Non-function symbol with USER_DEFINED source and confirm_overwrite=False → skipped."""
        with _stub_ghidra_symbol_types() as (src_type, sym_type):
            backend = _make_backend()
            backend.confirm_overwrite.return_value = False

            mock_sym = MagicMock()
            mock_sym.getName.return_value = 'real_sym'
            mock_sym.getSource.return_value = src_type.IMPORTED

            mock_ea = MagicMock()
            mock_ea.offset = 0x4000

            backend.program.getListing.return_value.getFunctionAt.return_value = None
            backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = mock_sym

            with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
                from mcpyghidra.tools.modify import _rename_sync
                results = _rename_sync(
                    backend,
                    [{'new_name': 'new_sym', 'addr': '0x4000', 'name': ''}],
                )

            assert 'skipped' in results[0]['error']


# ---------------------------------------------------------------------------
# _validate_comment_item
# ---------------------------------------------------------------------------


class TestValidateCommentItem:
    def test_disasm_without_addr_raises(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        with pytest.raises(GhidraError, match="requires addr"):
            _validate_comment_item('disasm', addr='', name='', line=None)

    def test_decompiler_without_line_raises(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        with pytest.raises(GhidraError, match="requires line"):
            _validate_comment_item('decompiler', addr='0x1000', name='', line=None)

    def test_decompiler_without_addr_or_name_raises(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        with pytest.raises(GhidraError, match="requires addr or name"):
            _validate_comment_item('decompiler', addr='', name='', line=1)

    def test_function_without_addr_or_name_raises(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        with pytest.raises(GhidraError, match="requires addr or name"):
            _validate_comment_item('function', addr='', name='', line=None)

    def test_both_without_addr_raises(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        with pytest.raises(GhidraError, match="requires addr"):
            _validate_comment_item('both', addr='', name='', line=None)

    def test_disasm_with_addr_does_not_raise(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        _validate_comment_item('disasm', addr='0x1000', name='', line=None)  # no exception

    def test_decompiler_with_line_and_name_does_not_raise(self):
        from mcpyghidra.tools.modify import _validate_comment_item
        _validate_comment_item('decompiler', addr='', name='my_func', line=5)  # no exception

    def test_unknown_kind_does_not_raise_in_validate(self):
        """Unknown kind passes through validate without raising (caught in caller)."""
        from mcpyghidra.tools.modify import _validate_comment_item
        _validate_comment_item('unknown_kind', addr='', name='', line=None)  # no exception


# ---------------------------------------------------------------------------
# set_comments — invalid kind produces error dict
# ---------------------------------------------------------------------------


class TestSetCommentsInvalidKind:
    def test_invalid_kind_produces_error_dict(self):
        """An unrecognised kind ('bogus') should appear as error in result."""
        backend = _make_backend()
        results = _run_async(
            __import__('mcpyghidra.tools.modify', fromlist=['set_comments']).set_comments,
            backend,
            [{'kind': 'bogus', 'addr': '0x1000', 'comment': 'hello'}],
        )
        assert results[0]['error'] is not None
        assert 'bogus' in results[0]['error'] or 'Invalid kind' in results[0]['error']


# ---------------------------------------------------------------------------
# _update_vars_sync — early return when no variables provided
# ---------------------------------------------------------------------------


class TestUpdateVarsSyncNoVars:
    def test_empty_dict_returns_error_string(self):
        backend = _make_backend()
        from mcpyghidra.tools.modify import _update_vars_sync
        result = _update_vars_sync(backend, 'some_func', {})
        assert 'ERROR' in result
        assert 'No variables' in result


# ---------------------------------------------------------------------------
# _update_vars_sync — collision: existing_var is non-None for new_name
# ---------------------------------------------------------------------------


class TestUpdateVarsSyncCollision:
    def test_collision_appends_already_exists_message(self):
        """If new_name already exists as a symbol, status contains 'already exists'."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_dec_func = MagicMock()
        mock_existing_var = MagicMock()
        mock_existing_var.name = 'buffer'

        # get_symbol returns: None for 'local_8' (old name), mock for 'buffer' (new name)
        def _get_symbol_side_effect(sym_name):
            if sym_name == 'buffer':
                return mock_existing_var
            return None

        mock_dec_func.get_symbol.side_effect = _get_symbol_side_effect
        backend.get_decompiled_func.return_value = mock_dec_func

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            from mcpyghidra.tools.modify import _update_vars_sync
            result = _update_vars_sync(
                backend,
                'main',
                {'local_8': {'new_name': 'buffer'}},
            )

        assert 'already exists' in result


# ---------------------------------------------------------------------------
# set_prototype — parser failure wrapped in ToolError / error dict
# ---------------------------------------------------------------------------


class TestSetPrototypeParserFailure:
    def test_parser_exception_produces_error_dict(self):
        """If FunctionSignatureParser.parse() raises, result has error string."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_func.getName.return_value = 'target_func'
        mock_func.getEntryPoint.return_value.offset = 0x5000
        mock_func.getComment.return_value = ''

        mock_dec_func = MagicMock()
        mock_dec_func.signature = 'void target_func()'
        backend.get_decompiled_func.return_value = mock_dec_func
        backend.program.getDataTypeManager.return_value = MagicMock()

        mock_ea = MagicMock()
        mock_ea.offset = 0x5000

        # Build minimal stubs for the ghidra imports inside _set_prototype_sync
        apply_cmd_mod = ModuleType('ghidra.app.cmd.function')
        apply_cmd_mod.ApplyFunctionSignatureCmd = MagicMock()  # type: ignore[attr-defined]
        sys.modules.setdefault('ghidra.app.cmd.function', apply_cmd_mod)

        parser_mock = MagicMock()
        parser_mock.parse.side_effect = Exception('bad prototype syntax')
        parser_class_mock = MagicMock(return_value=parser_mock)

        parser_mod = ModuleType('ghidra.app.util.parser')
        parser_mod.FunctionSignatureParser = parser_class_mock  # type: ignore[attr-defined]
        sys.modules.setdefault('ghidra.app.util.parser', parser_mod)

        task_mod = ModuleType('ghidra.util.task')
        task_mod.ConsoleTaskMonitor = MagicMock()  # type: ignore[attr-defined]
        sys.modules.setdefault('ghidra.util.task', task_mod)

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
                with patch.dict(sys.modules, {
                    'ghidra.app.cmd.function': apply_cmd_mod,
                    'ghidra.app.util.parser': parser_mod,
                    'ghidra.util.task': task_mod,
                }):
                    from mcpyghidra.tools.modify import set_prototype
                    results = _run_async(
                        set_prototype,
                        backend,
                        [{'addr': '0x5000', 'prototype': 'bad prototype !!!'}],
                    )

        assert results[0]['error'] is not None
        assert 'bad prototype syntax' in results[0]['error']


# ---------------------------------------------------------------------------
# patch — malformed hex bytes produces error dict
# ---------------------------------------------------------------------------


class TestPatchHexParsingError:
    def test_malformed_hex_produces_error_dict(self):
        """bytes.fromhex() raises ValueError on bad input → error dict."""
        backend = _make_backend()

        mock_ea = MagicMock()
        mock_ea.offset = 0x6000

        disasm_mod = ModuleType('ghidra.program.disassemble')
        disasm_mod.Disassembler = MagicMock()  # type: ignore[attr-defined]
        task_mod = sys.modules.get('ghidra.util.task') or ModuleType('ghidra.util.task')
        if not hasattr(task_mod, 'TaskMonitor'):
            task_mod.TaskMonitor = MagicMock()  # type: ignore[attr-defined]

        with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
            with patch.dict(sys.modules, {
                'ghidra.program.disassemble': disasm_mod,
                'ghidra.util.task': task_mod,
            }):
                from mcpyghidra.tools.modify import patch as patch_tool
                results = _run_async(
                    patch_tool,
                    backend,
                    [{'addr': '0x6000', 'hex_bytes': 'ZZ_NOT_HEX'}],
                )

        assert results[0]['error'] is not None

    def test_missing_addr_produces_error_dict(self):
        """addr='' should produce GhidraError error dict."""
        backend = _make_backend()

        disasm_mod = ModuleType('ghidra.program.disassemble')
        disasm_mod.Disassembler = MagicMock()  # type: ignore[attr-defined]
        task_mod_inner = ModuleType('ghidra.util.task')
        task_mod_inner.TaskMonitor = MagicMock()  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {
            'ghidra.program.disassemble': disasm_mod,
            'ghidra.util.task': task_mod_inner,
        }):
            from mcpyghidra.tools.modify import patch as patch_tool
            results = _run_async(
                patch_tool,
                backend,
                [{'addr': '', 'hex_bytes': '90'}],
            )

        assert results[0]['error'] is not None
        assert 'addr is required' in results[0]['error']

    def test_missing_hex_bytes_produces_error_dict(self):
        """hex_bytes='' should produce GhidraError error dict."""
        backend = _make_backend()

        disasm_mod = ModuleType('ghidra.program.disassemble')
        disasm_mod.Disassembler = MagicMock()  # type: ignore[attr-defined]
        task_mod_inner = ModuleType('ghidra.util.task')
        task_mod_inner.TaskMonitor = MagicMock()  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {
            'ghidra.program.disassemble': disasm_mod,
            'ghidra.util.task': task_mod_inner,
        }):
            from mcpyghidra.tools.modify import patch as patch_tool
            results = _run_async(
                patch_tool,
                backend,
                [{'addr': '0x6000', 'hex_bytes': ''}],
            )

        assert results[0]['error'] is not None
        assert 'hex_bytes is required' in results[0]['error']


# ---------------------------------------------------------------------------
# update_vars — async wrapper: empty variables_to_update
# ---------------------------------------------------------------------------


class TestUpdateVarsAsync:
    def test_async_empty_vars_returns_error_string(self):
        """update_vars() with empty dict should return error string (not raise)."""
        backend = _make_backend()
        from mcpyghidra.tools.modify import update_vars
        result = _run_async(update_vars, backend, 'some_func', {})
        assert isinstance(result, str)
        assert 'ERROR' in result


# ---------------------------------------------------------------------------
# _rename_sync — no-symbol path creates new label
# ---------------------------------------------------------------------------


class TestRenameSyncNoSymbol:
    def test_no_symbol_creates_new_label(self):
        """When both getFunctionAt and getPrimarySymbol return None, create label."""
        with _stub_ghidra_symbol_types() as (src_type, sym_type):
            backend = _make_backend()

            mock_ea = MagicMock()
            mock_ea.offset = 0x7000

            backend.program.getListing.return_value.getFunctionAt.return_value = None
            backend.program.getSymbolTable.return_value.getPrimarySymbol.return_value = None
            backend.program.getGlobalNamespace.return_value = MagicMock()

            with patch('mcpyghidra.tools.modify._get_address', return_value=mock_ea):
                from mcpyghidra.tools.modify import _rename_sync
                results = _rename_sync(
                    backend,
                    [{'new_name': 'brand_new_label', 'addr': '0x7000', 'name': ''}],
                )

            assert results[0]['error'] is None
            assert results[0]['old_name'] is None
            assert results[0]['new_name'] == 'brand_new_label'


# ---------------------------------------------------------------------------
# _rename_sync — missing new_name
# ---------------------------------------------------------------------------


class TestRenameSyncMissingNewName:
    def test_missing_new_name_produces_error(self):
        """new_name='' should produce GhidraError error dict."""
        with _stub_ghidra_symbol_types():
            backend = _make_backend()
            from mcpyghidra.tools.modify import _rename_sync
            results = _rename_sync(
                backend,
                [{'new_name': '', 'addr': '0x1000', 'name': ''}],
            )
            assert results[0]['error'] is not None
            assert 'new_name is required' in results[0]['error']


# ---------------------------------------------------------------------------
# _rename_sync — neither addr nor name provided
# ---------------------------------------------------------------------------


class TestRenameSyncNeitherAddrNorName:
    def test_neither_addr_nor_name_produces_error(self):
        """Providing neither addr nor name should produce GhidraError error dict."""
        with _stub_ghidra_symbol_types():
            backend = _make_backend()
            from mcpyghidra.tools.modify import _rename_sync
            results = _rename_sync(
                backend,
                [{'new_name': 'something'}],
            )
            assert results[0]['error'] is not None
            assert 'addr or name' in results[0]['error']


# ---------------------------------------------------------------------------
# set_prototype — missing addr or prototype
# ---------------------------------------------------------------------------


class TestSetPrototypeMissingFields:
    def _make_module_stubs(self):
        apply_cmd_mod = ModuleType('ghidra.app.cmd.function')
        apply_cmd_mod.ApplyFunctionSignatureCmd = MagicMock()  # type: ignore[attr-defined]
        parser_mod = ModuleType('ghidra.app.util.parser')
        parser_mod.FunctionSignatureParser = MagicMock()  # type: ignore[attr-defined]
        task_mod = ModuleType('ghidra.util.task')
        task_mod.ConsoleTaskMonitor = MagicMock()  # type: ignore[attr-defined]
        return {
            'ghidra.app.cmd.function': apply_cmd_mod,
            'ghidra.app.util.parser': parser_mod,
            'ghidra.util.task': task_mod,
        }

    def test_missing_addr_produces_error_dict(self):
        backend = _make_backend()
        with patch.dict(sys.modules, self._make_module_stubs()):
            from mcpyghidra.tools.modify import set_prototype
            results = _run_async(
                set_prototype,
                backend,
                [{'addr': '', 'prototype': 'int foo()'}],
            )
        assert results[0]['error'] is not None
        assert 'addr is required' in results[0]['error']

    def test_missing_prototype_produces_error_dict(self):
        backend = _make_backend()
        with patch.dict(sys.modules, self._make_module_stubs()):
            from mcpyghidra.tools.modify import set_prototype
            results = _run_async(
                set_prototype,
                backend,
                [{'addr': '0x1000', 'prototype': ''}],
            )
        assert results[0]['error'] is not None
        assert 'prototype is required' in results[0]['error']


# ---------------------------------------------------------------------------
# _update_vars_sync — no new_name and no new_type branch
# ---------------------------------------------------------------------------


class TestUpdateVarsSyncNeitherNameNorType:
    def test_neither_new_name_nor_new_type_appends_error_status(self):
        """If entry has neither new_name nor new_type, status contains ERROR message."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_dec_func = MagicMock()
        mock_dec_func.get_symbol.return_value = None

        backend.get_decompiled_func.return_value = mock_dec_func

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            from mcpyghidra.tools.modify import _update_vars_sync
            result = _update_vars_sync(
                backend,
                'main',
                {'local_4': {}},  # no new_name, no new_type
            )

        assert 'at least one of new_name or new_type is required' in result


# ---------------------------------------------------------------------------
# _update_vars_sync — success path: ghidra_var found, no collision
# ---------------------------------------------------------------------------


class TestUpdateVarsSyncSuccessPath:
    def test_successful_rename_appends_done(self):
        """When ghidra_var found and no collision, status contains 'Done'."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_ghidra_var = MagicMock()
        mock_ghidra_var.name = 'local_8'

        mock_dec_func = MagicMock()

        def _get_symbol_side(sym_name):
            # old name returns a var; new name returns None (no collision)
            if sym_name == 'local_8':
                return mock_ghidra_var
            return None

        mock_dec_func.get_symbol.side_effect = _get_symbol_side
        backend.get_decompiled_func.return_value = mock_dec_func

        with _stub_ghidra_symbol_types():
            with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
                from mcpyghidra.tools.modify import _update_vars_sync
                result = _update_vars_sync(
                    backend,
                    'main',
                    {'local_8': {'new_name': 'counter'}},
                )

        assert 'Done' in result

    def test_type_only_update_uses_original_name(self):
        """When only new_type given (no new_name), effective_name = ghidra_var.name."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_ghidra_var = MagicMock()
        mock_ghidra_var.name = 'param_1'

        mock_dec_func = MagicMock()

        def _get_symbol_side(sym_name):
            if sym_name == 'param_1':
                return mock_ghidra_var
            return None

        mock_dec_func.get_symbol.side_effect = _get_symbol_side
        backend.get_decompiled_func.return_value = mock_dec_func

        with _stub_ghidra_symbol_types():
            with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
                from mcpyghidra.tools.modify import _update_vars_sync
                result = _update_vars_sync(
                    backend,
                    'main',
                    {'param_1': {'new_type': 'char *'}},
                )

        assert 'Done' in result

    def test_update_exception_appends_error_status(self):
        """When ghidra_var.update() raises, status contains ERROR."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_ghidra_var = MagicMock()
        mock_ghidra_var.name = 'local_8'
        mock_ghidra_var.update.side_effect = RuntimeError('update failed')

        mock_dec_func = MagicMock()

        def _get_symbol_side(sym_name):
            if sym_name == 'local_8':
                return mock_ghidra_var
            return None

        mock_dec_func.get_symbol.side_effect = _get_symbol_side
        backend.get_decompiled_func.return_value = mock_dec_func

        with _stub_ghidra_symbol_types():
            with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
                from mcpyghidra.tools.modify import _update_vars_sync
                result = _update_vars_sync(
                    backend,
                    'main',
                    {'local_8': {'new_name': 'counter'}},
                )

        assert 'ERROR' in result


# ---------------------------------------------------------------------------
# _update_vars_sync — ghidra_var is None (symbol not found), no collision
# ---------------------------------------------------------------------------


class TestUpdateVarsSyncVarNotFound:
    def test_var_not_found_appends_already_exists_fallback(self):
        """When ghidra_var is None and existing_var is None, falls to else branch."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_dec_func = MagicMock()
        # Both old name and new name lookups return None
        mock_dec_func.get_symbol.return_value = None
        backend.get_decompiled_func.return_value = mock_dec_func

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            from mcpyghidra.tools.modify import _update_vars_sync
            result = _update_vars_sync(
                backend,
                'main',
                {'missing_var': {'new_name': 'new_name_here'}},
            )

        # ghidra_var is None → else branch → "already exists" message
        assert 'already exists' in result


# ---------------------------------------------------------------------------
# get_comment — success and error paths
# ---------------------------------------------------------------------------


class TestGetComment:
    def test_success_path_returns_comment(self):
        """get_comment returns comment text on success."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_func.getName.return_value = 'my_func'
        mock_func.getEntryPoint.return_value.offset = 0x9000
        mock_func.getComment.return_value = 'a plate comment'

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            from mcpyghidra.tools.modify import get_comment
            results = _run_async(get_comment, backend, [{'name': 'my_func'}])

        assert results[0]['error'] is None
        assert results[0]['comment'] == 'a plate comment'

    def test_success_path_handles_none_comment(self):
        """get_comment coerces None comment to empty string."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_func.getName.return_value = 'no_comment_func'
        mock_func.getEntryPoint.return_value.offset = 0x9100
        mock_func.getComment.return_value = None

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            from mcpyghidra.tools.modify import get_comment
            results = _run_async(get_comment, backend, [{'name': 'no_comment_func'}])

        assert results[0]['error'] is None
        assert results[0]['comment'] == ''

    def test_error_path_returns_error_dict(self):
        """get_comment wraps exceptions in error dict."""
        backend = _make_backend()

        with patch('mcpyghidra.tools.modify._get_function', side_effect=GhidraError('not found')):
            from mcpyghidra.tools.modify import get_comment
            results = _run_async(get_comment, backend, [{'name': 'missing'}])

        assert results[0]['error'] is not None
        assert 'not found' in results[0]['error']

    def test_single_item_dict_normalised_to_list(self):
        """get_comment accepts a single dict (not a list) and normalises it."""
        backend = _make_backend()

        mock_func = MagicMock()
        mock_func.getName.return_value = 'fn'
        mock_func.getEntryPoint.return_value.offset = 0x9200
        mock_func.getComment.return_value = 'x'

        with patch('mcpyghidra.tools.modify._get_function', return_value=mock_func):
            from mcpyghidra.tools.modify import get_comment
            # Pass a dict directly, not a list
            results = _run_async(get_comment, backend, {'name': 'fn'})

        assert isinstance(results, list)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# begin_trans / end_trans — sync helpers
# ---------------------------------------------------------------------------


class TestBeginEndTrans:
    def test_begin_trans_returns_started_message(self):
        backend = _make_backend()
        backend.program.startTransaction.return_value = 42

        from mcpyghidra.tools.modify import begin_trans
        result = _run_async(begin_trans, backend, 'my transaction')

        assert '42' in result
        assert 'Transaction started' in result

    def test_end_trans_returns_ended_message(self):
        backend = _make_backend()

        from mcpyghidra.tools.modify import end_trans
        result = _run_async(end_trans, backend, 7, commit=True)

        assert '7' in result
        assert 'ended' in result
