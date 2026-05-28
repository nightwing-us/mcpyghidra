"""Integration tests for analysis tools: decompile, disasm, symbols, xrefs.

Tests call tool functions directly on the HeadlessBackend instance. pyghidra must
be available (tests are session-scoped via conftest.py fixtures).
"""
from __future__ import annotations

import pytest

from mcpyghidra.tools.analysis import decompile, disasm, symbols, xrefs
from mcpyghidra.tools.core import get_funcs, list_entries
from mcpyghidra.tools.modify import get_comment
from tests.integration.helpers import assert_non_empty, assert_valid_address, run_async


def _get_main_address(backend) -> str:
    """Resolve main's entry address dynamically via list_entries."""
    result = run_async(list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='main')
    for item in result.items:
        if item['name'] == 'main':
            return item['address']
    pytest.fail(f'Could not find "main" in function list: {[i["name"] for i in result.items]}')


def _get_check_password_address(backend) -> str:
    """Resolve check_password's entry address dynamically via list_entries."""
    result = run_async(list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='check_password')
    for item in result.items:
        if item['name'] == 'check_password':
            return item['address']
    pytest.fail(
        f'Could not find "check_password" in function list: {[i["name"] for i in result.items]}'
    )


class TestDecompileFunction:
    """decompile(backend, [{'name': ...}])[0] -> dict with 'code'."""

    def test_decompile_main_by_name(self, backend):
        result = run_async(decompile, backend, [{'name': 'main'}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        code = result['code']
        assert isinstance(code, str)
        assert_non_empty(code)

    def test_decompile_main_contains_check_password(self, backend):
        result = run_async(decompile, backend, [{'name': 'main'}])[0]
        assert result['error'] is None
        assert 'check_password' in result['code'], (
            f'Expected "check_password" in decompilation of main, got:\n{result["code"][:500]}'
        )

    def test_decompile_main_by_addr(self, backend):
        addr = _get_main_address(backend)
        result = run_async(decompile, backend, [{'addr': addr}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        code = result['code']
        assert isinstance(code, str)
        assert_non_empty(code)
        assert 'check_password' in code, (
            f'Decompile by addr should also find check_password, got:\n{code[:500]}'
        )

    def test_decompile_check_password(self, backend):
        result = run_async(decompile, backend, [{'name': 'check_password'}])[0]
        assert result['error'] is None
        code = result['code']
        assert isinstance(code, str)
        assert_non_empty(code)
        assert 'strcmp' in code or 'check_password' in code, (
            f'Expected strcmp or check_password in decompilation, got:\n{code[:500]}'
        )

    def test_decompile_nonexistent_returns_error(self, backend):
        result = run_async(decompile, backend, [{'name': 'nonexistent_function_xyz'}])[0]
        assert result['error'] is not None, (
            'Expected error for nonexistent function, got none'
        )

    def test_decompile_batch_returns_list(self, backend):
        results = run_async(decompile, backend, [{'name': 'main'}, {'name': 'check_password'}])
        assert isinstance(results, list)
        assert len(results) == 2
        for r in results:
            assert r['error'] is None, f'Unexpected error: {r["error"]}'


class TestDisassembleFunction:
    """disasm(backend, [{'name': ...}])[0] -> dict with 'asm' containing ':' per line."""

    def test_disassemble_main_by_name(self, backend):
        result = run_async(disasm, backend, [{'name': 'main'}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        asm = result['asm']
        assert isinstance(asm, str)
        assert_non_empty(asm)

    def test_disassemble_main_has_colon_separators(self, backend):
        result = run_async(disasm, backend, [{'name': 'main'}])[0]
        assert result['error'] is None
        lines = [ln for ln in result['asm'].splitlines() if ln.strip()]
        assert len(lines) > 0, 'Expected at least one disassembly line'
        for line in lines:
            assert ':' in line, f'Expected ":" separator in disassembly line: {line!r}'

    def test_disassemble_returns_multiple_lines(self, backend):
        result = run_async(disasm, backend, [{'name': 'main'}])[0]
        assert result['error'] is None
        lines = [ln for ln in result['asm'].splitlines() if ln.strip()]
        assert len(lines) > 1, f'Expected multiple disassembly lines, got: {lines}'

    def test_disassemble_main_by_addr(self, backend):
        addr = _get_main_address(backend)
        result = run_async(disasm, backend, [{'addr': addr}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        assert isinstance(result['asm'], str)
        assert_non_empty(result['asm'])

    def test_disassemble_mode_is_function(self, backend):
        result = run_async(disasm, backend, [{'name': 'main'}])[0]
        assert result['error'] is None
        assert result['mode'] == 'function'


class TestDisassembleAddr:
    """disasm with count → address mode: disassemble N instructions from addr."""

    def test_disassemble_addr_basic(self, backend):
        addr = _get_main_address(backend)
        result = run_async(disasm, backend, [{'addr': addr, 'count': 10}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        assert isinstance(result['asm'], str)
        assert_non_empty(result['asm'])

    def test_disassemble_addr_line_count(self, backend):
        addr = _get_main_address(backend)
        result = run_async(disasm, backend, [{'addr': addr, 'count': 5}])[0]
        assert result['error'] is None
        lines = [ln for ln in result['asm'].splitlines() if ln.strip()]
        assert len(lines) >= 5, (
            f'Expected at least 5 lines for count=5, got {len(lines)}:\n{result["asm"]}'
        )

    def test_disassemble_addr_default_count(self, backend):
        addr = _get_main_address(backend)
        result = run_async(disasm, backend, [{'addr': addr, 'count': 10}])[0]
        assert result['error'] is None
        lines = [ln for ln in result['asm'].splitlines() if ln.strip()]
        assert len(lines) >= 3, (
            f'Expected multiple lines with count=10, got:\n{result["asm"]}'
        )

    def test_disassemble_addr_mode_is_address(self, backend):
        addr = _get_main_address(backend)
        result = run_async(disasm, backend, [{'addr': addr, 'count': 5}])[0]
        assert result['error'] is None
        assert result['mode'] == 'address'


class TestFindFunctionContaining:
    """get_funcs(backend, [addr]) resolves function by address."""

    def test_find_function_containing_main_addr(self, backend):
        addr = _get_main_address(backend)
        result = run_async(get_funcs, backend, [addr])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert result['name'] == 'main', f'Expected function name "main", got: {result["name"]!r}'

    def test_find_function_containing_returns_function_info(self, backend):
        addr = _get_main_address(backend)
        result = run_async(get_funcs, backend, [addr])[0]
        assert result.get('error') is None
        assert 'name' in result
        assert 'entrypoint' in result
        assert_valid_address(result['entrypoint'])

    def test_find_function_containing_check_password(self, backend):
        addr = _get_check_password_address(backend)
        result = run_async(get_funcs, backend, [addr])[0]
        assert result.get('error') is None
        assert result['name'] == 'check_password', (
            f'Expected "check_password", got: {result["name"]!r}'
        )


class TestGetSymbol:
    """symbols(backend, [addr])[0] -> dict with 'name' and 'symbol_type'."""

    def test_get_symbol_at_main(self, backend):
        addr = _get_main_address(backend)
        result = run_async(symbols, backend, [addr])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert result['name'] == 'main', f'Expected symbol name "main", got: {result["name"]!r}'

    def test_get_symbol_has_symbol_type(self, backend):
        addr = _get_main_address(backend)
        result = run_async(symbols, backend, [addr])[0]
        assert result.get('error') is None
        valid_types = {'function', 'code_label', 'global_variable', 'data_label', 'unknown'}
        assert result['symbol_type'] in valid_types, (
            f'Expected symbol_type in {valid_types}, got: {result["symbol_type"]!r}'
        )

    def test_get_symbol_main_is_function_type(self, backend):
        addr = _get_main_address(backend)
        result = run_async(symbols, backend, [addr])[0]
        assert result.get('error') is None
        assert result['symbol_type'] == 'function', (
            f'Expected main to have symbol_type="function", got: {result["symbol_type"]!r}'
        )

    def test_get_symbol_check_password(self, backend):
        addr = _get_check_password_address(backend)
        result = run_async(symbols, backend, [addr])[0]
        assert result.get('error') is None
        assert result['name'] == 'check_password', f'Got: {result["name"]!r}'
        assert result['symbol_type'] == 'function'


class TestFindXrefsToAddr:
    """xrefs(backend, [{'target': addr, 'direction': 'to'}])[0]['result'] -> ListResult."""

    def test_find_xrefs_to_check_password(self, backend):
        """check_password is called from main — xrefs list should be non-empty."""
        addr = _get_check_password_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'to'}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        list_result = result['result']
        assert list_result is not None
        assert isinstance(list_result.items, list)
        assert len(list_result.items) > 0, (
            'Expected at least one xref to check_password (called from main)'
        )

    def test_xrefs_items_have_from_key(self, backend):
        addr = _get_check_password_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'to'}])[0]
        assert result['error'] is None
        for item in result['result'].items:
            assert isinstance(item, dict)
            assert 'from' in item, f'Xref item missing "from" key: {item!r}'

    def test_xrefs_from_main_calls_check_password(self, backend):
        """The xref from main to check_password should identify main as the caller."""
        addr = _get_check_password_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'to'}])[0]
        assert result['error'] is None
        caller_funcs = []
        for item in result['result'].items:
            from_info = item.get('from', {})
            if isinstance(from_info, dict) and 'function' in from_info:
                caller_funcs.append(from_info['function'])
        assert 'main' in caller_funcs, (
            f'Expected "main" among callers of check_password, found: {caller_funcs}'
        )

    def test_xrefs_has_page_info(self, backend):
        addr = _get_check_password_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'to'}])[0]
        assert result['error'] is None
        list_result = result['result']
        assert list_result.page_info is not None
        assert list_result.page_info.total_count >= 0

    def test_xrefs_pagination(self, backend):
        """limit=1 should return at most 1 item."""
        addr = _get_check_password_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'to', 'limit': 1}])[0]
        assert result['error'] is None
        assert len(result['result'].items) <= 1


class TestFindXrefsFromAddr:
    """xrefs(backend, [{'target': addr, 'direction': 'from'}])[0]['result'] -> ListResult."""

    def test_find_xrefs_from_main(self, backend):
        """main calls check_password — outgoing xrefs should be non-empty."""
        addr = _get_main_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'from'}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        list_result = result['result']
        assert list_result is not None
        assert isinstance(list_result.items, list)

    def test_xrefs_from_items_have_to_key(self, backend):
        addr = _get_main_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'from'}])[0]
        assert result['error'] is None
        for item in result['result'].items:
            assert isinstance(item, dict)
            assert 'to' in item, f'Xref-from item missing "to" key: {item!r}'

    def test_xrefs_from_has_page_info(self, backend):
        addr = _get_main_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'from'}])[0]
        assert result['error'] is None
        list_result = result['result']
        assert list_result.page_info is not None
        assert list_result.page_info.total_count >= 0

    def test_xrefs_from_pagination_limit(self, backend):
        """limit=1 should return at most 1 item."""
        addr = _get_main_address(backend)
        result = run_async(xrefs, backend, [{'target': addr, 'direction': 'from', 'limit': 1}])[0]
        assert result['error'] is None
        assert len(result['result'].items) <= 1


class TestFindXrefsToFunc:
    """xrefs with function name target (not 0x prefix) → resolves via name."""

    def test_find_xrefs_to_check_password_by_name(self, backend):
        """check_password is called from main — xrefs should be non-empty."""
        result = run_async(xrefs, backend, [{'target': 'check_password', 'direction': 'to'}])[0]
        assert result['error'] is None, f'Unexpected error: {result["error"]}'
        list_result = result['result']
        assert list_result is not None
        assert isinstance(list_result.items, list)
        assert len(list_result.items) > 0, (
            'Expected at least one xref to check_password (called from main)'
        )

    def test_xrefs_to_func_items_have_from_key(self, backend):
        result = run_async(xrefs, backend, [{'target': 'check_password', 'direction': 'to'}])[0]
        assert result['error'] is None
        for item in result['result'].items:
            assert isinstance(item, dict)
            assert 'from' in item, f'Xref item missing "from" key: {item!r}'

    def test_xrefs_to_func_caller_is_main(self, backend):
        """The caller of check_password should include main."""
        result = run_async(xrefs, backend, [{'target': 'check_password', 'direction': 'to'}])[0]
        assert result['error'] is None
        caller_funcs = []
        for item in result['result'].items:
            from_info = item.get('from', {})
            if isinstance(from_info, dict) and 'function' in from_info:
                caller_funcs.append(from_info['function'])
        assert 'main' in caller_funcs, (
            f'Expected "main" among callers of check_password (by name), found: {caller_funcs}'
        )

    def test_xrefs_to_func_has_page_info(self, backend):
        result = run_async(xrefs, backend, [{'target': 'check_password', 'direction': 'to'}])[0]
        assert result['error'] is None
        list_result = result['result']
        assert list_result.page_info is not None
        assert list_result.page_info.total_count >= 0

    def test_xrefs_to_func_pagination_limit(self, backend):
        """limit=1 should return at most 1 item."""
        result = run_async(xrefs, backend, [{'target': 'check_password', 'direction': 'to', 'limit': 1}])[0]
        assert result['error'] is None
        assert len(result['result'].items) <= 1


class TestGetFunctionComment:
    """get_comment(backend, [{'name': ...}])[0] -> dict with 'comment', 'name', 'addr'."""

    def test_get_function_comment_by_name_returns_dict(self, backend):
        result = run_async(get_comment, backend, [{'name': 'main'}])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert 'comment' in result
        assert 'name' in result
        assert 'addr' in result

    def test_get_function_comment_contains_function_name(self, backend):
        result = run_async(get_comment, backend, [{'name': 'main'}])[0]
        assert result.get('error') is None
        assert result['name'] == 'main', (
            f'Expected result name "main", got: {result["name"]!r}'
        )

    def test_get_function_comment_by_addr(self, backend):
        addr = _get_main_address(backend)
        result = run_async(get_comment, backend, [{'addr': addr}])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert 'comment' in result
        assert 'addr' in result

    def test_get_function_comment_check_password(self, backend):
        result = run_async(get_comment, backend, [{'name': 'check_password'}])[0]
        assert result.get('error') is None
        assert result['name'] == 'check_password', (
            f'Expected result name "check_password", got: {result["name"]!r}'
        )
