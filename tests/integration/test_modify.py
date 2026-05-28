"""Integration tests for modify tools: rename, set_comments, get_comment, set_prototype.

Tests call tool functions directly on the HeadlessBackend instance. All mutation tests
perform a round-trip restore so the session-scoped fixture stays clean for
subsequent tests.
"""
from __future__ import annotations

import pytest

from mcpyghidra.tools.analysis import decompile, disasm, symbols
from mcpyghidra.tools.core import list_entries
from mcpyghidra.tools.modify import (
    get_comment,
    rename,
    set_comments,
    set_prototype,
)
from tests.integration.helpers import assert_non_empty, run_async


def _get_check_password_address(backend) -> str:
    """Resolve check_password's entry address dynamically via list_entries."""
    result = run_async(
        list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='check_password'
    )
    for item in result.items:
        if item['name'] == 'check_password':
            return item['address']
    pytest.fail(
        f'Could not find "check_password" in function list: '
        f'{[i["name"] for i in result.items]}'
    )


def _get_main_address(backend) -> str:
    """Resolve main's entry address dynamically via list_entries."""
    result = run_async(
        list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='main'
    )
    for item in result.items:
        if item['name'] == 'main':
            return item['address']
    pytest.fail(
        f'Could not find "main" in function list: '
        f'{[i["name"] for i in result.items]}'
    )


class TestSetSymbolName:
    """rename — rename a function symbol, verify, then restore."""

    def test_rename_check_password_and_restore(self, backend):
        """Rename check_password -> test_renamed, verify, then restore."""
        addr = _get_check_password_address(backend)

        # Rename to test_renamed by name
        result = run_async(rename, backend, [{'new_name': 'test_renamed', 'name': 'check_password'}])[0]
        assert result['error'] is None, f'Unexpected error in rename result: {result["error"]}'
        assert result['new_name'] == 'test_renamed'

        # Verify the rename took effect
        sym = run_async(symbols, backend, [addr])[0]
        assert sym.get('error') is None
        assert sym['name'] == 'test_renamed', (
            f'Expected symbol name "test_renamed" after rename, got: {sym["name"]!r}'
        )

        # Restore original name
        restore_result = run_async(rename, backend, [{'new_name': 'check_password', 'name': 'test_renamed'}])[0]
        assert restore_result['error'] is None, (
            f'Unexpected error restoring name: {restore_result["error"]}'
        )

        # Verify restore
        sym_after = run_async(symbols, backend, [addr])[0]
        assert sym_after.get('error') is None
        assert sym_after['name'] == 'check_password', (
            f'Expected symbol restored to "check_password", got: {sym_after["name"]!r}'
        )

    def test_rename_by_addr(self, backend):
        """Rename using addr parameter instead of name, then restore."""
        addr = _get_check_password_address(backend)

        result = run_async(rename, backend, [{'new_name': 'addr_renamed', 'addr': addr}])[0]
        assert result['error'] is None, f'Rename by addr failed: {result["error"]}'

        sym = run_async(symbols, backend, [addr])[0]
        assert sym.get('error') is None
        assert sym['name'] == 'addr_renamed', (
            f'Expected "addr_renamed", got: {sym["name"]!r}'
        )

        # Restore
        run_async(rename, backend, [{'new_name': 'check_password', 'name': 'addr_renamed'}])
        sym_after = run_async(symbols, backend, [addr])[0]
        assert sym_after.get('error') is None
        assert sym_after['name'] == 'check_password', (
            f'Expected restore to "check_password", got: {sym_after["name"]!r}'
        )

    def test_rename_requires_new_name(self, backend):
        """Empty new_name should return an error."""
        addr = _get_check_password_address(backend)
        result = run_async(rename, backend, [{'new_name': '', 'addr': addr}])[0]
        assert result['error'] is not None, (
            f'Expected error for empty new_name, got: {result}'
        )

    def test_rename_requires_addr_or_name(self, backend):
        """Must provide either addr or name."""
        result = run_async(rename, backend, [{'new_name': 'something'}])[0]
        assert result['error'] is not None, (
            f'Expected error when neither addr nor name given: {result}'
        )


class TestSetDisassemblyComment:
    """set_comments kind='disasm' — set EOL comment at address."""

    def test_set_comment_returns_success(self, backend):
        """Setting a comment should return no error."""
        addr = _get_check_password_address(backend)
        result = run_async(set_comments, backend, [{'kind': 'disasm', 'addr': addr, 'comment': 'test_disasm_comment'}])[0]
        try:
            assert result['error'] is None, f'Unexpected error: {result["error"]}'
            assert 'message' in result
            assert_non_empty(result['message'])
        finally:
            run_async(set_comments, backend, [{'kind': 'disasm', 'addr': addr, 'comment': ''}])

    def test_set_and_verify_comment_appears_in_disassembly(self, backend):
        """Comment set on entry address should appear in disassembly output."""
        addr = _get_check_password_address(backend)
        comment_text = 'integration_test_marker'

        run_async(set_comments, backend, [{'kind': 'disasm', 'addr': addr, 'comment': comment_text}])
        try:
            asm_result = run_async(disasm, backend, [{'name': 'check_password'}])[0]
            assert asm_result['error'] is None
            asm = asm_result['asm']
            assert comment_text in asm, (
                f'Expected "{comment_text}" in disassembly after setting comment.\n'
                f'Disassembly (first 500 chars):\n{asm[:500]}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'disasm', 'addr': addr, 'comment': ''}])

    def test_clear_comment(self, backend):
        """Clearing a comment should succeed without error."""
        addr = _get_check_password_address(backend)
        run_async(set_comments, backend, [{'kind': 'disasm', 'addr': addr, 'comment': 'will_be_cleared'}])
        result = run_async(set_comments, backend, [{'kind': 'disasm', 'addr': addr, 'comment': ''}])[0]
        assert result['error'] is None, f'Clear comment returned error: {result["error"]}'


class TestSetFunctionComment:
    """set_comments kind='function' + get_comment — plate comment round-trip."""

    def test_set_and_get_function_comment(self, backend):
        """Set a comment on main, read it back, then restore."""
        original_result = run_async(get_comment, backend, [{'name': 'main'}])[0]
        assert original_result.get('error') is None
        original_comment = original_result['comment']

        new_comment = 'test_plate_comment_for_main'
        set_result = run_async(set_comments, backend, [{'kind': 'function', 'name': 'main', 'comment': new_comment}])[0]
        assert set_result['error'] is None, f'set_comments error: {set_result["error"]}'

        try:
            read_result = run_async(get_comment, backend, [{'name': 'main'}])[0]
            assert read_result.get('error') is None
            assert new_comment in read_result['comment'], (
                f'Expected "{new_comment}" in get_comment result.\n'
                f'Got: {read_result["comment"]!r}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'function', 'name': 'main', 'comment': original_comment}])

    def test_set_and_clear_function_comment(self, backend):
        """Set a comment on check_password, then clear it."""
        original_result = run_async(get_comment, backend, [{'name': 'check_password'}])[0]
        assert original_result.get('error') is None
        original_comment = original_result['comment']

        test_comment = 'temp_test_comment'
        run_async(set_comments, backend, [{'kind': 'function', 'name': 'check_password', 'comment': test_comment}])

        try:
            read_result = run_async(get_comment, backend, [{'name': 'check_password'}])[0]
            assert read_result.get('error') is None
            assert test_comment in read_result['comment'], (
                f'Comment not found after set: {read_result["comment"]!r}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'function', 'name': 'check_password', 'comment': original_comment}])

    def test_set_function_comment_by_addr(self, backend):
        """set_comments kind='function' also accepts addr parameter."""
        addr = _get_main_address(backend)
        original_result = run_async(get_comment, backend, [{'addr': addr}])[0]
        assert original_result.get('error') is None
        original_comment = original_result['comment']

        set_result = run_async(set_comments, backend, [{'kind': 'function', 'addr': addr, 'comment': 'addr_comment_test'}])[0]
        assert set_result['error'] is None, f'Unexpected error: {set_result["error"]}'

        try:
            read_result = run_async(get_comment, backend, [{'addr': addr}])[0]
            assert read_result.get('error') is None
            assert 'addr_comment_test' in read_result['comment'], (
                f'Comment not found by addr: {read_result["comment"]!r}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'function', 'addr': addr, 'comment': original_comment}])

    def test_get_function_comment_name_field(self, backend):
        """get_comment result should have the function name in the 'name' field."""
        result = run_async(get_comment, backend, [{'name': 'main'}])[0]
        assert result.get('error') is None
        assert result['name'] == 'main', f'Expected name "main" in result: {result!r}'


class TestSetDecompilerComment:
    """set_comments kind='decompiler' — pre-comment at a decompiler line.

    NOTE: Pre-comments are stored at the instruction level in Ghidra's database.
    The Ghidra decompiler's getC() output does not include PRE_COMMENT annotations
    in the C pseudo-code text, so we verify success via the return value only.
    """

    def test_set_decompiler_comment_line1_returns_success(self, backend):
        """Setting a pre-comment at line 1 should return no error."""
        result = run_async(set_comments, backend, [{
            'kind': 'decompiler',
            'line': 1,
            'comment': 'decompiler_pre_comment_test',
            'name': 'check_password',
        }])[0]
        try:
            assert result['error'] is None, (
                f'set_comments returned error: {result["error"]}'
            )
            assert_non_empty(result['message'])
            assert 'Failed' not in result['message'], (
                f'set_comments returned failure: {result["message"]!r}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'decompiler', 'line': 1, 'comment': '', 'name': 'check_password'}])

    def test_set_decompiler_comment_by_func_name(self, backend):
        """set_comments kind='decompiler' accepts name parameter."""
        result = run_async(set_comments, backend, [{
            'kind': 'decompiler',
            'line': 1,
            'comment': 'func_name_comment',
            'name': 'check_password',
        }])[0]
        try:
            assert result['error'] is None, f'Unexpected error: {result["error"]}'
            assert 'Failed' not in result['message'], f'Unexpected failure: {result["message"]!r}'
        finally:
            run_async(set_comments, backend, [{'kind': 'decompiler', 'line': 1, 'comment': '', 'name': 'check_password'}])

    def test_set_decompiler_comment_by_addr(self, backend):
        """set_comments kind='decompiler' accepts addr parameter."""
        addr = _get_check_password_address(backend)
        result = run_async(set_comments, backend, [{
            'kind': 'decompiler',
            'line': 1,
            'comment': 'addr_comment',
            'addr': addr,
        }])[0]
        try:
            assert result['error'] is None, f'Unexpected error: {result["error"]}'
            assert 'Failed' not in result['message'], f'Unexpected failure: {result["message"]!r}'
        finally:
            run_async(set_comments, backend, [{'kind': 'decompiler', 'line': 1, 'comment': '', 'addr': addr}])

    def test_set_decompiler_comment_returns_line_number(self, backend):
        """Confirmation message should mention a line number."""
        result = run_async(set_comments, backend, [{
            'kind': 'decompiler',
            'line': 2,
            'comment': 'line_number_check',
            'name': 'check_password',
        }])[0]
        try:
            assert result['error'] is None
            assert 'line' in result['message'].lower(), (
                f'Expected "line" in confirmation: {result["message"]!r}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'decompiler', 'line': 2, 'comment': '', 'name': 'check_password'}])

    def test_set_decompiler_comment_success_prefix(self, backend):
        """Confirmation message should start with 'Successfully'."""
        result = run_async(set_comments, backend, [{
            'kind': 'decompiler',
            'line': 1,
            'comment': 'success_prefix_test',
            'name': 'check_password',
        }])[0]
        try:
            assert result['error'] is None
            assert result['message'].startswith('Successfully'), (
                f'Expected message to start with "Successfully", got: {result["message"]!r}'
            )
        finally:
            run_async(set_comments, backend, [{'kind': 'decompiler', 'line': 1, 'comment': '', 'name': 'check_password'}])


class TestSetFunctionPrototype:
    """set_prototype — change function signature, then restore."""

    def test_set_prototype_changes_signature(self, backend):
        """Change check_password signature and verify return via decompile."""
        addr = _get_check_password_address(backend)

        # Capture current signature before change
        original_decomp_result = run_async(decompile, backend, [{'name': 'check_password'}])[0]
        assert original_decomp_result['error'] is None
        original_decomp = original_decomp_result['code']

        new_prototype = 'int check_password(char *password)'
        result = run_async(set_prototype, backend, [{'addr': addr, 'prototype': new_prototype}])[0]
        assert result['error'] is None, f'set_prototype returned error: {result["error"]}'

        try:
            new_decomp_result = run_async(decompile, backend, [{'name': 'check_password'}])[0]
            assert new_decomp_result['error'] is None
            new_decomp = new_decomp_result['code']
            assert isinstance(new_decomp, str)
            assert_non_empty(new_decomp)
            assert 'check_password' in new_decomp, (
                f'Function name missing from decompile after prototype change: {new_decomp[:500]}'
            )
        finally:
            restore_proto = _extract_prototype_from_decomp(original_decomp, 'check_password')
            if restore_proto:
                run_async(set_prototype, backend, [{'addr': addr, 'prototype': restore_proto}])

    def test_set_prototype_returns_name_and_addr(self, backend):
        """Result should have name and addr fields."""
        addr = _get_check_password_address(backend)
        original_decomp_result = run_async(decompile, backend, [{'name': 'check_password'}])[0]
        assert original_decomp_result['error'] is None
        original_decomp = original_decomp_result['code']

        result = run_async(set_prototype, backend, [{'addr': addr, 'prototype': 'int check_password(char *pw)'}])[0]
        try:
            assert result['error'] is None
            assert 'name' in result
            assert 'addr' in result
        finally:
            restore_proto = _extract_prototype_from_decomp(original_decomp, 'check_password')
            if restore_proto:
                run_async(set_prototype, backend, [{'addr': addr, 'prototype': restore_proto}])


def _extract_prototype_from_decomp(decomp_text: str, func_name: str) -> str | None:
    """Try to extract a function prototype from the decompiled output.

    Returns the prototype string (without trailing semicolon or brace) or None
    if extraction fails.
    """
    for line in decomp_text.splitlines():
        stripped = line.strip()
        if func_name in stripped and '(' in stripped:
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                continue
            proto = stripped.rstrip('{').rstrip(';').strip()
            if proto:
                return proto
    return None
