"""Unit tests for search utilities — no runtime required."""
import re

import pytest
from mcpyghidra.tools.search_utils import (
    _glob_to_regex,
    match_instruction,
    match_operand,
    parse_byte_pattern,
)


class TestParseBytePattern:
    def test_exact_bytes(self):
        data, mask = parse_byte_pattern('48 8B 05')
        assert data == bytes([0x48, 0x8B, 0x05])
        assert mask == bytes([0xFF, 0xFF, 0xFF])

    def test_wildcards(self):
        data, mask = parse_byte_pattern('48 ?? 05')
        assert data == bytes([0x48, 0x00, 0x05])
        assert mask == bytes([0xFF, 0x00, 0xFF])

    def test_all_wildcards(self):
        data, mask = parse_byte_pattern('?? ?? ??')
        assert mask == bytes([0x00, 0x00, 0x00])

    def test_single_byte(self):
        data, mask = parse_byte_pattern('90')
        assert data == bytes([0x90])
        assert mask == bytes([0xFF])

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_byte_pattern('')

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            parse_byte_pattern('GG')

    def test_case_insensitive(self):
        data, mask = parse_byte_pattern('4a Bc')
        assert data == bytes([0x4A, 0xBC])

    def test_extra_whitespace(self):
        data, mask = parse_byte_pattern('  48   8B   05  ')
        assert data == bytes([0x48, 0x8B, 0x05])


class TestMatchOperand:
    def test_wildcard(self):
        assert match_operand('*', 'RAX') is True

    def test_exact_match(self):
        assert match_operand('RAX', 'RAX') is True
        assert match_operand('RAX', 'RBX') is False

    def test_case_insensitive(self):
        assert match_operand('rax', 'RAX') is True

    def test_glob_star(self):
        assert match_operand('R*', 'RAX') is True
        assert match_operand('R*', 'RBP') is True
        assert match_operand('R*', 'EAX') is False

    def test_glob_question(self):
        assert match_operand('R?X', 'RAX') is True
        assert match_operand('R?X', 'RBX') is True
        assert match_operand('R?X', 'RBP') is False

    def test_regex(self):
        assert match_operand('/.*0xDEAD.*/', 'dword ptr [0xDEADBEEF]') is True
        assert match_operand('/.*0xDEAD.*/', 'RAX') is False

    def test_regex_case_insensitive(self):
        assert match_operand('/r[a-d]x/', 'RAX') is True
        assert match_operand('/r[a-d]x/', 'RCX') is True

    def test_memory_glob(self):
        assert match_operand('[*]', '[RBP + -0x4]') is True

    # Branch: pattern starts with '/' but len <= 2 — falls through to glob path
    def test_single_slash_treated_as_glob(self):
        # '/' has length 1, so the regex branch is NOT taken; treated as literal glob
        assert match_operand('/', '/') is True
        assert match_operand('/', 'x') is False

    def test_double_slash_treated_as_glob(self):
        # '//' has length 2, so the regex branch is NOT taken
        assert match_operand('//', '//') is True
        assert match_operand('//', 'RAX') is False

    # Branch: malformed /regex/ — re.error must return False
    def test_malformed_regex_returns_false(self):
        assert match_operand('/[invalid/', 'anything') is False

    def test_malformed_regex_unclosed_group_returns_false(self):
        assert match_operand('/(unclosed/', 'test') is False


class TestGlobToRegex:
    """Exercise every character-class branch in _glob_to_regex (lines 48–56)."""

    def test_star_becomes_dot_star(self):
        assert _glob_to_regex('a*b') == 'a.*b'

    def test_question_becomes_dot(self):
        assert _glob_to_regex('a?b') == 'a.b'

    def test_plain_chars_pass_through(self):
        assert _glob_to_regex('abc') == 'abc'

    # Each special character in r'\.+^${}|()\[\]' must be re.escaped
    def test_backslash_escaped(self):
        result = _glob_to_regex('\\')
        assert result == re.escape('\\')

    def test_dot_escaped(self):
        result = _glob_to_regex('.')
        assert result == re.escape('.')

    def test_plus_escaped(self):
        assert _glob_to_regex('+') == re.escape('+')

    def test_caret_escaped(self):
        assert _glob_to_regex('^') == re.escape('^')

    def test_dollar_escaped(self):
        assert _glob_to_regex('$') == re.escape('$')

    def test_open_brace_escaped(self):
        assert _glob_to_regex('{') == re.escape('{')

    def test_close_brace_escaped(self):
        assert _glob_to_regex('}') == re.escape('}')

    def test_pipe_escaped(self):
        assert _glob_to_regex('|') == re.escape('|')

    def test_open_paren_escaped(self):
        assert _glob_to_regex('(') == re.escape('(')

    def test_close_paren_escaped(self):
        assert _glob_to_regex(')') == re.escape(')')

    def test_open_bracket_escaped(self):
        assert _glob_to_regex('[') == re.escape('[')

    def test_close_bracket_escaped(self):
        assert _glob_to_regex(']') == re.escape(']')

    def test_mixed_pattern(self):
        # Combines glob wildcards + special chars together
        result = _glob_to_regex('[*]')
        assert result == re.escape('[') + '.*' + re.escape(']')


class TestMatchInstruction:
    """Cover match_instruction including mnemonic/operand mismatch branches."""

    def test_mnemonic_wildcard_no_operands(self):
        assert match_instruction('*', None, 'MOV', []) is True

    def test_mnemonic_match_no_operands(self):
        assert match_instruction('MOV', None, 'MOV', []) is True

    def test_mnemonic_mismatch_returns_false(self):
        assert match_instruction('ADD', None, 'MOV', []) is False

    def test_mnemonic_glob_match(self):
        assert match_instruction('MO*', None, 'MOV', []) is True

    def test_mnemonic_case_insensitive(self):
        assert match_instruction('mov', None, 'MOV', []) is True

    def test_operand_wildcard_skipped(self):
        # '*' operand pattern must not check actual operand
        assert match_instruction('MOV', ['*', '*'], 'MOV', ['RAX', 'RBX']) is True

    def test_operand_match_succeeds(self):
        assert match_instruction('MOV', ['RAX'], 'MOV', ['RAX']) is True

    def test_operand_value_mismatch_returns_false(self):
        assert match_instruction('MOV', ['RAX'], 'MOV', ['RBX']) is False

    # Branch: i >= len(actual_operands) — pattern demands more operands than present
    def test_operand_count_exceeds_actual_returns_false(self):
        # Pattern has 2 non-wildcard operands; instruction has only 1
        assert match_instruction('MOV', ['RAX', 'RBX'], 'MOV', ['RAX']) is False

    def test_operand_count_exceeds_actual_all_wildcards_ok(self):
        # When extra pattern slot is '*', the continue skips before the index check
        assert match_instruction('MOV', ['RAX', '*'], 'MOV', ['RAX']) is True

    def test_no_operand_patterns_ignores_actual_operands(self):
        assert match_instruction('MOV', None, 'MOV', ['RAX', 'RBX']) is True

    def test_empty_operand_patterns_list_ignores_actual(self):
        # Empty list is falsy — operand check skipped entirely
        assert match_instruction('MOV', [], 'MOV', ['RAX', 'RBX']) is True

    def test_operand_regex_match(self):
        assert match_instruction('MOV', ['/r.x/'], 'MOV', ['RAX']) is True

    def test_operand_regex_no_match_returns_false(self):
        assert match_instruction('MOV', ['/r.x/'], 'MOV', ['RBP']) is False


class TestParseBytePatternAdditional:
    """Cover the out-of-range byte value branch (line 32)."""

    def test_out_of_range_raises(self):
        # int('100', 16) == 256 which is > 0xFF; the out-of-range ValueError is
        # caught by the except clause and re-raised as "Invalid byte token"
        with pytest.raises(ValueError, match='Invalid byte token'):
            parse_byte_pattern('100')

    def test_single_wildcard_char(self):
        # '?' is also accepted as wildcard (not just '??')
        data, mask = parse_byte_pattern('?')
        assert data == bytes([0x00])
        assert mask == bytes([0x00])
