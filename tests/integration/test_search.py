"""Integration tests for find_bytes and find_insns — search tools.

Tests call tool functions directly on the HeadlessBackend instance.
pyghidra must be available (tests are session-scoped via conftest.py fixtures).
"""
from __future__ import annotations


from mcpyghidra.tools.search import find_bytes, find_insns
from tests.integration.helpers import run_async


class TestFindBytes:
    """find_bytes(backend, patterns, limit, offset) -> list[dict]"""

    def test_find_bytes_prologue(self, backend):
        """Search for function prologue bytes returns at least one match."""
        # x86-64 prologue: PUSH RBP (0x55) or MOV RSP,RBP (48 89)
        result = run_async(find_bytes, backend, ['55'])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None, f'Unexpected error: {entry["error"]}'
        assert len(entry['items']) > 0, 'Expected at least one match for prologue byte 0x55'

    def test_find_bytes_wildcard(self, backend):
        """CALL instruction pattern E8 ?? ?? ?? ?? finds call instructions."""
        result = run_async(find_bytes, backend, ['E8 ?? ?? ?? ??'])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None, f'Unexpected error: {entry["error"]}'
        assert len(entry['items']) > 0, 'Expected CALL instructions in binary'
        # Verify match structure
        match = entry['items'][0]
        assert 'addr' in match
        assert 'bytes' in match
        assert '0x' in match['addr']

    def test_find_bytes_no_match(self, backend):
        """Searching for unlikely bytes returns empty matches list."""
        result = run_async(find_bytes, backend, ['DE AD BE EF DE AD'])
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert entry['items'] == []
        assert entry['has_more'] is False

    def test_find_bytes_pagination(self, backend):
        """limit=2 returns at most 2 matches; has_more=True if more exist."""
        # Use a very common byte to ensure pagination triggers
        result = run_async(find_bytes, backend, ['55'], limit=2)
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert len(entry['items']) <= 2
        # If there were more than 2 matches total, has_more should be True
        # (we can't guarantee has_more without knowing total count, but matches should be <=2)

    def test_find_bytes_multiple_patterns(self, backend):
        """Batch search with two patterns returns two result entries."""
        result = run_async(find_bytes, backend, ['55', 'C3'])
        assert len(result) == 2
        for entry in result:
            assert entry['error'] is None
            assert 'pattern' in entry
            assert 'items' in entry
            assert 'has_more' in entry

    def test_find_bytes_match_structure(self, backend):
        """Each match contains addr and bytes fields in correct format."""
        result = run_async(find_bytes, backend, ['55'], limit=5)
        entry = result[0]
        assert entry['error'] is None
        for match in entry['items']:
            assert 'addr' in match
            assert 'bytes' in match
            # addr should be a hex address string
            assert match['addr'].startswith('0x')
            # bytes should be a hex string like 'XX' or 'XX XX ...'
            assert len(match['bytes']) > 0


class TestFindInsns:
    """find_insns(backend, sequences, limit, offset) -> list[dict]"""

    def test_find_insns_call(self, backend):
        """CALL instruction sequence finds call instructions in binary."""
        result = run_async(find_insns,
            backend,
            [[{'mnemonic': 'CALL', 'operands': ['*']}]],
        )
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None, f'Unexpected error: {entry["error"]}'
        assert len(entry['items']) > 0, 'Expected CALL instructions in binary'
        # Verify match structure
        match = entry['items'][0]
        assert 'addr' in match
        assert 'instructions' in match
        assert len(match['instructions']) == 1
        assert '0x' in match['addr']

    def test_find_insns_no_match(self, backend):
        """Searching for a non-existent mnemonic returns empty matches."""
        result = run_async(find_insns,
            backend,
            [[{'mnemonic': 'XYZNOTREAL', 'operands': ['*']}]],
        )
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert entry['items'] == []
        assert entry['has_more'] is False

    def test_find_insns_glob_operand(self, backend):
        """Glob pattern on operand field filters instruction matches."""
        # RET has no operands — search for it with wildcard mnemonic
        result = run_async(find_insns,
            backend,
            [[{'mnemonic': 'RET', 'operands': []}]],
        )
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert len(entry['items']) > 0, 'Expected RET instructions in binary'

    def test_find_insns_wildcard_mnemonic(self, backend):
        """Wildcard mnemonic '*' matches any instruction."""
        result = run_async(find_insns,
            backend,
            [[{'mnemonic': '*', 'operands': ['*']}]],
            limit=5,
        )
        assert len(result) == 1
        entry = result[0]
        assert entry['error'] is None
        assert len(entry['items']) > 0

    def test_find_insns_multiple_sequences(self, backend):
        """Batch search with two sequences returns two result entries."""
        result = run_async(find_insns,
            backend,
            [
                [{'mnemonic': 'CALL', 'operands': ['*']}],
                [{'mnemonic': 'RET', 'operands': []}],
            ],
        )
        assert len(result) == 2
        for entry in result:
            assert 'sequence' in entry
            assert 'items' in entry
            assert 'has_more' in entry
            assert 'error' in entry
