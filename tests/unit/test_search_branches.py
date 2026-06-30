"""Unit tests for defensive / error branches in tools/search.py.

These tests run without Ghidra/pyghidra by mocking GhidraBackend and all
Java-type dependencies.  Each test targets exactly ONE branch.

Coverage goal: tools/search.py from 10% line / ~0% branch → 70%+ line / ~95% branch.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import anyio
import pytest

# ---------------------------------------------------------------------------
# Ghidra stub setup — must happen before any mcpyghidra.tools.search import
# ---------------------------------------------------------------------------

_GHIDRA_STUBS = [
    'ghidra',
    'ghidra.program',
    'ghidra.program.model',
    'ghidra.program.model.address',
    'ghidra.util',
    'ghidra.util.task',
    'jpype',
]

for _mod in _GHIDRA_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# AddressSet must be a real callable that can be instantiated
_mock_address_set_cls = MagicMock()
_mock_address_set_instance = MagicMock()
_mock_address_set_cls.return_value = _mock_address_set_instance
sys.modules['ghidra.program.model.address'].AddressSet = _mock_address_set_cls

# TaskMonitor.DUMMY must exist as a sentinel
_mock_task_monitor = MagicMock()
_mock_task_monitor.DUMMY = object()
sys.modules['ghidra.util.task'].TaskMonitor = _mock_task_monitor

# jpype.JArray and jpype.JByte must be callable
_mock_jpype = sys.modules['jpype']
_mock_jpype.JByte = MagicMock()
_mock_jpype.JArray = MagicMock(return_value=MagicMock(return_value=b''))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_backend() -> MagicMock:
    """Minimal mock GhidraBackend sufficient for search tool helpers."""
    backend = MagicMock()
    backend.program = MagicMock()
    return backend


def _run_async(async_fn, *args, **kwargs):
    """Run an async function synchronously for unit tests."""

    async def wrapper():
        return await async_fn(*args, **kwargs)

    return anyio.run(wrapper)


# ---------------------------------------------------------------------------
# parse_byte_pattern — validation branches
# (These live in search_utils but are exercised via _find_bytes_sync)
# ---------------------------------------------------------------------------


class TestParseBytePatternValidation:
    """parse_byte_pattern raises ValueError for bad inputs."""

    def test_empty_pattern_raises(self):
        """Empty string → ValueError('Empty byte pattern')."""
        from mcpyghidra.tools.search_utils import parse_byte_pattern

        with pytest.raises(ValueError, match='Empty byte pattern'):
            parse_byte_pattern('')

    def test_whitespace_only_raises(self):
        """All-whitespace string → same empty-pattern path."""
        from mcpyghidra.tools.search_utils import parse_byte_pattern

        with pytest.raises(ValueError, match='Empty byte pattern'):
            parse_byte_pattern('   ')

    def test_invalid_hex_token_raises(self):
        """Non-hex token 'ZZ' → ValueError('Invalid byte token')."""
        from mcpyghidra.tools.search_utils import parse_byte_pattern

        with pytest.raises(ValueError, match='Invalid byte token'):
            parse_byte_pattern('48 ZZ 05')

    def test_out_of_range_byte_raises(self):
        """Token '100' (256) is out of [0, 255] → ValueError."""
        from mcpyghidra.tools.search_utils import parse_byte_pattern

        with pytest.raises(ValueError, match='out of range|Invalid byte token'):
            parse_byte_pattern('100')


# ---------------------------------------------------------------------------
# _find_bytes_sync — has_more truncation (lines 50–52)
# ---------------------------------------------------------------------------


class TestFindBytesSyncHasMore:
    """_find_bytes_sync truncates results when more than limit matches are returned."""

    def test_has_more_truncates_results(self):
        """When _search_bytes_ghidra returns limit+1 items, has_more=True and list is truncated."""
        from mcpyghidra.tools.search import _find_bytes_sync

        backend = _make_backend()

        # Patch _search_bytes_ghidra to return limit+1 fake matches
        fake_matches = [{'addr': f'0x{i:04x}', 'bytes': '90'} for i in range(6)]  # 6 > limit=5

        with patch('mcpyghidra.tools.search._search_bytes_ghidra', return_value=fake_matches):
            results = _find_bytes_sync(backend, ['90'], limit=5, offset=0)

        assert len(results) == 1
        result = results[0]
        assert result['has_more'] is True
        assert len(result['items']) == 5  # truncated to limit

    def test_has_more_false_when_at_limit(self):
        """Exactly limit matches → has_more=False, no truncation."""
        from mcpyghidra.tools.search import _find_bytes_sync

        backend = _make_backend()
        fake_matches = [{'addr': f'0x{i:04x}', 'bytes': '90'} for i in range(5)]  # exactly limit=5

        with patch('mcpyghidra.tools.search._search_bytes_ghidra', return_value=fake_matches):
            results = _find_bytes_sync(backend, ['90'], limit=5, offset=0)

        assert results[0]['has_more'] is False
        assert len(results[0]['items']) == 5

    def test_parse_error_captured_in_error_field(self):
        """parse_byte_pattern raising → error field is populated, matches is []."""
        from mcpyghidra.tools.search import _find_bytes_sync

        backend = _make_backend()
        results = _find_bytes_sync(backend, ['INVALID TOKEN'], limit=10, offset=0)

        assert len(results) == 1
        assert results[0]['error'] is not None
        assert results[0]['items'] == []
        assert results[0]['has_more'] is False


# ---------------------------------------------------------------------------
# _search_bytes_ghidra — addr.add(1) exception (lines 119–122)
# ---------------------------------------------------------------------------


class TestSearchBytesGhidraAddrAddException:
    """_search_bytes_ghidra breaks out of loop when addr.add(1) raises."""

    def test_addr_add_exception_breaks_loop(self):
        """addr.add(1) raising an exception → loop exits (break), returns partial matches."""
        from mcpyghidra.tools.search import _search_bytes_ghidra

        backend = _make_backend()
        program = backend.program
        memory = program.getMemory.return_value

        # addr.add raises on first call (simulating past-end-of-address-space)
        mock_addr = MagicMock()
        mock_addr.add.side_effect = Exception('past end of address space')
        mock_addr.getOffset.return_value = 0x1000

        program.getMinAddress.return_value = mock_addr
        program.getMaxAddress.return_value = MagicMock()

        # memory.findBytes returns mock_addr once, then None
        memory.findBytes.side_effect = [mock_addr, None]

        # _read_bytes_at won't fail
        memory.getBytes.return_value = None

        with patch('mcpyghidra.tools.search._read_bytes_at', return_value='90'):
            with patch.dict(sys.modules, {'jpype': _mock_jpype}):
                results = _search_bytes_ghidra(
                    backend, data=b'\x90', mask=b'\xff', max_results=10, skip=0
                )

        # One match recorded before the addr.add raised
        assert len(results) == 1
        assert results[0]['addr'] == '0x1000'

    def test_skip_logic_works_before_addr_add_exception(self):
        """When skip=1, first match is skipped; addr.add raises after skip → 0 matches returned."""
        from mcpyghidra.tools.search import _search_bytes_ghidra

        backend = _make_backend()
        program = backend.program
        memory = program.getMemory.return_value

        mock_addr = MagicMock()
        mock_addr.add.side_effect = Exception('past end')
        mock_addr.getOffset.return_value = 0x2000

        program.getMinAddress.return_value = mock_addr
        program.getMaxAddress.return_value = MagicMock()
        memory.findBytes.return_value = mock_addr

        with patch('mcpyghidra.tools.search._read_bytes_at', return_value='90'):
            with patch.dict(sys.modules, {'jpype': _mock_jpype}):
                results = _search_bytes_ghidra(
                    backend, data=b'\x90', mask=b'\xff', max_results=10, skip=1
                )

        # First hit was skipped, then addr.add raises → 0 recorded
        assert results == []


# ---------------------------------------------------------------------------
# _read_bytes_at — exception fallback (lines 133–134)
# ---------------------------------------------------------------------------


class TestReadBytesAt:
    """_read_bytes_at returns '' when memory.getBytes() raises."""

    def test_get_bytes_exception_returns_empty_string(self):
        """memory.getBytes() raising → returns empty string ''."""
        from mcpyghidra.tools.search import _read_bytes_at

        memory = MagicMock()
        memory.getBytes.side_effect = Exception('memory read error')
        addr = MagicMock()

        result = _read_bytes_at(memory, addr, 4)
        assert result == ''

    def test_successful_read_returns_hex_string(self):
        """memory.getBytes() succeeds → returns space-separated uppercase hex."""
        from mcpyghidra.tools.search import _read_bytes_at

        memory = MagicMock()
        addr = MagicMock()

        # memory.getBytes writes into the bytearray in-place via side_effect
        def fill_buf(a, buf):
            buf[0] = 0x48
            buf[1] = 0x8B

        memory.getBytes.side_effect = fill_buf

        result = _read_bytes_at(memory, addr, 2)
        assert result == '48 8B'


# ---------------------------------------------------------------------------
# _get_executable_addresses — no executable blocks (lines 259–267)
# ---------------------------------------------------------------------------


class TestGetExecutableAddresses:
    """_get_executable_addresses returns an AddressSet; empty when no blocks are executable."""

    def test_no_executable_blocks_returns_empty_set(self):
        """All blocks have isExecute()=False → AddressSet.add() never called."""
        from mcpyghidra.tools.search import _get_executable_addresses

        program = MagicMock()
        mock_block = MagicMock()
        mock_block.isExecute.return_value = False
        program.getMemory.return_value.getBlocks.return_value = [mock_block]

        _get_executable_addresses(program)

        # addr_set.add() should NOT have been called (block not executable)
        _mock_address_set_instance.add.assert_not_called()

    def test_executable_block_adds_address_range(self):
        """isExecute()=True → addr_set.add(block.getAddressRange()) called once."""
        from mcpyghidra.tools.search import _get_executable_addresses

        # Reset mock state
        _mock_address_set_instance.reset_mock()

        program = MagicMock()
        mock_block = MagicMock()
        mock_block.isExecute.return_value = True
        mock_range = MagicMock()
        mock_block.getAddressRange.return_value = mock_range
        program.getMemory.return_value.getBlocks.return_value = [mock_block]

        _get_executable_addresses(program)

        _mock_address_set_instance.add.assert_called_once_with(mock_range)

    def test_mixed_blocks_only_adds_executable(self):
        """Only executable blocks contribute to the address set."""
        from mcpyghidra.tools.search import _get_executable_addresses

        _mock_address_set_instance.reset_mock()

        program = MagicMock()
        non_exec = MagicMock()
        non_exec.isExecute.return_value = False
        exec_block = MagicMock()
        exec_block.isExecute.return_value = True
        exec_range = MagicMock()
        exec_block.getAddressRange.return_value = exec_range

        program.getMemory.return_value.getBlocks.return_value = [non_exec, exec_block]

        _get_executable_addresses(program)

        # add called exactly once (only for exec_block)
        _mock_address_set_instance.add.assert_called_once_with(exec_range)


# ---------------------------------------------------------------------------
# _try_match_sequence — operand mismatch (lines 245–251)
# ---------------------------------------------------------------------------


class TestTryMatchSequence:
    """_try_match_sequence returns None on operand/mnemonic mismatch."""

    def _make_insn(self, mnemonic: str, operands: list[str]) -> MagicMock:
        insn = MagicMock()
        insn.getMnemonicString.return_value = mnemonic
        insn.getNumOperands.return_value = len(operands)
        insn.getDefaultOperandRepresentation.side_effect = lambda i: operands[i]
        return insn

    def test_mnemonic_mismatch_returns_none(self):
        """Instruction mnemonic doesn't match pattern → returns None."""
        from mcpyghidra.tools.search import _try_match_sequence

        insn = self._make_insn('MOV', ['RAX', 'RBX'])
        sequence = [{'mnemonic': 'PUSH', 'operands': None}]

        result = _try_match_sequence(insn, sequence)
        assert result is None

    def test_operand_mismatch_returns_none(self):
        """Mnemonic matches but operand pattern doesn't → returns None."""
        from mcpyghidra.tools.search import _try_match_sequence

        insn = self._make_insn('MOV', ['RAX', 'RBX'])
        # Pattern requires RCX as first operand but actual is RAX
        sequence = [{'mnemonic': 'MOV', 'operands': ['RCX']}]

        result = _try_match_sequence(insn, sequence)
        assert result is None

    def test_current_none_mid_sequence_returns_none(self):
        """getNext() returns None mid-sequence → returns None."""
        from mcpyghidra.tools.search import _try_match_sequence

        insn1 = self._make_insn('PUSH', ['RBP'])
        insn1.getNext.return_value = None  # no second instruction

        sequence = [
            {'mnemonic': 'PUSH', 'operands': None},
            {'mnemonic': 'MOV', 'operands': None},
        ]

        result = _try_match_sequence(insn1, sequence)
        assert result is None

    def test_full_sequence_match_returns_list(self):
        """All instructions match → returns list of matched instructions."""
        from mcpyghidra.tools.search import _try_match_sequence

        insn2 = self._make_insn('MOV', ['RBP', 'RSP'])
        insn2.getNext.return_value = None

        insn1 = self._make_insn('PUSH', ['RBP'])
        insn1.getNext.return_value = insn2

        sequence = [
            {'mnemonic': 'PUSH', 'operands': None},
            {'mnemonic': 'MOV', 'operands': None},
        ]

        result = _try_match_sequence(insn1, sequence)
        assert result is not None
        assert len(result) == 2

    def test_wildcard_mnemonic_matches_any(self):
        """mnemonic='*' matches any instruction mnemonic."""
        from mcpyghidra.tools.search import _try_match_sequence

        insn = self._make_insn('XCHG', ['RAX', 'RBX'])
        sequence = [{'mnemonic': '*', 'operands': None}]

        result = _try_match_sequence(insn, sequence)
        assert result is not None
        assert len(result) == 1

    def test_empty_sequence_returns_empty_list(self):
        """Empty sequence pattern → matched immediately, returns empty list."""
        from mcpyghidra.tools.search import _try_match_sequence

        insn = self._make_insn('NOP', [])
        result = _try_match_sequence(insn, [])
        assert result == []


# ---------------------------------------------------------------------------
# _find_insns_sync — empty sequences / has_more (lines 155–184)
# ---------------------------------------------------------------------------


class TestFindInsnsSyncEdgeCases:
    """_find_insns_sync handles empty sequence list and has_more truncation."""

    def test_empty_sequences_list_returns_empty(self):
        """sequences=[] → results list is empty (no iterations)."""
        from mcpyghidra.tools.search import _find_insns_sync

        backend = _make_backend()
        results = _find_insns_sync(backend, sequences=[], limit=10, offset=0)
        assert results == []

    def test_search_exception_captured_in_error_field(self):
        """_search_insns_ghidra raising → error field populated, matches=[]."""
        from mcpyghidra.tools.search import _find_insns_sync

        backend = _make_backend()
        with patch(
            'mcpyghidra.tools.search._search_insns_ghidra',
            side_effect=RuntimeError('boom'),
        ):
            results = _find_insns_sync(
                backend, sequences=[[{'mnemonic': 'NOP'}]], limit=10, offset=0
            )

        assert len(results) == 1
        assert results[0]['error'] == 'boom'
        assert results[0]['items'] == []
        assert results[0]['has_more'] is False

    def test_has_more_truncation_in_insns(self):
        """More than limit insn matches → has_more=True, list truncated to limit."""
        from mcpyghidra.tools.search import _find_insns_sync

        backend = _make_backend()
        fake_matches = [{'addr': f'0x{i:04x}', 'instructions': []} for i in range(6)]

        with patch(
            'mcpyghidra.tools.search._search_insns_ghidra', return_value=fake_matches
        ):
            results = _find_insns_sync(
                backend, sequences=[[{'mnemonic': 'NOP'}]], limit=5, offset=0
            )

        assert results[0]['has_more'] is True
        assert len(results[0]['items']) == 5

    def test_has_more_false_exactly_at_limit(self):
        """Exactly limit matches → has_more=False."""
        from mcpyghidra.tools.search import _find_insns_sync

        backend = _make_backend()
        fake_matches = [{'addr': f'0x{i:04x}', 'instructions': []} for i in range(5)]

        with patch(
            'mcpyghidra.tools.search._search_insns_ghidra', return_value=fake_matches
        ):
            results = _find_insns_sync(
                backend, sequences=[[{'mnemonic': 'NOP'}]], limit=5, offset=0
            )

        assert results[0]['has_more'] is False
        assert len(results[0]['items']) == 5


# ---------------------------------------------------------------------------
# _search_insns_ghidra — integration of _try_match_sequence via skipping
# ---------------------------------------------------------------------------


class TestSearchInsnsGhidra:
    """_search_insns_ghidra skip logic and match/no-match paths."""

    def _make_insn(self, mnemonic: str, offset: int = 0x1000) -> MagicMock:
        insn = MagicMock()
        insn.getMnemonicString.return_value = mnemonic
        insn.getNumOperands.return_value = 0
        insn.getNext.return_value = None
        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = offset
        insn.getAddress.return_value = mock_addr
        insn.toString.return_value = f'{mnemonic} ; at {offset:#x}'
        return insn

    def test_skip_logic_skips_first_match(self):
        """With skip=1 the first match is counted but not recorded; second is recorded."""
        from mcpyghidra.tools.search import _search_insns_ghidra

        insn_a = self._make_insn('NOP', 0x1000)
        insn_b = self._make_insn('NOP', 0x1001)

        mock_iter = MagicMock()
        mock_iter.hasNext.side_effect = [True, True, False]
        mock_iter.next.side_effect = [insn_a, insn_b]

        backend = _make_backend()
        backend.program.getListing.return_value.getInstructions.return_value = mock_iter

        with patch('mcpyghidra.tools.search._get_executable_addresses', return_value=MagicMock()):
            with patch(
                'mcpyghidra.tools.search._try_match_sequence',
                side_effect=[[insn_a], [insn_b]],
            ):
                results = _search_insns_ghidra(
                    backend, sequence=[{'mnemonic': 'NOP'}], max_results=10, skip=1
                )

        # first match skipped, second recorded
        assert len(results) == 1
        assert results[0]['addr'] == '0x1001'

    def test_no_match_returns_empty(self):
        """_try_match_sequence returning None for all insns → empty results."""
        from mcpyghidra.tools.search import _search_insns_ghidra

        insn = self._make_insn('PUSH', 0x2000)
        mock_iter = MagicMock()
        mock_iter.hasNext.side_effect = [True, False]
        mock_iter.next.return_value = insn

        backend = _make_backend()
        backend.program.getListing.return_value.getInstructions.return_value = mock_iter

        with patch('mcpyghidra.tools.search._get_executable_addresses', return_value=MagicMock()):
            with patch('mcpyghidra.tools.search._try_match_sequence', return_value=None):
                results = _search_insns_ghidra(
                    backend, sequence=[{'mnemonic': 'NOP'}], max_results=10, skip=0
                )

        assert results == []


# ---------------------------------------------------------------------------
# find_bytes / find_insns async wrappers — non-list coercion
# ---------------------------------------------------------------------------


class TestAsyncWrappers:
    """find_bytes and find_insns coerce non-list arguments."""

    def test_find_bytes_string_coerced_to_list(self):
        """Passing a bare string instead of list → coerced to [string]."""
        from mcpyghidra.tools.search import find_bytes

        backend = _make_backend()
        with patch('mcpyghidra.tools.search._find_bytes_sync', return_value=[]) as mock_sync:
            _run_async(find_bytes, backend, '90')  # type: ignore[arg-type]
            # _find_bytes_sync was called with a list
            called_patterns = mock_sync.call_args[0][1]
            assert isinstance(called_patterns, list)
            assert called_patterns == ['90']

    def test_find_insns_non_list_coerced(self):
        """Passing a single sequence dict instead of list → coerced to [sequence]."""
        from mcpyghidra.tools.search import find_insns

        backend = _make_backend()
        single_seq = [{'mnemonic': 'NOP'}]
        with patch('mcpyghidra.tools.search._find_insns_sync', return_value=[]) as mock_sync:
            _run_async(find_insns, backend, single_seq)  # type: ignore[arg-type]
            called_sequences = mock_sync.call_args[0][1]
            assert isinstance(called_sequences, list)
