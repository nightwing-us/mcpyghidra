"""Unit tests for branches in tools/cfg.py not reached by integration tests.

Targets:
1. _resolve_function — address-parse exception, getFunctionAt None,
   getFunctionContaining None, name-iteration exhausted (raises ValueError).
2. _resolve_name — thunked_func is None (returns func.getName() directly).
3. cfg_sync — normalize=False, include_bytes=True, include_disassembly=True,
   instruction flow-type isCall/isNotCall, string reference with None value,
   call target func is None (falls back to _addr_to_hex), include_bytes when
   insn.getBytes() is None, bytes/disasm merge branches in normalize_ghidra_cfg.
4. normalize_ghidra_cfg — bytes-only merge (successor has bytes but block has
   none), instructions-only merge (successor has instructions but block has none).

All tests run without Ghidra/pyghidra (pure mock).
"""
from __future__ import annotations

import base64
import sys
from unittest.mock import MagicMock

import pytest

from mcpyghidra.models import BasicBlock

# ---------------------------------------------------------------------------
# Ghidra stub modules — must be installed before any cfg import
# ---------------------------------------------------------------------------

_GHIDRA_STUBS = [
    'ghidra',
    'ghidra.program',
    'ghidra.program.model',
    'ghidra.program.model.block',
    'ghidra.util',
    'ghidra.util.task',
]
for _mod in _GHIDRA_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# Provide concrete sentinel objects for the two names cfg_sync imports.
_mock_simple_block_model_cls = MagicMock()
_mock_task_monitor_module = MagicMock()
_mock_task_monitor_module.TaskMonitor.DUMMY = MagicMock()

sys.modules['ghidra.program.model.block'] = MagicMock(
    SimpleBlockModel=_mock_simple_block_model_cls
)
sys.modules['ghidra.util.task'] = _mock_task_monitor_module


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_program(*, addr_raises: bool = False, func_at: object = None,
                  func_containing: object = None) -> MagicMock:
    """Return a minimal mock program suitable for _resolve_function tests."""
    program = MagicMock()
    addr_factory = MagicMock()
    program.getAddressFactory.return_value = addr_factory

    if addr_raises:
        addr_factory.getAddress.side_effect = Exception('bad address')
    else:
        mock_addr = MagicMock()
        addr_factory.getAddress.return_value = mock_addr

    func_mgr = MagicMock()
    func_mgr.getFunctionAt.return_value = func_at
    func_mgr.getFunctionContaining.return_value = func_containing
    program.getFunctionManager.return_value = func_mgr
    return program


def _make_iter(*items) -> MagicMock:
    """Build a Java-style hasNext/next iterator mock from *items*."""
    it = MagicMock()
    side_effects_has = [True] * len(items) + [False]
    side_effects_next = list(items)
    it.hasNext.side_effect = side_effects_has
    it.next.side_effect = side_effects_next
    return it


def _make_func(name: str = 'test_func', entry_offset: int = 0x1000) -> MagicMock:
    """Return a minimal mock Ghidra function."""
    func = MagicMock()
    func.getName.return_value = name
    mock_ep = MagicMock()
    mock_ep.getOffset.return_value = entry_offset
    func.getEntryPoint.return_value = mock_ep
    return func


# ---------------------------------------------------------------------------
# _addr_to_hex
# ---------------------------------------------------------------------------


class TestAddrToHex:
    """Pure helper — single branch but not covered by integration."""

    def test_converts_offset_to_hex(self):
        from mcpyghidra.tools.cfg import _addr_to_hex

        mock_addr = MagicMock()
        mock_addr.getOffset.return_value = 0x1234
        assert _addr_to_hex(mock_addr) == '0x1234'


# ---------------------------------------------------------------------------
# _resolve_name — thunk chain
# ---------------------------------------------------------------------------


class TestResolveName:
    """_resolve_name resolves through the thunk chain when present."""

    def test_thunked_func_is_none_returns_direct_name(self):
        """getThunkedFunction(True) returns None → func.getName() is used."""
        from mcpyghidra.tools.cfg import _resolve_name

        func = MagicMock()
        func.getThunkedFunction.return_value = None
        func.getName.return_value = 'real_func'

        assert _resolve_name(func) == 'real_func'

    def test_thunked_func_present_returns_thunk_name(self):
        """getThunkedFunction(True) returns a thunk → thunk.getName() used."""
        from mcpyghidra.tools.cfg import _resolve_name

        thunked = MagicMock()
        thunked.getName.return_value = 'thunk_target'

        func = MagicMock()
        func.getThunkedFunction.return_value = thunked

        assert _resolve_name(func) == 'thunk_target'


# ---------------------------------------------------------------------------
# _resolve_function — all error / fallback branches
# ---------------------------------------------------------------------------


class TestResolveFunctionBranches:
    """Each branch of _resolve_function's two-stage lookup."""

    def test_address_lookup_succeeds_via_get_function_at(self):
        """getFunctionAt(addr) returns non-None → function returned immediately."""
        from mcpyghidra.tools.cfg import _resolve_function

        mock_func = _make_func()
        program = _make_program(func_at=mock_func)

        result = _resolve_function(program, '0x1000')
        assert result is mock_func

    def test_get_function_at_none_falls_through_to_containing(self):
        """getFunctionAt returns None, getFunctionContaining returns a function."""
        from mcpyghidra.tools.cfg import _resolve_function

        mock_func = _make_func()
        program = _make_program(func_at=None, func_containing=mock_func)

        result = _resolve_function(program, '0x1000')
        assert result is mock_func

    def test_address_parse_exception_falls_through_to_name_search(self):
        """getAddress raises → try-except swallowed → name iteration used."""
        from mcpyghidra.tools.cfg import _resolve_function

        mock_func = _make_func(name='target_func')
        program = _make_program(addr_raises=True)

        # Provide name iterator that yields matching func.
        func_iter = _make_iter(mock_func)
        program.getFunctionManager.return_value.getFunctions.return_value = func_iter

        result = _resolve_function(program, 'target_func')
        assert result is mock_func

    def test_both_address_lookups_none_falls_to_name_search(self):
        """getFunctionAt=None AND getFunctionContaining=None → name iteration."""
        from mcpyghidra.tools.cfg import _resolve_function

        mock_func = _make_func(name='by_name_func')
        program = _make_program(func_at=None, func_containing=None)

        func_iter = _make_iter(mock_func)
        program.getFunctionManager.return_value.getFunctions.return_value = func_iter

        result = _resolve_function(program, 'by_name_func')
        assert result is mock_func

    def test_name_not_matching_skips_and_raises(self):
        """Name iteration finds no match → ValueError raised."""
        from mcpyghidra.tools.cfg import _resolve_function

        wrong_func = _make_func(name='other_func')
        program = _make_program(addr_raises=True)

        func_iter = _make_iter(wrong_func)
        program.getFunctionManager.return_value.getFunctions.return_value = func_iter

        with pytest.raises(ValueError, match='Function not found'):
            _resolve_function(program, 'missing_func')

    def test_empty_name_iteration_raises(self):
        """No functions in iterator → ValueError raised."""
        from mcpyghidra.tools.cfg import _resolve_function

        program = _make_program(addr_raises=True)
        func_iter = _make_iter()  # empty iterator
        program.getFunctionManager.return_value.getFunctions.return_value = func_iter

        with pytest.raises(ValueError, match='Function not found'):
            _resolve_function(program, 'ghost')

    def test_getaddress_returns_none_falls_through_to_name_search(self):
        """getAddress() returns None → addr is None branch → skip to name search."""
        from mcpyghidra.tools.cfg import _resolve_function

        program = MagicMock()
        # getAddress returns None explicitly.
        program.getAddressFactory.return_value.getAddress.return_value = None

        mock_func = _make_func(name='named_func')
        func_iter = _make_iter(mock_func)
        program.getFunctionManager.return_value.getFunctions.return_value = func_iter

        result = _resolve_function(program, 'named_func')
        assert result is mock_func


# ---------------------------------------------------------------------------
# normalize_ghidra_cfg — bytes/instructions merge sub-branches
# ---------------------------------------------------------------------------


def _block(
    address: str,
    size: int,
    successors: list[str] | None = None,
    instruction_count: int = 1,
    called_funcs: dict[str, str] | None = None,
    strings: list[str] | None = None,
    raw_bytes: bytes | None = None,
    instructions: list[dict[str, str]] | None = None,
) -> BasicBlock:
    b = BasicBlock(
        address=address,
        size=size,
        successors=successors or [],
        instruction_count=instruction_count,
        called_funcs=called_funcs or {},
        strings=strings or [],
    )
    if raw_bytes is not None:
        b = b.model_copy(update={'bytes': base64.b64encode(raw_bytes).decode()})
    if instructions is not None:
        b = b.model_copy(update={'instructions': instructions})
    return b


class TestNormalizeGhidraCFGBytesBranches:
    """Cover the bytes/instructions merge sub-branches inside normalize_ghidra_cfg."""

    def test_both_blocks_have_bytes_merged(self):
        """When both blocks carry bytes, merged block bytes = concat of both."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        a_bytes = b'\x90\x90'  # 2 NOPs
        b_bytes = b'\xcc\xcc'  # 2 INTs
        blocks = {
            '0x1000': _block('0x1000', size=2, successors=['0x1002'],
                              instruction_count=2, raw_bytes=a_bytes),
            '0x1002': _block('0x1002', size=2, successors=[],
                              instruction_count=2, raw_bytes=b_bytes),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x1004)
        assert len(result) == 1
        merged = result['0x1000']
        decoded = base64.b64decode(merged.bytes)
        assert decoded == a_bytes + b_bytes

    def test_only_successor_has_bytes_inherited(self):
        """Block has no bytes, successor has bytes → merged block inherits bytes."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        succ_bytes = b'\xde\xad\xbe\xef'
        blocks = {
            '0x1000': _block('0x1000', size=4, successors=['0x1004'],
                              instruction_count=2),  # no bytes
            '0x1004': _block('0x1004', size=4, successors=[],
                              instruction_count=2, raw_bytes=succ_bytes),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x1008)
        assert len(result) == 1
        merged = result['0x1000']
        assert merged.bytes is not None
        assert base64.b64decode(merged.bytes) == succ_bytes

    def test_both_blocks_have_instructions_merged(self):
        """When both blocks carry instructions, merged list = concat."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        insns_a = [{'address': '0x1000', 'mnemonic': 'nop', 'operands': ''}]
        insns_b = [{'address': '0x1002', 'mnemonic': 'ret', 'operands': ''}]
        blocks = {
            '0x1000': _block('0x1000', size=2, successors=['0x1002'],
                              instruction_count=1, instructions=insns_a),
            '0x1002': _block('0x1002', size=2, successors=[],
                              instruction_count=1, instructions=insns_b),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x1004)
        assert len(result) == 1
        merged = result['0x1000']
        assert merged.instructions == insns_a + insns_b

    def test_only_successor_has_instructions_inherited(self):
        """Block has no instructions, successor has them → inherited on merge."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        insns_b = [{'address': '0x1004', 'mnemonic': 'hlt', 'operands': ''}]
        blocks = {
            '0x1000': _block('0x1000', size=4, successors=['0x1004'],
                              instruction_count=2),  # no instructions
            '0x1004': _block('0x1004', size=4, successors=[],
                              instruction_count=1, instructions=insns_b),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x1008)
        assert len(result) == 1
        merged = result['0x1000']
        assert merged.instructions == insns_b


# ---------------------------------------------------------------------------
# cfg_sync — flag branches (normalize, include_bytes, include_disassembly)
# ---------------------------------------------------------------------------


def _make_backend_for_cfg(
    *,
    func_name: str = 'test_func',
    entry_offset: int = 0x1000,
    block_min_offset: int = 0x1000,
    block_max_offset: int = 0x1009,
    func_body_min_offset: int = 0x1000,
    func_body_max_offset: int = 0x1009,
    include_call_insn: bool = False,
    include_string_ref: bool = False,
    insn_bytes: bytes | None = None,
    call_target_func: object | None = None,
    string_value: str | None = 'hello',
) -> MagicMock:
    """Build a fully-wired backend mock for cfg_sync exercising given flags."""
    backend = MagicMock()
    program = MagicMock()
    backend.program = program

    # _resolve_function → address lookup succeeds.
    mock_addr = MagicMock()
    program.getAddressFactory.return_value.getAddress.return_value = mock_addr

    mock_func = MagicMock()
    mock_func.getName.return_value = func_name
    mock_ep = MagicMock()
    mock_ep.getOffset.return_value = entry_offset
    mock_func.getEntryPoint.return_value = mock_ep

    func_mgr = MagicMock()
    func_mgr.getFunctionAt.return_value = mock_func
    program.getFunctionManager.return_value = func_mgr

    # Function body address range.
    mock_body = MagicMock()
    mock_func.getBody.return_value = mock_body

    func_min = MagicMock()
    func_min.getOffset.return_value = func_body_min_offset
    mock_body.getMinAddress.return_value = func_min

    func_max = MagicMock()
    func_max.getOffset.return_value = func_body_max_offset
    mock_body.getMaxAddress.return_value = func_max

    # SimpleBlockModel: one code block returned.
    mock_block = MagicMock()

    blk_min = MagicMock()
    blk_min.getOffset.return_value = block_min_offset
    mock_block.getMinAddress.return_value = blk_min

    blk_max = MagicMock()
    blk_max.getOffset.return_value = block_max_offset
    mock_block.getMaxAddress.return_value = blk_max

    # No successors for this block by default.
    mock_block.getDestinations.return_value = _make_iter()

    block_model_inst = MagicMock()
    block_model_inst.getCodeBlocksContaining.return_value = _make_iter(mock_block)
    _mock_simple_block_model_cls.return_value = block_model_inst

    # Instruction setup.
    mock_insn = MagicMock()
    mock_insn.getNumOperands.return_value = 0

    flow_type = MagicMock()
    flow_type.isCall.return_value = include_call_insn
    mock_insn.getFlowType.return_value = flow_type

    if include_call_insn:
        # Build a call reference pointing to call_target_func (or raw address).
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = True
        target_addr = MagicMock()
        target_addr.getOffset.return_value = 0x2000
        mock_ref.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [mock_ref]
        func_mgr.getFunctionAt.side_effect = [mock_func, call_target_func]
    else:
        mock_insn.getReferencesFrom.return_value = []

    if include_string_ref:
        mock_insn.getNumOperands.return_value = 1
        mock_op_ref = MagicMock()
        mock_op_ref.getReferenceType.return_value.isCall.return_value = False
        str_addr = MagicMock()
        mock_op_ref.getToAddress.return_value = str_addr

        mock_data = MagicMock()
        mock_data.hasStringValue.return_value = True
        mock_data.getValue.return_value = string_value

        listing = MagicMock()
        program.getListing.return_value = listing
        listing.getDefinedDataAt.return_value = mock_data
        listing.getInstructions.return_value = _make_iter(mock_insn)
        mock_insn.getOperandReferences.return_value = [mock_op_ref]
    else:
        listing = MagicMock()
        program.getListing.return_value = listing
        listing.getInstructions.return_value = _make_iter(mock_insn)
        mock_insn.getOperandReferences.return_value = []

    if insn_bytes is not None:
        # Return Java-style signed bytes (simulate & 0xFF in the source).
        mock_insn.getBytes.return_value = list(insn_bytes)
    else:
        mock_insn.getBytes.return_value = None

    mock_insn_addr = MagicMock()
    mock_insn_addr.getOffset.return_value = block_min_offset
    mock_insn.getAddress.return_value = mock_insn_addr
    mock_insn.getMnemonicString.return_value = 'nop'
    mock_insn.getDefaultOperandRepresentation.return_value = ''

    return backend


class TestCfgSyncFlagBranches:
    """cfg_sync flag branches — normalize, include_bytes, include_disassembly."""

    def test_normalize_false_skips_normalization(self):
        """normalize=False → normalize_ghidra_cfg is NOT called; raw blocks returned."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg()
        result = cfg_sync(backend, '0x1000', normalize=False)
        # One block — no merging attempted.
        assert result.block_count == 1
        assert result.entry == '0x1000'

    def test_normalize_true_calls_normalization(self):
        """normalize=True → normalize_ghidra_cfg called; result is still valid."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg()
        result = cfg_sync(backend, '0x1000', normalize=True)
        assert result.block_count >= 1

    def test_include_bytes_true_attaches_bytes(self):
        """include_bytes=True and insn.getBytes() returns data → block.bytes set."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg(insn_bytes=b'\x90')
        result = cfg_sync(backend, '0x1000', normalize=False, include_bytes=True)
        block = next(iter(result.blocks.values()))
        assert block.bytes is not None
        assert base64.b64decode(block.bytes) == b'\x90'

    def test_include_bytes_none_from_insn_stays_empty(self):
        """include_bytes=True but insn.getBytes() returns None → block.bytes is None."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg(insn_bytes=None)
        result = cfg_sync(backend, '0x1000', normalize=False, include_bytes=True)
        block = next(iter(result.blocks.values()))
        # getBytes() returned None → raw_bytes stayed empty → b64encode(b'') is ''
        # The block.bytes field is only set when include_bytes is True; bytes=''.
        assert block.bytes == base64.b64encode(b'').decode()

    def test_include_disassembly_true_attaches_instructions(self):
        """include_disassembly=True → block.instructions list populated."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg()
        result = cfg_sync(backend, '0x1000', normalize=False, include_disassembly=True)
        block = next(iter(result.blocks.values()))
        assert block.instructions is not None
        assert len(block.instructions) == 1
        assert block.instructions[0]['mnemonic'] == 'nop'

    def test_include_disassembly_false_leaves_instructions_none(self):
        """include_disassembly=False → block.instructions is None."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg()
        result = cfg_sync(backend, '0x1000', normalize=False, include_disassembly=False)
        block = next(iter(result.blocks.values()))
        assert block.instructions is None


# ---------------------------------------------------------------------------
# cfg_sync — call-instruction and string-reference branches
# ---------------------------------------------------------------------------


class TestCfgSyncInstructionBranches:
    """Cover isCall branches and string-reference scanning in cfg_sync."""

    def test_call_with_known_target_func_uses_resolve_name(self):
        """isCall=True and getFunctionAt returns a function → _resolve_name used."""
        from mcpyghidra.tools.cfg import cfg_sync

        target_func = MagicMock()
        target_func.getThunkedFunction.return_value = None
        target_func.getName.return_value = 'callee'

        backend = _make_backend_for_cfg(
            include_call_insn=True,
            call_target_func=target_func,
        )
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert 'callee' in block.called_funcs.values()

    def test_call_with_unknown_target_uses_addr_hex(self):
        """isCall=True but getFunctionAt returns None → _addr_to_hex used as name."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg(
            include_call_insn=True,
            call_target_func=None,
        )
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        # When func is None the name == the hex address of the call target.
        assert '0x2000' in block.called_funcs

    def test_string_reference_with_valid_value_collected(self):
        """String reference with non-None value → strings list populated."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg(
            include_string_ref=True,
            string_value='secret',
        )
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert 'secret' in block.strings

    def test_string_reference_with_none_value_skipped(self):
        """String reference where getValue() returns None → not appended."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg(
            include_string_ref=True,
            string_value=None,
        )
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert block.strings == []

    def test_non_call_instruction_skips_reference_scan(self):
        """flow_type.isCall()=False → getReferencesFrom not called for calls."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = _make_backend_for_cfg(include_call_insn=False)
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert block.called_funcs == {}

    def test_out_of_function_successor_filtered_in_normalize(self):
        """Successor outside function range is removed during normalization."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        # Block at 0x1000 has a successor outside [0x1000, 0x1010)
        blocks = {
            '0x1000': BasicBlock(
                address='0x1000',
                size=10,
                successors=['0xdead'],
                instruction_count=1,
            ),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x1010)
        assert result['0x1000'].successors == []

    def test_in_function_successor_not_in_blocks_kept_if_in_range(self):
        """Forward successor in address range but not yet in blocks dict is kept."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        # Successor 0x1008 is in [0x1000, 0x1010) but NOT a key in blocks.
        blocks = {
            '0x1000': BasicBlock(
                address='0x1000',
                size=8,
                successors=['0x1008'],
                instruction_count=1,
            ),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x1010)
        assert '0x1008' in result['0x1000'].successors


# ---------------------------------------------------------------------------
# cfg_sync — successor collection (destination iterator) and data None branch
# ---------------------------------------------------------------------------


class TestCfgSyncSuccessorAndDataBranches:
    """Cover the destination-iterator and data-is-None sub-branches in cfg_sync."""

    def _make_backend_with_successor(self) -> MagicMock:
        """Backend whose code block has one destination."""
        backend = MagicMock()
        program = MagicMock()
        backend.program = program

        mock_addr = MagicMock()
        program.getAddressFactory.return_value.getAddress.return_value = mock_addr

        mock_func = _make_func()
        func_mgr = MagicMock()
        func_mgr.getFunctionAt.return_value = mock_func
        program.getFunctionManager.return_value = func_mgr

        mock_body = MagicMock()
        mock_func.getBody.return_value = mock_body

        func_min = MagicMock()
        func_min.getOffset.return_value = 0x1000
        mock_body.getMinAddress.return_value = func_min
        func_max = MagicMock()
        func_max.getOffset.return_value = 0x100f
        mock_body.getMaxAddress.return_value = func_max

        mock_block = MagicMock()
        blk_min = MagicMock()
        blk_min.getOffset.return_value = 0x1000
        mock_block.getMinAddress.return_value = blk_min
        blk_max = MagicMock()
        blk_max.getOffset.return_value = 0x100f
        mock_block.getMaxAddress.return_value = blk_max

        # One destination with known address.
        dest = MagicMock()
        dest_addr = MagicMock()
        dest_addr.getOffset.return_value = 0x2000
        dest.getDestinationAddress.return_value = dest_addr
        mock_block.getDestinations.return_value = _make_iter(dest)

        block_model_inst = MagicMock()
        block_model_inst.getCodeBlocksContaining.return_value = _make_iter(mock_block)
        _mock_simple_block_model_cls.return_value = block_model_inst

        listing = MagicMock()
        program.getListing.return_value = listing
        listing.getInstructions.return_value = _make_iter()  # no instructions

        return backend

    def test_destination_iter_yields_successor_hex(self):
        """Destination iterator with one entry → successors list contains its hex."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = self._make_backend_with_successor()
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert '0x2000' in block.successors

    def _make_backend_data_none(self) -> MagicMock:
        """Backend where data at a string-ref address is None (getDefinedDataAt returns None)."""
        backend = MagicMock()
        program = MagicMock()
        backend.program = program

        mock_addr = MagicMock()
        program.getAddressFactory.return_value.getAddress.return_value = mock_addr

        mock_func = _make_func()
        func_mgr = MagicMock()
        func_mgr.getFunctionAt.return_value = mock_func
        program.getFunctionManager.return_value = func_mgr

        mock_body = MagicMock()
        mock_func.getBody.return_value = mock_body

        func_min = MagicMock()
        func_min.getOffset.return_value = 0x1000
        mock_body.getMinAddress.return_value = func_min
        func_max = MagicMock()
        func_max.getOffset.return_value = 0x100f
        mock_body.getMaxAddress.return_value = func_max

        mock_block = MagicMock()
        blk_min = MagicMock()
        blk_min.getOffset.return_value = 0x1000
        mock_block.getMinAddress.return_value = blk_min
        blk_max = MagicMock()
        blk_max.getOffset.return_value = 0x100f
        mock_block.getMaxAddress.return_value = blk_max
        mock_block.getDestinations.return_value = _make_iter()

        block_model_inst = MagicMock()
        block_model_inst.getCodeBlocksContaining.return_value = _make_iter(mock_block)
        _mock_simple_block_model_cls.return_value = block_model_inst

        mock_insn = MagicMock()
        flow_type = MagicMock()
        flow_type.isCall.return_value = False
        mock_insn.getFlowType.return_value = flow_type
        mock_insn.getReferencesFrom.return_value = []
        mock_insn.getNumOperands.return_value = 1

        mock_op_ref = MagicMock()
        str_addr = MagicMock()
        mock_op_ref.getToAddress.return_value = str_addr
        mock_insn.getOperandReferences.return_value = [mock_op_ref]

        insn_addr = MagicMock()
        insn_addr.getOffset.return_value = 0x1000
        mock_insn.getAddress.return_value = insn_addr
        mock_insn.getMnemonicString.return_value = 'mov'
        mock_insn.getDefaultOperandRepresentation.return_value = 'eax'
        mock_insn.getBytes.return_value = None

        listing = MagicMock()
        program.getListing.return_value = listing
        listing.getInstructions.return_value = _make_iter(mock_insn)
        # Return None for getDefinedDataAt → the `if data is not None` guard fires.
        listing.getDefinedDataAt.return_value = None

        return backend

    def test_data_none_at_operand_ref_skips_string(self):
        """getDefinedDataAt returns None → no string appended."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = self._make_backend_data_none()
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert block.strings == []

    def _make_backend_has_string_false(self) -> MagicMock:
        """Backend where data.hasStringValue() returns False."""
        backend = self._make_backend_data_none()
        # Override listing to return data with hasStringValue=False.
        mock_data = MagicMock()
        mock_data.hasStringValue.return_value = False
        backend.program.getListing.return_value.getDefinedDataAt.return_value = mock_data
        return backend

    def test_has_string_value_false_skips_string(self):
        """data.hasStringValue()=False → not appended to strings."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = self._make_backend_has_string_false()
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert block.strings == []

    def _make_backend_call_ref_not_call_type(self) -> MagicMock:
        """isCall() insn but ref.getReferenceType().isCall() returns False."""
        backend = MagicMock()
        program = MagicMock()
        backend.program = program

        mock_addr = MagicMock()
        program.getAddressFactory.return_value.getAddress.return_value = mock_addr

        mock_func = _make_func()
        func_mgr = MagicMock()
        func_mgr.getFunctionAt.return_value = mock_func
        program.getFunctionManager.return_value = func_mgr

        mock_body = MagicMock()
        mock_func.getBody.return_value = mock_body
        func_min = MagicMock()
        func_min.getOffset.return_value = 0x1000
        mock_body.getMinAddress.return_value = func_min
        func_max = MagicMock()
        func_max.getOffset.return_value = 0x100f
        mock_body.getMaxAddress.return_value = func_max

        mock_block = MagicMock()
        blk_min = MagicMock()
        blk_min.getOffset.return_value = 0x1000
        mock_block.getMinAddress.return_value = blk_min
        blk_max = MagicMock()
        blk_max.getOffset.return_value = 0x100f
        mock_block.getMaxAddress.return_value = blk_max
        mock_block.getDestinations.return_value = _make_iter()

        block_model_inst = MagicMock()
        block_model_inst.getCodeBlocksContaining.return_value = _make_iter(mock_block)
        _mock_simple_block_model_cls.return_value = block_model_inst

        mock_insn = MagicMock()
        flow_type = MagicMock()
        flow_type.isCall.return_value = True
        mock_insn.getFlowType.return_value = flow_type

        # Ref whose getReferenceType().isCall() = False — should be skipped.
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = False
        mock_insn.getReferencesFrom.return_value = [mock_ref]
        mock_insn.getNumOperands.return_value = 0
        mock_insn.getOperandReferences.return_value = []

        insn_addr = MagicMock()
        insn_addr.getOffset.return_value = 0x1000
        mock_insn.getAddress.return_value = insn_addr
        mock_insn.getMnemonicString.return_value = 'call'
        mock_insn.getDefaultOperandRepresentation.return_value = ''
        mock_insn.getBytes.return_value = None

        listing = MagicMock()
        program.getListing.return_value = listing
        listing.getInstructions.return_value = _make_iter(mock_insn)
        listing.getDefinedDataAt.return_value = None

        return backend

    def test_call_ref_not_call_type_produces_no_called_func(self):
        """isCall=True but ref.getReferenceType().isCall()=False → called_funcs empty."""
        from mcpyghidra.tools.cfg import cfg_sync

        backend = self._make_backend_call_ref_not_call_type()
        result = cfg_sync(backend, '0x1000', normalize=False)
        block = next(iter(result.blocks.values()))
        assert block.called_funcs == {}


# ---------------------------------------------------------------------------
# normalize_ghidra_cfg — empty dict early-return
# ---------------------------------------------------------------------------


class TestNormalizeGhidraCFGEmpty:
    """The very first guard in normalize_ghidra_cfg."""

    def test_empty_blocks_returns_empty_dict(self):
        """Empty input dict → {} returned immediately (line 448 early return)."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        result = normalize_ghidra_cfg({}, function_start=0x1000, function_end=0x2000)
        assert result == {}

    def test_non_contiguous_successor_not_merged(self):
        """Successor address does not immediately follow block end → no merge (line 508)."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        # A ends at 0x100a; B starts at 0x1020 (gap) — non-contiguous, no merge.
        blocks = {
            '0x1000': _block('0x1000', size=10, successors=['0x1020'],
                              instruction_count=2),
            '0x1020': _block('0x1020', size=10, successors=[],
                              instruction_count=2),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x102a)
        assert len(result) == 2

    def test_multi_predecessor_successor_not_merged(self):
        """Successor has >1 predecessor → no merge (line 511)."""
        from mcpyghidra.tools.cfg import normalize_ghidra_cfg

        # A → B (contiguous), C → B: B has 2 predecessors → no merge.
        blocks = {
            '0x1000': _block('0x1000', size=10, successors=['0x100a'],
                              instruction_count=2),
            '0x100a': _block('0x100a', size=10, successors=[],
                              instruction_count=2),
            '0x2000': _block('0x2000', size=10, successors=['0x100a'],
                              instruction_count=2),
        }
        result = normalize_ghidra_cfg(blocks, function_start=0x1000,
                                      function_end=0x200a)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# callgraph_sync — all branches
# ---------------------------------------------------------------------------


def _make_func_with_offset(name: str, entry_offset: int) -> MagicMock:
    """Mock function with a getEntryPoint() whose getOffset() returns entry_offset."""
    func = MagicMock()
    func.getName.return_value = name
    func.getThunkedFunction.return_value = None
    ep = MagicMock()
    ep.getOffset.return_value = entry_offset
    func.getEntryPoint.return_value = ep
    return func


def _make_callgraph_backend(
    root_name: str = 'root',
    root_offset: int = 0x1000,
) -> MagicMock:
    """Return a minimal backend for callgraph_sync.

    No callees or callers by default — tests add them per scenario.
    """
    backend = MagicMock()
    program = MagicMock()
    backend.program = program

    root_func = _make_func_with_offset(root_name, root_offset)

    # _resolve_function → address lookup returns root func.
    program.getAddressFactory.return_value.getAddress.return_value = MagicMock()
    func_mgr = MagicMock()
    func_mgr.getFunctionAt.return_value = root_func
    program.getFunctionManager.return_value = func_mgr

    # getListing — used by _get_callees.
    listing = MagicMock()
    program.getListing.return_value = listing
    listing.getInstructions.return_value = _make_iter()  # no instructions by default

    # getReferenceManager — used by _get_callers.
    ref_mgr = MagicMock()
    ref_mgr.getReferencesTo.return_value = []
    program.getReferenceManager.return_value = ref_mgr

    return backend


class TestCallgraphSyncBranches:
    """Cover all major branches in callgraph_sync."""

    def test_invalid_direction_raises(self):
        """direction not in valid set → ValueError."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()
        with pytest.raises(ValueError, match="Invalid direction"):
            callgraph_sync(backend, '0x1000', direction='sideways')

    def test_callees_direction_no_callees_returns_root_only(self):
        """direction='callees', no callees → result has exactly root node."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()
        result = callgraph_sync(backend, '0x1000', direction='callees')
        assert result.direction == 'callees'
        assert len(result.nodes) == 1
        assert result.nodes[0].addr == '0x1000'
        assert result.nodes[0].depth == 0
        assert result.edges == []

    def test_callers_direction_no_callers_returns_root_only(self):
        """direction='callers', no callers → result has exactly root node."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()
        result = callgraph_sync(backend, '0x1000', direction='callers')
        assert result.direction == 'callers'
        assert len(result.nodes) == 1
        assert not result.truncated

    def test_callees_direction_with_one_callee(self):
        """direction='callees', one callee → edge added from root to callee."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee = _make_func_with_offset('callee', 0x2000)

        # Make _get_callees return callee: need an isCall instruction with a call ref.
        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = True
        target_addr = MagicMock()
        mock_ref.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [mock_ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),  # _resolve_function
            callee,                                   # _get_callees inner lookup
        ]

        # callee body has no instructions.
        callee_body = MagicMock()
        callee.getBody.return_value = callee_body
        backend.program.getListing.return_value.getInstructions.side_effect = [
            _make_iter(mock_insn),  # root body
            _make_iter(),           # callee body (no calls)
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=1)
        # root + callee
        assert len(result.nodes) == 2
        assert len(result.edges) == 1
        edge = result.edges[0]
        assert edge.from_addr == '0x1000'
        assert edge.to_addr == '0x2000'

    def test_callers_direction_with_one_caller(self):
        """direction='callers', one caller → edge added from caller to root."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        caller_func = _make_func_with_offset('caller', 0x500)

        caller_ref = MagicMock()
        caller_ref.getReferenceType.return_value.isCall.return_value = True
        from_addr = MagicMock()
        caller_ref.getFromAddress.return_value = from_addr
        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = [caller_ref]
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = caller_func

        # caller body has no instructions (prevent infinite recursion via _get_callers).
        backend.program.getReferenceManager.return_value.getReferencesTo.side_effect = [
            [caller_ref],  # first call (root's callers)
            [],             # second call (caller's callers — none)
        ]

        result = callgraph_sync(backend, '0x1000', direction='callers', max_depth=1)
        assert len(result.nodes) == 2
        assert len(result.edges) == 1
        edge = result.edges[0]
        # caller→root convention
        assert edge.from_addr == '0x500'
        assert edge.to_addr == '0x1000'

    def test_both_direction_traverses_callees_then_callers(self):
        """direction='both' → visited reset to root only between callees/callers passes."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()
        # No callees, no callers → both passes run but find nothing extra.
        result = callgraph_sync(backend, '0x1000', direction='both')
        assert result.direction == 'both'
        assert len(result.nodes) == 1

    def test_depth_limit_truncates(self):
        """max_depth=0 → any callee at depth 1 triggers depth truncation."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee = _make_func_with_offset('callee', 0x2000)
        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = True
        target_addr = MagicMock()
        mock_ref.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [mock_ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        # First getFunctionAt: _resolve_function; second: callee lookup in _get_callees.
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee,
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=0)
        assert result.truncated is True
        assert result.limit_reason == 'depth'

    def test_node_limit_truncates(self):
        """max_nodes=1 → second node triggers node-limit truncation."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee = _make_func_with_offset('callee', 0x2000)
        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = True
        target_addr = MagicMock()
        mock_ref.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [mock_ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee,
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_nodes=1)
        assert result.truncated is True
        assert result.limit_reason == 'nodes'

    def test_edge_limit_truncates(self):
        """max_edges=0 → first edge attempt triggers edge-limit truncation."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee = _make_func_with_offset('callee', 0x2000)
        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = True
        target_addr = MagicMock()
        mock_ref.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [mock_ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee,
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_edges=0)
        assert result.truncated is True
        assert result.limit_reason == 'edges'

    def test_already_visited_node_not_revisited(self):
        """Visiting an already-seen address returns immediately (visited guard)."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        # Callee that points back to root (cycle).
        root_func = _make_func_with_offset('root', 0x1000)
        callee = _make_func_with_offset('callee', 0x2000)

        def get_insns_for_func(body, forward):
            # root body → one call to callee.
            mock_insn = MagicMock()
            mock_insn.getFlowType.return_value.isCall.return_value = True
            mock_ref = MagicMock()
            mock_ref.getReferenceType.return_value.isCall.return_value = True
            target_addr = MagicMock()
            mock_ref.getToAddress.return_value = target_addr
            mock_insn.getReferencesFrom.return_value = [mock_ref]
            return _make_iter(mock_insn)

        # callee body → one call back to root (same address 0x1000).
        back_insn = MagicMock()
        back_insn.getFlowType.return_value.isCall.return_value = True
        back_ref = MagicMock()
        back_ref.getReferenceType.return_value.isCall.return_value = True
        back_target = MagicMock()
        back_ref.getToAddress.return_value = back_target
        back_insn.getReferencesFrom.return_value = [back_ref]

        call_counts: list[int] = [0]

        def getInstructions(body, forward):
            call_counts[0] += 1
            if call_counts[0] == 1:
                return get_insns_for_func(body, forward)
            return _make_iter(back_insn)

        backend.program.getListing.return_value.getInstructions.side_effect = getInstructions

        # getFunctionAt: 1st _resolve_function→root, 2nd callee lookup, 3rd root (back edge).
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            root_func,
            callee,
            root_func,  # back-edge — root already in visited, will be skipped.
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=5)
        # root + callee only — the cycle back to root is short-circuited.
        assert not result.truncated
        addrs = {n.addr for n in result.nodes}
        assert '0x1000' in addrs
        assert '0x2000' in addrs

    def test_duplicate_edge_not_added_twice(self):
        """Duplicate edge key → edge_set prevents double-insertion."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        # Two separate callee references both pointing to the same callee at 0x2000.
        callee = _make_func_with_offset('callee', 0x2000)

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        target_addr = MagicMock()

        ref1 = MagicMock()
        ref1.getReferenceType.return_value.isCall.return_value = True
        ref1.getToAddress.return_value = target_addr

        ref2 = MagicMock()
        ref2.getReferenceType.return_value.isCall.return_value = True
        ref2.getToAddress.return_value = target_addr

        mock_insn.getReferencesFrom.return_value = [ref1, ref2]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee,  # ref1 lookup
            callee,  # ref2 lookup
        ]
        # callee body has no instructions.
        backend.program.getListing.return_value.getInstructions.side_effect = [
            _make_iter(mock_insn),
            _make_iter(),
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=1)
        # Even though ref1 and ref2 both point to same callee, only 1 edge expected.
        assert len(result.edges) == 1

    def test_get_callees_skips_ref_not_call_type(self):
        """_get_callees: ref whose getReferenceType().isCall()=False is ignored."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        # Ref that is NOT a call type.
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = False
        mock_insn.getReferencesFrom.return_value = [mock_ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)

        result = callgraph_sync(backend, '0x1000', direction='callees')
        assert result.nodes[0].addr == '0x1000'
        assert len(result.edges) == 0

    def test_get_callees_skips_none_target_function(self):
        """_get_callees: getFunctionAt returns None → callee not added."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        mock_ref = MagicMock()
        mock_ref.getReferenceType.return_value.isCall.return_value = True
        target_addr = MagicMock()
        mock_ref.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [mock_ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        # getFunctionAt: first for _resolve_function (returns root), second None (callee lookup).
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            None,
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees')
        # No callee added; only root node.
        assert len(result.nodes) == 1
        assert len(result.edges) == 0

    def test_get_callers_skips_none_caller_function(self):
        """_get_callers: getFunctionContaining returns None → caller not added."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        caller_ref = MagicMock()
        caller_ref.getReferenceType.return_value.isCall.return_value = True
        from_addr = MagicMock()
        caller_ref.getFromAddress.return_value = from_addr
        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = [caller_ref]
        # getFunctionContaining returns None → caller skipped.
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = callgraph_sync(backend, '0x1000', direction='callers')
        assert len(result.nodes) == 1
        assert len(result.edges) == 0

    def test_get_callers_skips_ref_not_call_type(self):
        """_get_callers: ref.getReferenceType().isCall()=False → caller ignored."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        caller_ref = MagicMock()
        caller_ref.getReferenceType.return_value.isCall.return_value = False
        backend.program.getReferenceManager.return_value.getReferencesTo.return_value = [caller_ref]

        result = callgraph_sync(backend, '0x1000', direction='callers')
        assert len(result.nodes) == 1
        assert len(result.edges) == 0

    def test_already_truncated_skips_iteration(self):
        """Once truncated=True, traverse() returns immediately without iterating."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee_a = _make_func_with_offset('a', 0x2000)
        callee_b = _make_func_with_offset('b', 0x3000)

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True

        ref_a = MagicMock()
        ref_a.getReferenceType.return_value.isCall.return_value = True
        ref_a.getToAddress.return_value = MagicMock()

        ref_b = MagicMock()
        ref_b.getReferenceType.return_value.isCall.return_value = True
        ref_b.getToAddress.return_value = MagicMock()

        mock_insn.getReferencesFrom.return_value = [ref_a, ref_b]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee_a,
            callee_b,
        ]
        # After callee_a is added (depth=1) with max_depth=0 → depth exceeded.
        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=0)
        assert result.truncated is True

    def test_get_callees_non_call_insn_skipped(self):
        """_get_callees: insn.getFlowType().isCall()=False → refs not inspected."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = False
        # getReferencesFrom should NOT be called; if it is the test will catch side effects.
        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)

        result = callgraph_sync(backend, '0x1000', direction='callees')
        assert len(result.nodes) == 1
        assert len(result.edges) == 0

    def test_node_already_in_nodes_skips_reinsertion(self):
        """When the same function addr is visited via two paths, node added only once."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        # Both traversal passes ('both') visit root; node should exist after first pass.
        result = callgraph_sync(backend, '0x1000', direction='both')
        root_nodes = [n for n in result.nodes if n.addr == '0x1000']
        assert len(root_nodes) == 1  # deduplicated

    def test_depth_limit_reason_not_overwritten_when_already_set(self):
        """limit_reason is not overwritten once set: 'depth' stays if already 'depth'."""
        from mcpyghidra.tools.cfg import callgraph_sync

        # We need TWO callees both at depth > max_depth so both trigger the
        # `depth > max_depth` branch.  The second call sees limit_reason already set.
        backend = _make_callgraph_backend()

        callee_a = _make_func_with_offset('a', 0x2000)
        callee_b = _make_func_with_offset('b', 0x3000)

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True

        ref_a = MagicMock()
        ref_a.getReferenceType.return_value.isCall.return_value = True
        ref_a.getToAddress.return_value = MagicMock()
        ref_b = MagicMock()
        ref_b.getReferenceType.return_value.isCall.return_value = True
        ref_b.getToAddress.return_value = MagicMock()
        mock_insn.getReferencesFrom.return_value = [ref_a, ref_b]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee_a,
            callee_b,
        ]

        # max_depth=0 means depth=1 > 0 triggers truncation on first callee;
        # second callee call sees truncated=True → early return (line 332).
        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=0)
        assert result.truncated is True
        assert result.limit_reason == 'depth'

    def test_duplicate_edge_key_traversal_still_continues(self):
        """Duplicate edge is not re-added to edges list but traverse still recurses."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee = _make_func_with_offset('callee', 0x2000)
        callee_body = MagicMock()
        callee.getBody.return_value = callee_body

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True

        # Two refs both pointing to same callee address.
        target_addr = MagicMock()
        ref1 = MagicMock()
        ref1.getReferenceType.return_value.isCall.return_value = True
        ref1.getToAddress.return_value = target_addr
        ref2 = MagicMock()
        ref2.getReferenceType.return_value.isCall.return_value = True
        ref2.getToAddress.return_value = target_addr
        mock_insn.getReferencesFrom.return_value = [ref1, ref2]

        insn_calls: list[int] = [0]

        def side_getInstructions(body, forward):
            insn_calls[0] += 1
            if insn_calls[0] == 1:
                return _make_iter(mock_insn)
            return _make_iter()

        backend.program.getListing.return_value.getInstructions.side_effect = side_getInstructions
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee,  # ref1
            callee,  # ref2 — same callee, visited guard fires
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=2)
        # Only one edge despite two refs to same callee.
        assert len(result.edges) == 1

    def test_node_not_re_added_when_addr_already_in_nodes(self):
        """'both' direction: root node added during callees pass; callers pass finds
        addr already in nodes → the `if addr_hex not in nodes` branch takes False path."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()
        # 'both' direction: root traversed twice (callees pass, then callers pass).
        # After callees pass, root is in nodes. Callers pass re-visits root but the
        # node already exists so the `if addr_hex not in nodes` check is False.
        result = callgraph_sync(backend, '0x1000', direction='both')
        root_nodes = [n for n in result.nodes if n.addr == '0x1000']
        assert len(root_nodes) == 1

    def test_limit_reason_not_overwritten_on_second_depth_violation(self):
        """limit_reason is set on first depth violation; second violation sees it non-None.

        This covers the `if limit_reason is None` False branch (line 341->343).
        We need two separate callees both at depth > max_depth.  The first truncates
        with limit_reason='depth'.  The second (reached via the broken-out loop
        continuing in the outer caller) calls traverse again which returns early at
        `if truncated: return`, NOT re-entering the `if limit_reason is None` check.

        To hit `if limit_reason is None` False: we need the edge-limit path to fire
        AFTER depth already set limit_reason, or we can set truncated=True manually
        and then call traverse with a pre-existing limit_reason by triggering the
        'both' direction scenario where callers pass also encounters depth > max_depth.
        """
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee = _make_func_with_offset('callee', 0x2000)
        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True
        ref = MagicMock()
        ref.getReferenceType.return_value.isCall.return_value = True
        ref.getToAddress.return_value = MagicMock()
        mock_insn.getReferencesFrom.return_value = [ref]

        backend.program.getListing.return_value.getInstructions.return_value = _make_iter(mock_insn)
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee,
        ]

        # max_depth=0 → first callee triggers depth truncation with limit_reason='depth'.
        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=0)
        assert result.limit_reason == 'depth'

    def test_both_direction_callee_also_appears_as_caller_node_not_re_added(self):
        """'both' mode: a function already in nodes from callees pass appears again in
        callers pass — the `if addr_hex not in nodes` False branch fires."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        # We will arrange: root has callee A; and root's caller is also A.
        # In callees pass: A added to nodes.
        # In callers pass: visited reset to {root}. Root's callers include A.
        # A is not in visited, so traverse(A) proceeds past visited check.
        # A IS in nodes → `if addr_hex not in nodes` is False.

        func_a = _make_func_with_offset('a', 0x2000)

        # callees pass: root → A (one call instruction).
        mock_insn_root = MagicMock()
        mock_insn_root.getFlowType.return_value.isCall.return_value = True
        ref_to_a = MagicMock()
        ref_to_a.getReferenceType.return_value.isCall.return_value = True
        ref_to_a.getToAddress.return_value = MagicMock()
        mock_insn_root.getReferencesFrom.return_value = [ref_to_a]

        # A body has no calls (preventing infinite recursion).
        insn_call_no: list[int] = [0]

        def getInstructions(body, forward):
            insn_call_no[0] += 1
            if insn_call_no[0] == 1:
                return _make_iter(mock_insn_root)
            return _make_iter()

        backend.program.getListing.return_value.getInstructions.side_effect = getInstructions

        # getFunctionAt: first _resolve_function→root, second _get_callees→A.
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            func_a,
        ]

        # callers pass: root's callers include A (via getReferenceManager).
        ref_from_a = MagicMock()
        ref_from_a.getReferenceType.return_value.isCall.return_value = True
        ref_from_a.getFromAddress.return_value = MagicMock()
        # Root's callers = [A]. A's callers = [] (no infinite loop).
        backend.program.getReferenceManager.return_value.getReferencesTo.side_effect = [
            [ref_from_a],  # root's callers
            [],             # A's callers
        ]
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = func_a

        result = callgraph_sync(backend, '0x1000', direction='both', max_depth=2)
        # A should appear only once in nodes.
        a_nodes = [n for n in result.nodes if n.addr == '0x2000']
        assert len(a_nodes) == 1

    def test_duplicate_edge_still_traverses_target(self):
        """Duplicate edge_key skips edge insertion but still recurses (line 377->381)."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        # Two references from root both point to callee_a (same addresses → same edge_key).
        func_a = _make_func_with_offset('a', 0x2000)

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True

        # Both refs have the same target address mock (so getOffset returns same value).
        shared_target = MagicMock()
        shared_target.getOffset.return_value = 0x2000

        ref1 = MagicMock()
        ref1.getReferenceType.return_value.isCall.return_value = True
        ref1.getToAddress.return_value = shared_target

        ref2 = MagicMock()
        ref2.getReferenceType.return_value.isCall.return_value = True
        ref2.getToAddress.return_value = shared_target

        mock_insn.getReferencesFrom.return_value = [ref1, ref2]

        call_count: list[int] = [0]

        def getInstructions(body, forward):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_iter(mock_insn)
            return _make_iter()

        backend.program.getListing.return_value.getInstructions.side_effect = getInstructions
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            func_a,  # ref1 lookup
            func_a,  # ref2 lookup — same function, edge_key already in edge_set
        ]

        result = callgraph_sync(backend, '0x1000', direction='callees', max_depth=2)
        # Edge between root and A inserted only once.
        assert len([e for e in result.edges
                    if e.from_addr == '0x1000' and e.to_addr == '0x2000']) == 1

    def test_truncated_flag_prevents_processing_after_edges_limit(self):
        """After edges are exhausted, the `if truncated: break` in the for-loop fires."""
        from mcpyghidra.tools.cfg import callgraph_sync

        backend = _make_callgraph_backend()

        callee_a = _make_func_with_offset('a', 0x2000)
        callee_b = _make_func_with_offset('b', 0x3000)

        mock_insn = MagicMock()
        mock_insn.getFlowType.return_value.isCall.return_value = True

        ref_a = MagicMock()
        ref_a.getReferenceType.return_value.isCall.return_value = True
        ref_a.getToAddress.return_value = MagicMock()
        ref_b = MagicMock()
        ref_b.getReferenceType.return_value.isCall.return_value = True
        ref_b.getToAddress.return_value = MagicMock()
        mock_insn.getReferencesFrom.return_value = [ref_a, ref_b]

        insn_call_count: list[int] = [0]

        def make_insn_iter(body, forward):
            insn_call_count[0] += 1
            if insn_call_count[0] == 1:
                return _make_iter(mock_insn)
            return _make_iter()  # callee bodies have no calls

        backend.program.getListing.return_value.getInstructions.side_effect = make_insn_iter
        backend.program.getFunctionManager.return_value.getFunctionAt.side_effect = [
            _make_func_with_offset('root', 0x1000),
            callee_a,
            callee_b,
        ]

        # max_edges=1 → first callee consumes the only edge slot; second triggers limit;
        # `if truncated: break` fires to exit the for-loop early.
        result = callgraph_sync(backend, '0x1000', direction='callees', max_edges=1)
        assert result.truncated is True
        assert result.limit_reason == 'edges'


# ---------------------------------------------------------------------------
# async wrappers — smoke tests (line 250 and 412)
# ---------------------------------------------------------------------------

import anyio  # noqa: E402


def _run_async(coro_fn, *args, **kwargs):
    async def wrapper():
        return await coro_fn(*args, **kwargs)
    return anyio.run(wrapper)


class TestAsyncWrappers:
    """cfg() and callgraph() async wrappers just delegate — smoke tests only."""

    def test_cfg_async_wrapper_returns_cfg_result(self):
        """cfg() delegates to cfg_sync in a thread pool."""
        from mcpyghidra.tools.cfg import cfg

        backend = _make_backend_for_cfg()
        result = _run_async(cfg, backend, '0x1000', False)
        assert result.block_count >= 1

    def test_callgraph_async_wrapper_returns_callgraph_result(self):
        """callgraph() delegates to callgraph_sync in a thread pool."""
        from mcpyghidra.tools.cfg import callgraph

        backend = _make_callgraph_backend()
        result = _run_async(callgraph, backend, '0x1000', direction='callees')
        assert result.direction == 'callees'
