"""CFG extraction and normalization tools."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import anyio

from mcpyghidra.models import (
    BasicBlock,
    CFGFeatures,
    CFGResult,
    CallgraphEdge,
    CallgraphNode,
    CallgraphResult,
)

if TYPE_CHECKING:
    from mcpyghidra.backend import GhidraBackend


# ---------------------------------------------------------------------------
# Address conversion helper
# ---------------------------------------------------------------------------


def _addr_to_hex(addr) -> str:
    """Convert Ghidra address to hex string."""
    return hex(addr.getOffset())


# ---------------------------------------------------------------------------
# Function resolution helper
# ---------------------------------------------------------------------------


def _resolve_name(func) -> str:
    """Get function name, resolving through thunk chain."""
    thunked = func.getThunkedFunction(True)
    if thunked is not None:
        return thunked.getName()
    return func.getName()


def _resolve_function(program, address_or_name: str):
    """Resolve a function by address (hex string) or name.

    Tries address lookup first (both getFunctionAt and getFunctionContaining),
    then falls back to iterating all functions by name.

    Raises:
        ValueError: if no function is found.
    """
    func_mgr = program.getFunctionManager()

    # Try as address first
    try:
        addr = program.getAddressFactory().getAddress(address_or_name)
        if addr is not None:
            func = func_mgr.getFunctionAt(addr)
            if func is not None:
                return func
            func = func_mgr.getFunctionContaining(addr)
            if func is not None:
                return func
    except Exception:
        pass

    # Try as name — use flat_api-style iteration
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        if func.getName() == address_or_name:
            return func

    raise ValueError(f'Function not found: {address_or_name!r}')


# ---------------------------------------------------------------------------
# CFG extraction
# ---------------------------------------------------------------------------


def cfg_sync(
    backend: 'GhidraBackend',
    address: str,
    normalize: bool = True,
    include_bytes: bool = False,
    include_disassembly: bool = False,
) -> CFGResult:
    """Extract the control flow graph for a function.

    Args:
        backend: Active GhidraBackend instance.
        address: Hex address string or function name identifying the function.
        normalize: Apply IDA-style normalization (merge post-call split blocks,
            filter out-of-function successors, sort successors).
        include_bytes: Attach base64-encoded raw bytes to each block.
        include_disassembly: Attach per-instruction disassembly list to each block.

    Returns:
        CFGResult with entry point, block map, and aggregated features.
    """
    from ghidra.program.model.block import SimpleBlockModel
    from ghidra.util.task import TaskMonitor

    program = backend.program
    func = _resolve_function(program, address)

    func_body = func.getBody()
    func_start = func_body.getMinAddress()
    func_end = func_body.getMaxAddress()

    block_model = SimpleBlockModel(program)
    listing = program.getListing()
    monitor = TaskMonitor.DUMMY

    blocks: dict[str, BasicBlock] = {}

    # Iterate all code blocks contained within the function body.
    block_iter = block_model.getCodeBlocksContaining(func_body, monitor)
    while block_iter.hasNext():
        code_block = block_iter.next()

        addr = code_block.getMinAddress()
        # size = max_addr - min_addr + 1 (byte count, inclusive)
        size = code_block.getMaxAddress().getOffset() - addr.getOffset() + 1
        addr_hex = _addr_to_hex(addr)

        # Collect successors (destination addresses of control-flow edges).
        successors: list[str] = []
        dest_iter = code_block.getDestinations(monitor)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            dest_addr = dest.getDestinationAddress()
            successors.append(_addr_to_hex(dest_addr))

        # Analyse instructions in the block.
        called_funcs: dict[str, str] = {}
        strings: list[str] = []
        insn_count = 0
        raw_bytes = bytearray()
        instructions_list: list[dict[str, str]] = []

        insn_iter = listing.getInstructions(code_block, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            insn_count += 1

            # Detect call instructions and record call targets.
            flow_type = insn.getFlowType()
            if flow_type.isCall():
                for ref in insn.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        target_addr = ref.getToAddress()
                        target_func = program.getFunctionManager().getFunctionAt(
                            target_addr
                        )
                        name = (
                            _resolve_name(target_func)
                            if target_func is not None
                            else _addr_to_hex(target_addr)
                        )
                        called_funcs[_addr_to_hex(target_addr)] = name

            # Collect string references from all operands.
            for op_idx in range(insn.getNumOperands()):
                for ref in insn.getOperandReferences(op_idx):
                    ref_addr = ref.getToAddress()
                    data = listing.getDefinedDataAt(ref_addr)
                    if data is not None and data.hasStringValue():
                        value = data.getValue()
                        if value is not None:
                            strings.append(str(value))

            # Optionally accumulate raw bytes.
            if include_bytes:
                insn_bytes = insn.getBytes()
                if insn_bytes is not None:
                    raw_bytes.extend(bytes([b & 0xFF for b in insn_bytes]))

            # Optionally accumulate per-instruction disassembly.
            if include_disassembly:
                mnemonic = str(insn.getMnemonicString())
                operands = ', '.join(
                    str(insn.getDefaultOperandRepresentation(i))
                    for i in range(insn.getNumOperands())
                )
                instructions_list.append({
                    'address': _addr_to_hex(insn.getAddress()),
                    'mnemonic': mnemonic,
                    'operands': operands,
                })

        block = BasicBlock(
            address=addr_hex,
            size=size,
            successors=successors,
            instruction_count=insn_count,
            called_funcs=called_funcs,
            strings=strings,
        )

        if include_bytes:
            block = block.model_copy(
                update={'bytes': base64.b64encode(bytes(raw_bytes)).decode()}
            )
        if include_disassembly:
            block = block.model_copy(update={'instructions': instructions_list})

        blocks[addr_hex] = block

    # Optionally normalise (merge Ghidra's post-call splits, filter OOF successors).
    if normalize:
        func_start_int = func_start.getOffset()
        # function_end is exclusive — one past the last byte.
        func_end_int = func_end.getOffset() + 1
        blocks = normalize_ghidra_cfg(blocks, func_start_int, func_end_int)

    # Aggregate function-level features across all (possibly merged) blocks.
    all_called_funcs: dict[str, str] = {}
    all_strings: list[str] = []
    total_insns = 0
    for b in blocks.values():
        all_called_funcs.update(b.called_funcs)
        all_strings.extend(b.strings)
        total_insns += b.instruction_count

    return CFGResult(
        entry=_addr_to_hex(func.getEntryPoint()),
        block_count=len(blocks),
        blocks=blocks,
        features=CFGFeatures(
            instruction_count=total_insns,
            called_funcs=all_called_funcs,
            strings=all_strings,
        ),
    )


async def cfg(
    backend: 'GhidraBackend',
    address: str,
    normalize: bool = True,
    include_bytes: bool = False,
    include_disassembly: bool = False,
) -> CFGResult:
    """Async wrapper for cfg_sync — runs Ghidra work in a thread pool."""
    return await anyio.to_thread.run_sync(
        lambda: cfg_sync(
            backend, address, normalize, include_bytes, include_disassembly
        )
    )


# ---------------------------------------------------------------------------
# Callgraph traversal
# ---------------------------------------------------------------------------


def callgraph_sync(
    backend: 'GhidraBackend',
    address: str,
    direction: str = 'callees',
    max_depth: int = 5,
    max_nodes: int = 1000,
    max_edges: int = 5000,
) -> CallgraphResult:
    """Build a call graph rooted at the given function.

    Args:
        backend: Active GhidraBackend instance.
        address: Hex address string or function name identifying the root function.
        direction: One of ``'callees'``, ``'callers'``, or ``'both'``.
        max_depth: Maximum DFS traversal depth (inclusive).
        max_nodes: Stop adding nodes when this count is reached.
        max_edges: Stop adding edges when this count is reached.

    Returns:
        CallgraphResult with node/edge lists and truncation metadata.
    """
    if direction not in ('callees', 'callers', 'both'):
        raise ValueError(
            f"Invalid direction '{direction}', must be 'callees', 'callers', or 'both'"
        )

    program = backend.program
    func_mgr = program.getFunctionManager()
    listing = program.getListing()

    root_func = _resolve_function(program, address)
    root_addr = _addr_to_hex(root_func.getEntryPoint())

    nodes: dict[str, CallgraphNode] = {}
    edges: list[CallgraphEdge] = []
    edge_set: set[tuple[str, str]] = set()
    visited: set[str] = set()
    truncated = False
    limit_reason: str | None = None

    def _get_callees(func):
        """Return the set of functions directly called by *func*."""
        callees: set = set()
        body = func.getBody()
        insn_iter = listing.getInstructions(body, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            if insn.getFlowType().isCall():
                for ref in insn.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        target = func_mgr.getFunctionAt(ref.getToAddress())
                        if target is not None:
                            callees.add(target)
        return callees

    def _get_callers(func):
        """Return the set of functions that directly call *func*."""
        callers: set = set()
        ref_mgr = program.getReferenceManager()
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            if ref.getReferenceType().isCall():
                caller = func_mgr.getFunctionContaining(ref.getFromAddress())
                if caller is not None:
                    callers.add(caller)
        return callers

    def traverse(func, depth: int, get_related, is_callee_direction: bool) -> None:
        nonlocal truncated, limit_reason

        if truncated:
            return

        addr_hex = _addr_to_hex(func.getEntryPoint())

        if addr_hex in visited:
            return

        if depth > max_depth:
            truncated = True
            if limit_reason is None:
                limit_reason = 'depth'
            return

        if len(nodes) >= max_nodes:
            truncated = True
            limit_reason = 'nodes'
            return

        visited.add(addr_hex)
        if addr_hex not in nodes:
            nodes[addr_hex] = CallgraphNode(
                addr=addr_hex,
                name=_resolve_name(func),
                depth=depth,
            )

        for related in get_related(func):
            if truncated:
                break

            related_addr = _addr_to_hex(related.getEntryPoint())

            if len(edges) >= max_edges:
                truncated = True
                limit_reason = 'edges'
                break

            # Edge direction: callees → from=caller, to=callee;
            #                 callers → from=caller, to=callee (same convention).
            if is_callee_direction:
                from_addr, to_addr = addr_hex, related_addr
            else:
                from_addr, to_addr = related_addr, addr_hex

            edge_key = (from_addr, to_addr)
            if edge_key not in edge_set:
                edge_set.add(edge_key)
                edges.append(CallgraphEdge(from_addr=from_addr, to_addr=to_addr))

            traverse(related, depth + 1, get_related, is_callee_direction)

    if direction in ('callees', 'both'):
        traverse(root_func, 0, _get_callees, is_callee_direction=True)

    if direction in ('callers', 'both'):
        # For 'both': reset visited to only the root so callers are traversed
        # from the root but previously-discovered callee nodes are not re-added.
        if direction == 'both':
            visited = {root_addr}
        traverse(root_func, 0, _get_callers, is_callee_direction=False)

    return CallgraphResult(
        root=root_addr,
        direction=direction,
        nodes=list(nodes.values()),
        edges=edges,
        truncated=truncated,
        limit_reason=limit_reason,
    )


async def callgraph(
    backend: 'GhidraBackend',
    address: str,
    direction: str = 'callees',
    max_depth: int = 5,
    max_nodes: int = 1000,
    max_edges: int = 5000,
) -> CallgraphResult:
    """Async wrapper for callgraph_sync — runs Ghidra work in a thread pool."""
    return await anyio.to_thread.run_sync(
        lambda: callgraph_sync(
            backend, address, direction, max_depth, max_nodes, max_edges
        )
    )


# ---------------------------------------------------------------------------
# CFG normalization
# ---------------------------------------------------------------------------


def normalize_ghidra_cfg(
    blocks: dict[str, BasicBlock],
    function_start: int,
    function_end: int,
) -> dict[str, BasicBlock]:
    """Normalize Ghidra CFG to match IDA block boundaries.

    Applies three passes:
    1. Out-of-function successor filter: remove successors whose addresses fall
       outside [function_start, function_end) and are not already in the blocks
       dict.  This runs BEFORE the merge pass so absorbed successors are already
       clean — no special exemption is required after merging.
    2. Post-call block merge: merge contiguous blocks where the successor has
       <=1 predecessor (Ghidra splits at every CALL; IDA does not).
    3. Sort successors in ascending address order.

    Args:
        blocks: Mapping of hex-address string to BasicBlock.
        function_start: Inclusive lower bound of the function address range.
        function_end: Exclusive upper bound (one past the last byte of the
                      function body).  The valid range is
                      [function_start, function_end).
    """
    if not blocks:
        return {}

    # Work on a mutable deep copy so callers are not surprised by mutation.
    result: dict[str, BasicBlock] = {
        addr: block.model_copy(deep=True) for addr, block in blocks.items()
    }

    # --- Pass 1: filter out-of-function successors ---------------------------
    #
    # A successor is kept when it is already present in the blocks dict OR
    # when its address falls within [function_start, function_end).  This
    # covers forward references to blocks that appear later in the dict as
    # well as the common case where both ends of a branch are in-function.
    #
    # Running this pass first means the merge pass never inherits PLT/external
    # successors from absorbed blocks, eliminating the old merged_absorbers
    # exemption entirely.

    for block in result.values():
        block.successors = [
            s
            for s in block.successors
            if s in result or (function_start <= int(s, 16) < function_end)
        ]

    # --- Pass 2: fixed-point merge of contiguous single-predecessor blocks ---

    def _build_pred_counts(blks: dict[str, BasicBlock]) -> dict[str, int]:
        counts: dict[str, int] = {addr: 0 for addr in blks}
        for block in blks.values():
            for succ in block.successors:
                if succ in counts:
                    counts[succ] += 1
        return counts

    changed = True
    while changed:
        changed = False
        pred_counts = _build_pred_counts(result)

        for addr in list(result.keys()):
            if addr not in result:
                # Already removed in this pass.
                continue

            block = result[addr]
            succs = block.successors

            # Merge condition: exactly 1 successor that is contiguous AND
            # that successor has at most 1 predecessor.
            if len(succs) != 1:
                continue

            succ_addr = succs[0]
            if succ_addr not in result:
                continue

            block_end = int(addr, 16) + block.size
            succ_int = int(succ_addr, 16)
            if block_end != succ_int:
                continue

            if pred_counts.get(succ_addr, 0) > 1:
                continue

            # Perform the merge.
            succ_block = result.pop(succ_addr)

            block.size += succ_block.size
            block.instruction_count += succ_block.instruction_count
            block.called_funcs = {**block.called_funcs, **succ_block.called_funcs}
            block.strings = block.strings + succ_block.strings
            block.successors = succ_block.successors

            # Merge bytes (base64 decode, concat, re-encode).
            if block.bytes is not None and succ_block.bytes is not None:
                merged_bytes = base64.b64decode(block.bytes) + base64.b64decode(
                    succ_block.bytes
                )
                block = block.model_copy(
                    update={'bytes': base64.b64encode(merged_bytes).decode()}
                )
            elif succ_block.bytes is not None:
                block = block.model_copy(update={'bytes': succ_block.bytes})

            # Merge instructions (concatenate lists).
            if block.instructions is not None and succ_block.instructions is not None:
                block = block.model_copy(
                    update={
                        'instructions': block.instructions + succ_block.instructions
                    }
                )
            elif succ_block.instructions is not None:
                block = block.model_copy(
                    update={'instructions': succ_block.instructions}
                )

            result[addr] = block
            changed = True
            # Continue iterating — the while loop will rebuild pred_counts
            # for the next round, handling chains of 3 or more blocks.

    # --- Pass 3: sort successors ---------------------------------------------

    for block in result.values():
        block.successors = sorted(block.successors, key=lambda x: int(x, 16))

    return result
