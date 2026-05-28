"""Search tools — find_bytes and find_insns.

Ghidra implementation using Memory.findBytes with mask arrays.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
from mcpyghidra.tools.search_utils import parse_byte_pattern

if TYPE_CHECKING:
    from mcpyghidra.backend import GhidraBackend


async def find_bytes(
    backend: 'GhidraBackend',
    patterns: list[str],
    limit: int = 1000,
    offset: int = 0,
) -> list[dict]:
    """Search for byte patterns with wildcard support.

    Each pattern: space-separated hex tokens, '??' for wildcard.
    Example: '48 8B ?? ??'
    """
    if not isinstance(patterns, list):
        patterns = [patterns]
    return await anyio.to_thread.run_sync(
        lambda: _find_bytes_sync(backend, patterns, limit, offset)
    )


def _find_bytes_sync(
    backend: 'GhidraBackend',
    patterns: list[str],
    limit: int,
    offset: int,
) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results = []
    for pattern_str in patterns:
        try:
            data_bytes, mask_bytes = parse_byte_pattern(pattern_str)
            matches = _search_bytes_ghidra(
                backend, data_bytes, mask_bytes, limit + 1, offset
            )

            has_more = len(matches) > limit
            if has_more:
                matches = matches[:limit]

            results.append({
                'pattern': pattern_str,
                'matches': matches,
                'has_more': has_more,
                'error': None,
            })
        except Exception as e:
            results.append({
                'pattern': pattern_str,
                'matches': [],
                'has_more': False,
                'error': str(e),
            })
    return results


def _search_bytes_ghidra(
    backend: 'GhidraBackend',
    data: bytes,
    mask: bytes,
    max_results: int,
    skip: int,
) -> list[dict]:
    """Search using Ghidra Memory.findBytes with mask arrays."""
    from ghidra.util.task import TaskMonitor
    import jpype

    program = backend.program
    memory = program.getMemory()
    monitor = TaskMonitor.DUMMY

    # Convert to Java byte arrays.
    # Java bytes are signed (-128 to 127); Python bytes are unsigned (0 to 255).
    # Values > 127 must be converted to their signed equivalents for JPype.
    # Use jpype.JArray(jpype.JByte) to construct from a Python list (JPype 1.x API).
    def _to_signed(b: int) -> int:
        return b if b < 128 else b - 256

    j_data = jpype.JArray(jpype.JByte)([_to_signed(b) for b in data])
    j_mask = jpype.JArray(jpype.JByte)([_to_signed(b) for b in mask])

    start_addr = program.getMinAddress()
    end_addr = program.getMaxAddress()

    matches = []
    found = 0
    skipped = 0
    addr = start_addr

    while addr is not None and found < max_results:
        addr = memory.findBytes(addr, end_addr, j_data, j_mask, True, monitor)
        if addr is None:
            break

        if skipped < skip:
            skipped += 1
        else:
            # Read actual matched bytes for display
            matched_bytes = _read_bytes_at(memory, addr, len(data))
            matches.append({
                'addr': f'{addr.getOffset():#x}',
                'bytes': matched_bytes,
            })
            found += 1

        try:
            addr = addr.add(1)  # advance past match
        except Exception:
            break  # past end of address space

    return matches


def _read_bytes_at(memory, addr, length: int) -> str:
    """Read bytes at address and format as hex string."""
    try:
        buf = bytearray(length)
        memory.getBytes(addr, buf)
        return ' '.join(f'{b:02X}' for b in buf)
    except Exception:
        return ''


async def find_insns(
    backend: 'GhidraBackend',
    sequences: list[list[dict]],
    limit: int = 1000,
    offset: int = 0,
) -> list[dict]:
    """Search for consecutive instruction sequences.

    Each sequence is a list of {mnemonic, operands} dicts.
    Operands use glob by default, /regex/ for regex.
    """
    if not isinstance(sequences, list):
        sequences = [sequences]
    return await anyio.to_thread.run_sync(
        lambda: _find_insns_sync(backend, sequences, limit, offset)
    )


def _find_insns_sync(
    backend: 'GhidraBackend',
    sequences: list[list[dict]],
    limit: int,
    offset: int,
) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results = []
    for sequence in sequences:
        try:
            matches = _search_insns_ghidra(backend, sequence, limit + 1, offset)

            has_more = len(matches) > limit
            if has_more:
                matches = matches[:limit]

            results.append({
                'sequence': sequence,
                'matches': matches,
                'has_more': has_more,
                'error': None,
            })
        except Exception as e:
            results.append({
                'sequence': sequence,
                'matches': [],
                'has_more': False,
                'error': str(e),
            })
    return results


def _search_insns_ghidra(
    backend: 'GhidraBackend',
    sequence: list[dict],
    max_results: int,
    skip: int,
) -> list[dict]:
    """Search Ghidra instructions for consecutive sequence match."""
    from mcpyghidra.tools.search_utils import match_instruction  # noqa: F401 (used in _try_match_sequence)

    program = backend.program
    listing = program.getListing()

    # Get executable address set
    exec_set = _get_executable_addresses(program)
    insn_iter = listing.getInstructions(exec_set, True)

    matches = []
    found = 0
    skipped = 0

    while insn_iter.hasNext() and found < max_results:
        insn = insn_iter.next()

        # Check if this instruction starts a matching sequence
        matched_insns = _try_match_sequence(insn, sequence)
        if matched_insns is not None:
            if skipped < skip:
                skipped += 1
            else:
                matches.append({
                    'addr': f'{insn.getAddress().getOffset():#x}',
                    'instructions': [
                        f'{i.getAddress().getOffset():#x}: {i.toString()}'
                        for i in matched_insns
                    ],
                })
                found += 1

    return matches


def _try_match_sequence(start_insn, sequence: list[dict]) -> list | None:
    """Try to match a sequence starting at start_insn. Returns matched instructions or None."""
    from mcpyghidra.tools.search_utils import match_instruction

    matched = []
    current = start_insn

    for pattern in sequence:
        if current is None:
            return None

        mnemonic = current.getMnemonicString()
        operands = [
            current.getDefaultOperandRepresentation(i)
            for i in range(current.getNumOperands())
        ]

        if not match_instruction(
            pattern.get('mnemonic', '*'),
            pattern.get('operands'),
            mnemonic,
            operands,
        ):
            return None

        matched.append(current)
        current = current.getNext()

    return matched


def _get_executable_addresses(program):
    """Get AddressSet of executable memory blocks."""
    from ghidra.program.model.address import AddressSet

    addr_set = AddressSet()
    for block in program.getMemory().getBlocks():
        if block.isExecute():
            addr_set.add(block.getAddressRange())
    return addr_set
