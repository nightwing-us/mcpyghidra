"""Analysis tools: decompile, disasm, symbols, xrefs.

All functions take ``backend: GhidraBackend`` as their first argument.
These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.

Tool merges implemented here:
- disasm: merges disassemble_function + disassemble_addr
- xrefs:  merges find_xrefs_to_addr + find_xrefs_from_addr + find_xrefs_to_func
"""

from __future__ import annotations

import sys
from typing import (
    cast,
    Dict,
    Iterable,
    TYPE_CHECKING,
)

import anyio

from mcpyghidra.backend import GhidraBackend, GhidraError
from mcpyghidra.models import (
    ListResult,
    SymbolInfo,
)
from mcpyghidra.tools.core import (
    _get_address,
    _get_function,
    _tool_result_list_formatter,
)

if sys.version_info >= (3, 12):
    from mcpyghidra.custom_types_312 import JsonValueTypes
else:
    from mcpyghidra.custom_types_p312 import JsonValueTypes

if TYPE_CHECKING:
    from ghidra.program.database.code import InstructionDB
    from ghidra.program.model.address import GenericAddress
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Reference


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------


async def decompile(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Decompile function(s). Each item: {addr?, name?}.

    Returns C pseudocode WITH function comment prepended as a block comment.

    Each item in ``items`` is a dict with optional keys:
    - addr: hex address string (e.g. '0x401000')
    - name: function name string

    RETURNS: list of dicts, each with:
    - code: decompiled C pseudocode (on success), including comment block
    - name: resolved function name
    - entrypoint: function entry point (hex)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _decompile_sync(backend, items))


def _decompile_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for item in items:
        addr = item.get('addr', '') or ''
        name = item.get('name', '') or ''
        try:
            func = _get_function(backend, addr=addr, name=name)
            dec_func = backend.get_decompiled_func(func=func, reset=True)
            comment = func.getComment()
            code = dec_func.c_code
            if comment:
                code = f'/* {comment} */\n{code}'
            results.append({
                'name': dec_func.name,
                'entrypoint': dec_func.entrypoint,
                'code': code,
                'error': None,
            })
        except Exception as e:
            results.append({'addr': addr, 'name': name, 'error': str(e)})
    return results


# ---------------------------------------------------------------------------
# disasm helpers
# ---------------------------------------------------------------------------


def _disasm_function(backend: GhidraBackend, func: 'Function') -> str:
    """Disassemble an entire function, returning formatted multi-line string."""
    from ghidra.program.model.listing import CodeUnit

    result = []
    listing = backend.program.getListing()
    start_addr = func.getEntryPoint()
    end_addr = func.getBody().getMaxAddress()

    instructions = cast(
        Iterable['InstructionDB'],
        listing.getInstructions(start_addr, True),
    )
    for inst in instructions:
        if inst.getAddress() > end_addr:
            break

        bytes_ = inst.getBytes()
        hex_bytes = ' '.join(f'{b & 0xFF:02X}' for b in bytes_) if bytes_ else ''

        comment = listing.getComment(CodeUnit.EOL_COMMENT, inst.getAddress())
        comment_str = f' ; {comment}' if comment else ''

        result.append(
            f'{inst.getAddress().offset:x}: {hex_bytes:<20} {inst.toString()}{comment_str}'
        )
    return '\n'.join(result)


def _disasm_addr(backend: GhidraBackend, ea: 'GenericAddress', count: int) -> str:
    """Disassemble ``count`` instructions from ``ea``, returning formatted string."""
    from ghidra.app.util import PseudoDisassembler

    program = backend.program
    memory = program.getMemory()
    listing = program.getListing()
    pseudo = PseudoDisassembler(program)

    disasm_lines = []
    cur = ea

    for _ in range(max(0, count)):
        block = memory.getBlock(cur)
        if block is None:
            disasm_lines.append(
                f'{cur}: Out of mapped memory or reached block boundary.'
            )
            break

        instr = listing.getInstructionAt(cur)
        if instr is None:
            instr = pseudo.disassemble(cur)

        if instr is None:
            disasm_lines.append(f'{cur}: Failed to decode instruction.')
            break

        line = instr.toString()
        if not line:
            disasm_lines.append(f'{cur}: Could not generate disassembly.')
            break

        disasm_lines.append(f'{cur}: {line}')

        length = instr.getLength()
        if length <= 0:
            disasm_lines.append(
                f'{cur}: Decoder returned zero-length instruction; stopping.'
            )
            break

        next_off = cur.getOffset() + length
        cur = cur.getAddressSpace().getAddress(next_off)

    return '\n'.join(disasm_lines)


# ---------------------------------------------------------------------------
# disasm (merged)
# ---------------------------------------------------------------------------


async def disasm(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Disassemble function(s) or address ranges. MERGED from disassemble_function + disassemble_addr.

    Each item in ``items`` is a dict with optional keys:
    - addr: hex address string (e.g. '0x401000')
    - name: function name string
    - count: number of instructions (int, optional)

    Mode detection per item:
    - count is set (not None) → address mode: disassemble count instructions from addr
    - name provided → function mode: disassemble the named function
    - addr inside a function, no count → function mode: disassemble containing function
    - addr not in a function, no count → address mode with default 20 instructions

    RETURNS: list of dicts, each with:
    - asm: disassembly text (on success)
    - addr: resolved address
    - name: function name (if function mode)
    - mode: 'function' or 'address'
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _disasm_sync(backend, items))


def _disasm_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for item in items:
        addr = item.get('addr', '') or ''
        name = item.get('name', '') or ''
        count = item.get('count', None)

        try:
            if count is not None:
                # Address mode: N instructions from addr
                if not addr:
                    raise GhidraError('addr is required when count is specified')
                ea = _get_address(backend, addr)
                asm_text = _disasm_addr(backend, ea, count)
                results.append({
                    'addr': addr,
                    'mode': 'address',
                    'count': count,
                    'asm': asm_text,
                    'error': None,
                })
            elif name:
                # Function mode by name
                func = _get_function(backend, addr='', name=name)
                asm_text = _disasm_function(backend, func)
                results.append({
                    'addr': f'{func.getEntryPoint().offset:#x}',
                    'name': func.getName(),
                    'mode': 'function',
                    'asm': asm_text,
                    'error': None,
                })
            elif addr:
                # Try function mode first (addr inside function), fallback to address mode
                ea = _get_address(backend, addr)
                func = backend.program.getFunctionManager().getFunctionContaining(ea)
                if func is not None:
                    asm_text = _disasm_function(backend, func)
                    results.append({
                        'addr': f'{func.getEntryPoint().offset:#x}',
                        'name': func.getName(),
                        'mode': 'function',
                        'asm': asm_text,
                        'error': None,
                    })
                else:
                    # Fallback: disassemble 20 instructions from addr
                    asm_text = _disasm_addr(backend, ea, 20)
                    results.append({
                        'addr': addr,
                        'mode': 'address',
                        'count': 20,
                        'asm': asm_text,
                        'error': None,
                    })
            else:
                raise GhidraError('Either addr or name must be provided')
        except Exception as e:
            results.append({'addr': addr, 'name': name, 'error': str(e)})
    return results


# ---------------------------------------------------------------------------
# symbols
# ---------------------------------------------------------------------------


def _classify_symbol(backend: GhidraBackend, ea: 'GenericAddress') -> SymbolInfo:
    """Return a SymbolInfo for the primary symbol at ``ea``."""
    from ghidra.program.model.symbol import SymbolType as _SymbolType

    program = backend.program
    listing = program.getListing()
    symtab = program.getSymbolTable()

    f = listing.getFunctionAt(ea)
    if f is not None:
        return SymbolInfo(name=f.name, symbol_type='function')

    sym = symtab.getPrimarySymbol(ea)
    if sym is None:
        raise GhidraError(f'No symbol found at {ea.offset:#x}')

    stype = sym.getSymbolType()
    symbol_type: str = 'unknown'
    if stype == _SymbolType.LABEL:
        symbol_type = 'code_label'
    elif stype == _SymbolType.GLOBAL:
        symbol_type = 'global_variable'
    elif stype == _SymbolType.DATA:
        symbol_type = 'data_label'
    elif stype == _SymbolType.FUNCTION:
        symbol_type = 'function'

    return SymbolInfo(name=sym.name, symbol_type=symbol_type)


async def symbols(backend: GhidraBackend, items: list[str]) -> list[dict]:
    """Get symbol info for address(es). Batch: accepts list of hex addrs.

    Each entry in ``items`` is a hex address string (e.g. '0x401000').

    RETURNS: list of dicts, each with:
    - addr: input address
    - name: symbol name (on success)
    - symbol_type: one of function, code_label, global_variable, data_label, unknown (on success)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _symbols_sync(backend, items))


def _symbols_sync(backend: GhidraBackend, items: list[str]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for addr in items:
        try:
            ea = _get_address(backend, addr)
            if ea is None:
                raise GhidraError(f'Failed to parse address: {addr}')
            info = _classify_symbol(backend, ea)
            results.append({
                'addr': addr,
                'name': info.name,
                'symbol_type': info.symbol_type,
                'error': None,
            })
        except Exception as e:
            results.append({'addr': addr, 'error': str(e)})
    return results


# ---------------------------------------------------------------------------
# xrefs helpers
# ---------------------------------------------------------------------------


def _xrefs_to_addr(
    backend: GhidraBackend,
    ea: 'GenericAddress',
    offset: int = 0,
    limit: int = 500,
) -> ListResult:
    """Find all references TO ``ea``."""
    ref_mgr = backend.program.getReferenceManager()
    ref_iter = ref_mgr.getReferencesTo(ea)

    def process_xref(ref: 'Reference') -> Dict[str, JsonValueTypes]:
        from_addr = ref.getFromAddress()
        ref_type = ref.getReferenceType()
        ref_func = backend.program.getFunctionManager().getFunctionContaining(from_addr)
        from_info: Dict[str, JsonValueTypes] = {'addr': f'{from_addr.offset:#x}'}
        if ref_func:
            from_info['function'] = ref_func.name
        return {
            'type': 'Cross-Reference to Address',
            'from': from_info,
            'xref-type': str(ref_type),
        }

    return _tool_result_list_formatter(
        f'Cross-references to {ea.offset:#x}',
        'cross-reference',
        process_xref,
        ref_iter,
        offset,
        limit,
    )


def _xrefs_from_addr(
    backend: GhidraBackend,
    ea: 'GenericAddress',
    offset: int = 0,
    limit: int = 500,
) -> ListResult:
    """Find all references FROM ``ea``."""
    ref_mgr = backend.program.getReferenceManager()
    ref_iter = ref_mgr.getReferencesFrom(ea)

    def process_xref(ref: 'Reference') -> Dict[str, JsonValueTypes]:
        to_addr = ref.getToAddress()
        ref_type = ref.getReferenceType()
        ref_func = backend.program.getFunctionManager().getFunctionContaining(to_addr)
        to_info: Dict[str, JsonValueTypes] = {'addr': f'{to_addr.offset:#x}'}
        if ref_func:
            to_info['function'] = ref_func.name
        return {
            'type': f'Cross-Reference from {ea.offset:#x}',
            'to': to_info,
            'xref-type': str(ref_type),
        }

    return _tool_result_list_formatter(
        f'Cross-references from {ea.offset:#x}',
        'cross-reference',
        process_xref,
        ref_iter,
        offset,
        limit,
    )


# ---------------------------------------------------------------------------
# xrefs (merged)
# ---------------------------------------------------------------------------


async def xrefs(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Cross-references. MERGED from find_xrefs_to_addr + find_xrefs_from_addr + find_xrefs_to_func.

    Each item in ``items`` is a dict with keys:
    - target: hex address string (e.g. '0x401000') OR function name string
      Auto-detection: starts with '0x' → address, otherwise → function name resolved to entry point
    - direction: 'to' (default) or 'from'
    - offset: pagination start (default 0)
    - limit: max results per item (default 500)

    RETURNS: list of dicts, each with:
    - target: input target value
    - direction: 'to' or 'from'
    - result: ListResult (on success)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _xrefs_sync(backend, items))


def _xrefs_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for item in items:
        target: str = item.get('target', '') or ''
        direction: str = item.get('direction', 'to') or 'to'
        item_offset: int = int(item.get('offset', 0) or 0)
        item_limit: int = int(item.get('limit', 500) or 500)

        if item_offset < 0:
            results.append({
                'target': target,
                'direction': direction,
                'error': 'offset must be non-negative',
            })
            continue
        if item_limit <= 0:
            results.append({
                'target': target,
                'direction': direction,
                'error': 'limit must be positive',
            })
            continue

        try:
            # Auto-detect: 0x prefix → address, otherwise → function name
            if target.startswith('0x') or target.startswith('0X'):
                ea = _get_address(backend, target)
            else:
                # Resolve function name to entry point via flat_api (O(1) hash lookup)
                matched_func = backend.flat_api.getFunction(target)
                if matched_func is None:
                    raise GhidraError(f'Function {target!r} not found')
                ea = matched_func.getEntryPoint()

            if direction == 'to':
                list_result = _xrefs_to_addr(backend, ea, item_offset, item_limit)
            elif direction == 'from':
                list_result = _xrefs_from_addr(backend, ea, item_offset, item_limit)
            else:
                raise GhidraError(
                    f"direction must be 'to' or 'from', got {direction!r}"
                )

            results.append({
                'target': target,
                'direction': direction,
                'result': list_result,
                'error': None,
            })
        except Exception as e:
            results.append({'target': target, 'direction': direction, 'error': str(e)})
    return results
