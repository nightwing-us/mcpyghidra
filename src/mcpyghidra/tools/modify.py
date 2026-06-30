"""Modify tools: rename, set_comments, update_vars, set_prototype, patch, transactions.

All functions take ``backend: GhidraBackend`` as their first argument.
These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.

Tool merges implemented here:
- set_comments: merges set_function_disassembly_comment + set_function_decompiler_comment
                + set_function_comment  (kind param: 'disasm'|'decompiler'|'function'|'both')
"""

from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    Dict,
)

import anyio
from mcpyghidra.backend import GhidraBackend, GhidraError
from mcpyghidra.models import VarUpdate, VarUpdateReport
from mcpyghidra.tools.core import (
    _get_address,
    _get_function,
)

if TYPE_CHECKING:
    from ghidra.program.model.symbol import SourceType


# ---------------------------------------------------------------------------
# Module-level SourceType sentinel (mirrors mcpserver._AI_SOURCE_TYPE)
# Resolved lazily at call time to avoid import-time Java class resolution.
# ---------------------------------------------------------------------------


def _ai_source_type() -> 'SourceType':
    from ghidra.program.model.symbol import SourceType as _SourceType

    return getattr(_SourceType, 'AI', _SourceType.ANALYSIS)


# ---------------------------------------------------------------------------
# Private comment helpers
# ---------------------------------------------------------------------------


def _set_eol_comment(backend: GhidraBackend, addr: str, comment: str) -> str:
    """Set an EOL (end-of-line) comment at the given address in the listing view."""
    from ghidra.program.model.listing import CodeUnit

    ea = _get_address(backend, addr)
    backend.program.getListing().setComment(ea, CodeUnit.EOL_COMMENT, comment)
    return f'Successfully set disasm comment at {ea} to: {comment}'


def _set_decompiler_pre_comment(
    backend: GhidraBackend,
    line: int,
    comment: str,
    addr: str = '',
    name: str = '',
) -> str:
    """Set a pre-comment at ``line`` in the decompiler view of a function."""
    func = _get_function(backend, addr=addr, name=name)
    dec_func = backend.get_decompiled_func(func=func)
    if commented_line := dec_func.add_pre_comment_at_c_line(line, comment):
        return f'Successfully set comment at line {commented_line} to: {comment}'
    return f'Failed to set comment at line {line} to: {comment}'


def _set_function_plate_comment(
    backend: GhidraBackend,
    comment: str,
    addr: str = '',
    name: str = '',
) -> str:
    """Set the plate (function-level) comment on a function."""
    func = _get_function(backend, addr=addr, name=name)
    func.setComment(comment)
    return f'Comment updated for function {func.getName()} @ {func.getEntryPoint().offset:#x}'


# ---------------------------------------------------------------------------
# Private helper: resolve symbol by old name
# ---------------------------------------------------------------------------


def _resolve_by_old_name(
    backend: GhidraBackend,
    old_name: str,
) -> tuple['object | None', str | None, str | None]:
    """Resolve a unique symbol/function by name in the global namespace.

    Returns (addr, kind_str, err) where addr may be None on error.
    """
    from ghidra.program.model.symbol import SymbolType as _SymbolType

    if not old_name:
        return None, None, 'old_name not provided'

    symtab = backend.program.getSymbolTable()
    it = symtab.getSymbols(old_name)
    matches = [
        s
        for s in it
        if s.getSymbolType()
        in (_SymbolType.FUNCTION, _SymbolType.LABEL, _SymbolType.GLOBAL)
    ]
    if len(matches) == 0:
        return None, None, f"name '{old_name}' not found"
    if len(matches) > 1:
        return None, None, f"name '{old_name}' is ambiguous ({len(matches)} matches)"

    s = matches[0]
    kind = s.getSymbolType()
    if kind == _SymbolType.FUNCTION:
        return s.getAddress(), 'function', None
    elif kind == _SymbolType.GLOBAL:
        return s.getAddress(), 'global_variable', None
    else:
        return s.getAddress(), 'label', None


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------


async def rename(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Rename symbol(s). Each item: {new_name, addr?, name?}. Batched with per-item errors.

    Each item in ``items`` is a dict with:
    - new_name: new symbol name (required)
    - addr: hex address of the symbol (optional)
    - name: current symbol name (optional, alternative to addr)

    Provide EITHER addr OR name per item. If addr has no symbol, creates a new user label.

    RETURNS: list of dicts, each with:
    - addr: resolved hex address
    - old_name: previous symbol name
    - new_name: new name applied
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    backend.begin_batch()
    try:
        return await anyio.to_thread.run_sync(lambda: _rename_sync(backend, items))
    finally:
        backend.end_batch()


def _is_higher_priority_source(source_type: 'SourceType') -> bool:
    """Return True if the source type is higher priority than AI/ANALYSIS.

    USER and IMPORTED symbols are considered higher priority — the user or
    import loader intentionally set the name and confirmation is needed before
    the AI overwrites it.
    """
    from ghidra.program.model.symbol import SourceType as _SourceType

    return source_type in (_SourceType.USER_DEFINED, _SourceType.IMPORTED)


def _rename_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""

    ai_src = _ai_source_type()
    results: list[dict] = []

    with backend.create_transaction('batch rename'):
        for item in items:
            new_name: str = item.get('new_name', '') or ''
            addr: str = item.get('addr', '') or ''
            name: str = item.get('name', '') or ''
            try:
                if not new_name:
                    raise GhidraError('new_name is required')

                if addr:
                    ea = _get_address(backend, addr)
                    if ea is None:
                        raise GhidraError(f'Failed to parse address: {addr}')
                elif name:
                    ea, _, err = _resolve_by_old_name(backend, name)
                    if err:
                        raise GhidraError(err)
                else:
                    raise GhidraError('Provide either addr or name')

                program = backend.program
                listing = program.getListing()
                symtab = program.getSymbolTable()

                f = listing.getFunctionAt(ea)
                sym = symtab.getPrimarySymbol(ea)

                if f is not None:
                    old_name_val = f.getName()
                    if name and f.getName() != name:
                        raise GhidraError(
                            f"name mismatch: current_name='{f.getName()}' != name='{name}'"
                        )
                    # Check if we're overwriting a higher-priority name
                    try:
                        existing_source = f.getSymbol().getSource()
                    except Exception:
                        existing_source = None
                    if existing_source is not None and _is_higher_priority_source(
                        existing_source
                    ):
                        old_type = str(existing_source)
                        description = (
                            f'Confirm renaming {old_name_val} ({old_type}) '
                            f'at {ea.offset:#x} to {new_name}?'
                        )
                        if not backend.confirm_overwrite(description):
                            results.append({
                                'addr': f'{ea.offset:#x}',
                                'old_name': old_name_val,
                                'new_name': new_name,
                                'error': 'skipped: user declined overwrite of higher-priority symbol',
                            })
                            continue
                    f.setName(new_name, ai_src)
                    results.append({
                        'addr': f'{ea.offset:#x}',
                        'old_name': old_name_val,
                        'new_name': new_name,
                        'error': None,
                    })
                elif sym is not None:
                    old_name_val = sym.getName()
                    if name and sym.getName() != name:
                        raise GhidraError(
                            f"name mismatch: current_name='{sym.getName()}' != name='{name}'"
                        )
                    # Check if we're overwriting a higher-priority name
                    try:
                        existing_source = sym.getSource()
                    except Exception:
                        existing_source = None
                    if existing_source is not None and _is_higher_priority_source(
                        existing_source
                    ):
                        old_type = str(existing_source)
                        description = (
                            f'Confirm renaming {old_name_val} ({old_type}) '
                            f'at {ea.offset:#x} to {new_name}?'
                        )
                        if not backend.confirm_overwrite(description):
                            results.append({
                                'addr': f'{ea.offset:#x}',
                                'old_name': old_name_val,
                                'new_name': new_name,
                                'error': 'skipped: user declined overwrite of higher-priority symbol',
                            })
                            continue
                    sym.setName(new_name, ai_src)
                    results.append({
                        'addr': f'{ea.offset:#x}',
                        'old_name': old_name_val,
                        'new_name': new_name,
                        'error': None,
                    })
                else:
                    # No symbol: create a user label in the global namespace
                    symtab.createLabel(
                        ea, new_name, program.getGlobalNamespace(), ai_src
                    )
                    results.append({
                        'addr': f'{ea.offset:#x}',
                        'old_name': None,
                        'new_name': new_name,
                        'error': None,
                    })
            except Exception as e:
                results.append({
                    'addr': addr,
                    'name': name,
                    'new_name': new_name,
                    'error': str(e),
                })

    return results


# ---------------------------------------------------------------------------
# update_vars
# ---------------------------------------------------------------------------


async def update_vars(
    backend: GhidraBackend,
    function_name: str,
    variables_to_update: Dict[str, Dict[str, str]],
) -> dict:
    """Rename/retype variables in a function. Keeps existing dict-of-dicts interface.

    THIS MODIFIES THE GHIDRA DATABASE.

    PARAMETERS:
    - function_name: Name of the function containing the variables
    - variables_to_update: Dict mapping old_name -> {new_name?, new_type?}

    TYPE NOTE: Labels don't have types - type changes are ignored for labels.

    EXAMPLE:
      update_vars(
        backend,
        function_name="main",
        variables_to_update={
          "local_8": {"new_name": "buffer", "new_type": "char *"},
          "param_1": {"new_name": "argc"}
        }
      )

    RETURNS: Structured dict with keys: function, addr, results (list of per-variable
    dicts with var/new_name/new_type/error), error (function-level or null)."""
    backend.begin_batch()
    try:
        return await anyio.to_thread.run_sync(
            lambda: _update_vars_sync(backend, function_name, variables_to_update)
        )
    finally:
        backend.end_batch()


def _update_vars_sync(
    backend: GhidraBackend,
    function_name: str,
    variables_to_update: Dict[str, Dict[str, str]],
) -> dict:
    """Sync implementation — runs in thread pool."""
    if not variables_to_update:
        return VarUpdateReport(
            function=function_name,
            addr=None,
            results=[],
            error='No variables were provided to update',
        ).model_dump()

    try:
        func = _get_function(backend, name=function_name)
        dec_func = backend.get_decompiled_func(func=func)
    except Exception as e:
        # Function-level failure (not found, or resolved but won't decompile):
        # top-level error, empty results, null addr.
        return VarUpdateReport(
            function=function_name,
            addr=None,
            results=[],
            error=str(e),
        ).model_dump()

    addr_hex = f'{func.getEntryPoint().offset:#x}'
    results: list[VarUpdate] = []

    with backend.create_transaction(
        f'Update {len(variables_to_update)} function variables'
    ):
        for var_name, new_vals in variables_to_update.items():
            new_name = new_vals.get('new_name')
            new_type = new_vals.get('new_type')
            item = VarUpdate(var=var_name, new_name=new_name, new_type=new_type)

            if not new_name and not new_type:
                item.error = 'at least one of new_name or new_type is required'
            else:
                ghidra_var = dec_func.get_symbol(var_name)
                existing_var = dec_func.get_symbol(new_name) if new_name else None

                if ghidra_var and not existing_var:
                    try:
                        # Pass through the original symbol's name when only the
                        # type is changing, so update() doesn't try to rename.
                        # GhidraNamedEntity is abstract; concrete subclasses
                        # (GhidraVariable, GhidraParameter) all expose `.name`.
                        effective_name = (
                            new_name if new_name else ghidra_var.name  # type: ignore[attr-defined]
                        )
                        ghidra_var.update(
                            new_name=effective_name,
                            new_type=new_type or '',
                            source_type=_ai_source_type(),
                        )
                    except Exception as e:
                        item.error = str(e)
                elif not ghidra_var:
                    item.error = f"Variable not found in function '{function_name}'"
                else:
                    # ghidra_var exists AND existing_var (new name) also exists
                    item.error = f"target name '{new_name}' already exists"

            results.append(item)

    return VarUpdateReport(
        function=function_name,
        addr=addr_hex,
        results=results,
        error=None,
    ).model_dump()


# ---------------------------------------------------------------------------
# set_comments (MERGED: disasm + decompiler + function)
# ---------------------------------------------------------------------------


async def set_comments(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Set comment(s). MERGED 3→1. Each item: {comment, kind?, addr?, name?, line?}

    kind values and their effect:
    - 'disasm'     → EOL comment at addr (requires addr)
    - 'decompiler' → pre-comment at line in function (requires line and addr or name)
    - 'function'   → plate comment on function (requires addr or name)
    - 'both'       (default) → disasm comment at addr; ALSO decompiler comment IF line provided

    RETURNS: list of dicts, each with:
    - kind: the effective kind used
    - addr: address string
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    backend.begin_batch()
    try:
        return await anyio.to_thread.run_sync(
            lambda: _set_comments_sync(backend, items)
        )
    finally:
        backend.end_batch()


def _set_comments_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []

    with backend.create_transaction('batch set_comments'):
        for item in items:
            comment: str = item.get('comment', '') or ''
            kind: str = item.get('kind', 'both') or 'both'
            addr: str = item.get('addr', '') or ''
            name: str = item.get('name', '') or ''
            line: int | None = item.get('line', None)

            try:
                _validate_comment_item(kind, addr, name, line)

                if kind == 'disasm':
                    msg = _set_eol_comment(backend, addr, comment)
                    results.append({
                        'kind': kind,
                        'addr': addr,
                        'message': msg,
                        'error': None,
                    })

                elif kind == 'decompiler':
                    assert line is not None  # validated above
                    msg = _set_decompiler_pre_comment(
                        backend, line, comment, addr=addr, name=name
                    )
                    results.append({
                        'kind': kind,
                        'addr': addr,
                        'name': name,
                        'line': line,
                        'message': msg,
                        'error': None,
                    })

                elif kind == 'function':
                    msg = _set_function_plate_comment(
                        backend, comment, addr=addr, name=name
                    )
                    results.append({
                        'kind': kind,
                        'addr': addr,
                        'name': name,
                        'message': msg,
                        'error': None,
                    })

                elif kind == 'both':
                    messages: list[str] = []
                    # Always set disasm at addr
                    msg_disasm = _set_eol_comment(backend, addr, comment)
                    messages.append(msg_disasm)
                    # Optionally set decompiler if line is provided
                    if line is not None:
                        msg_dec = _set_decompiler_pre_comment(
                            backend, line, comment, addr=addr, name=name
                        )
                        messages.append(msg_dec)
                    results.append({
                        'kind': kind,
                        'addr': addr,
                        'name': name,
                        'line': line,
                        'message': '; '.join(messages),
                        'error': None,
                    })

                else:
                    raise GhidraError(
                        f"Invalid kind '{kind}'. Must be one of: disasm, decompiler, function, both"
                    )

            except Exception as e:
                results.append({
                    'kind': kind,
                    'addr': addr,
                    'name': name,
                    'error': str(e),
                })

    return results


def _validate_comment_item(kind: str, addr: str, name: str, line: int | None) -> None:
    """Validate required fields for each comment kind. Raises GhidraError on violation."""
    if kind == 'disasm':
        if not addr:
            raise GhidraError("kind='disasm' requires addr")
    elif kind == 'decompiler':
        if line is None:
            raise GhidraError("kind='decompiler' requires line")
        if not addr and not name:
            raise GhidraError("kind='decompiler' requires addr or name")
    elif kind == 'function':
        if not addr and not name:
            raise GhidraError("kind='function' requires addr or name")
    elif kind == 'both':
        if not addr:
            raise GhidraError("kind='both' requires addr")
    # else: unknown kind, caught in caller


# ---------------------------------------------------------------------------
# get_comment
# ---------------------------------------------------------------------------


async def get_comment(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Get function comment(s). Each item: {addr?, name?}. Batched.

    RETURNS: list of dicts, each with:
    - name: function name
    - addr: function entry point address
    - comment: plate comment text (may be empty string)
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _get_comment_sync(backend, items))


def _get_comment_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for item in items:
        addr: str = item.get('addr', '') or ''
        name: str = item.get('name', '') or ''
        try:
            func = _get_function(backend, addr=addr, name=name)
            results.append({
                'name': func.getName(),
                'addr': f'{func.getEntryPoint().offset:#x}',
                'comment': func.getComment() or '',
                'error': None,
            })
        except Exception as e:
            results.append({'addr': addr, 'name': name, 'error': str(e)})
    return results


# ---------------------------------------------------------------------------
# set_prototype
# ---------------------------------------------------------------------------


async def set_prototype(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Set function prototype(s). Each item: {addr, prototype}. Batched.

    THIS MODIFIES THE GHIDRA DATABASE.

    PARAMETERS per item:
    - addr: hex address of function (required)
    - prototype: new signature in C style (e.g., "int main(int argc, char **argv)")

    The old signature is saved in the function comment for reference.

    RETURNS: list of dicts, each with:
    - addr: function address
    - name: function name
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    backend.begin_batch()
    try:
        return await anyio.to_thread.run_sync(
            lambda: _set_prototype_sync(backend, items)
        )
    finally:
        backend.end_batch()


def _set_prototype_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser
    from ghidra.util.task import ConsoleTaskMonitor

    results: list[dict] = []

    with backend.create_transaction('batch set_prototype'):
        for item in items:
            addr: str = item.get('addr', '') or ''
            prototype: str = item.get('prototype', '') or ''
            try:
                if not addr:
                    raise GhidraError('addr is required')
                if not prototype:
                    raise GhidraError('prototype is required')

                func = _get_function(backend, addr=addr)
                dec_func = backend.get_decompiled_func(func=func)
                orig_sig = dec_func.signature

                orig_comment = func.getComment() or ''
                new_comment = f'{orig_comment}\n\nMCP: Updating signature from:\n  {orig_sig}\nto:\n  {prototype}'
                func.setComment(new_comment)

                dtm = backend.program.getDataTypeManager()
                # DataTypeManagerService only available in plugin mode; use None
                # otherwise. (FunctionSignatureParser accepts None for headless.)
                dtms = None
                parser = FunctionSignatureParser(dtm, dtms)
                ea = _get_address(backend, addr)
                sig = parser.parse(None, prototype)  # type: ignore[arg-type]

                cmd = ApplyFunctionSignatureCmd(ea, sig, _ai_source_type())
                if cmd.applyTo(backend.program, ConsoleTaskMonitor()):  # type: ignore[no-untyped-call]
                    results.append({
                        'addr': f'{func.getEntryPoint().offset:#x}',
                        'name': func.getName(),
                        'error': None,
                    })
                else:
                    raise GhidraError(
                        f'Error applying prototype for function {func.getName()} @ {func.getEntryPoint().offset:#x}.'
                    )
            except Exception as e:
                results.append({'addr': addr, 'prototype': prototype, 'error': str(e)})

    return results


# ---------------------------------------------------------------------------
# patch
# ---------------------------------------------------------------------------


async def patch(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Patch instruction(s). Each item: {addr, hex_bytes}. Batched.

    THIS MODIFIES THE GHIDRA DATABASE.

    PARAMETERS per item:
    - addr: hex address (e.g., "401000")
    - hex_bytes: new bytes as hex string (e.g., "90" for NOP, "EB05" for short jump)

    BEHAVIOR: Clears existing code unit, writes bytes, re-disassembles.

    RETURNS: list of dicts, each with:
    - addr: patched address
    - error: null on success, error message string on failure"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _patch_sync(backend, items))


def _patch_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    from ghidra.program.disassemble import Disassembler
    from ghidra.util.task import TaskMonitor

    results: list[dict] = []

    with backend.create_transaction('batch patch'):
        for item in items:
            addr: str = item.get('addr', '') or ''
            hex_bytes: str = item.get('hex_bytes', '') or ''
            try:
                if not addr:
                    raise GhidraError('addr is required')
                if not hex_bytes:
                    raise GhidraError('hex_bytes is required')

                target_addr = _get_address(backend, addr)
                new_bytes = bytes.fromhex(hex_bytes)
                program = backend.program
                mem = program.getMemory()

                # Clear existing instructions before patching
                listing = program.getListing()
                code_unit = listing.getCodeUnitAt(target_addr)
                if code_unit:
                    listing.clearCodeUnits(
                        target_addr, target_addr.add(len(new_bytes) - 1), False
                    )

                # Write the bytes
                mem.setBytes(target_addr, new_bytes)

                disassembler = Disassembler.getDisassembler(
                    program, TaskMonitor.DUMMY, None
                )
                disassembler.disassemble(target_addr, None)

                results.append({'addr': f'0x{target_addr}', 'error': None})
            except Exception as e:
                results.append({'addr': addr, 'hex_bytes': hex_bytes, 'error': str(e)})

    return results


# ---------------------------------------------------------------------------
# begin_trans / end_trans
# ---------------------------------------------------------------------------


async def begin_trans(backend: GhidraBackend, description: str) -> dict:
    """Start a manual transaction for multiple modifications.

    RETURNS: Dict with keys: transaction_id (int), message (str), error (null or str).

    WHEN TO USE:
    - Most modification tools handle transactions internally.
    - Only use manual transactions when making MULTIPLE modifications that should be atomic.
    - If you're calling ONE modification tool, you don't need this.

    EXAMPLE:
      tx = begin_trans(backend, "Rename related functions")
      rename(backend, [...])
      end_trans(backend, tx['transaction_id'], commit=True)"""
    return await anyio.to_thread.run_sync(
        lambda: _begin_trans_sync(backend, description)
    )


def _begin_trans_sync(backend: GhidraBackend, description: str) -> dict:
    """Sync implementation — runs in thread pool."""
    try:
        tx_id = backend.program.startTransaction(description)
        return {
            'transaction_id': tx_id,
            'message': f'Transaction started with ID {tx_id}',
            'error': None,
        }
    except Exception as e:
        return {
            'transaction_id': None,
            'message': str(e),
            'error': str(e),
        }


async def end_trans(
    backend: GhidraBackend, transaction_id: int, commit: bool = True
) -> dict:
    """End a manual transaction started with begin_trans.

    PARAMETERS:
    - transaction_id: ID returned from begin_trans
    - commit: True to save changes, False to discard/rollback

    RETURNS: Dict with keys: transaction_id (int), committed (bool), message (str),
    error (null on success, str on failure).

    WHEN TO USE: Only after begin_trans for multi-modification workflows.
    Single modification tools handle transactions internally."""
    return await anyio.to_thread.run_sync(
        lambda: _end_trans_sync(backend, transaction_id, commit)
    )


def _end_trans_sync(backend: GhidraBackend, transaction_id: int, commit: bool) -> dict:
    """Sync implementation — runs in thread pool."""
    try:
        backend.program.endTransaction(transaction_id, commit)
        committed_str = 'committed' if commit else 'rolled back'
        return {
            'transaction_id': transaction_id,
            'committed': commit,
            'message': f'Transaction {transaction_id} {committed_str}',
            'error': None,
        }
    except Exception as e:
        return {
            'transaction_id': transaction_id,
            'committed': False,
            'message': str(e),
            'error': str(e),
        }
