"""Core read-only tools: list, cursor, context, funcs.

All functions take ``backend: GhidraBackend`` as their first argument.
These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.
"""

from __future__ import annotations

import sys
from typing import (
    Annotated,
    Any,
    Callable,
    cast,
    Dict,
    Iterable,
    Sequence,
    TYPE_CHECKING,
    TypeVar,
    Union,
)

import anyio
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import Field

from mcpyghidra.backend import GhidraBackend, GhidraError
from mcpyghidra.models import (
    AnalysisState,
    ApplicationInfo,
    ArchitectureInfo,
    BinaryContext,
    CurrentLocation,
    EntryTypes,
    FunctionInfo,
    ListResult,
    MemoryLayout,
    page_limit,
    ProgramInfo,
    ResultPageInfo,
)

if sys.version_info >= (3, 12):
    from mcpyghidra.custom_types_312 import JsonValueTypes
else:
    from mcpyghidra.custom_types_p312 import JsonValueTypes

if TYPE_CHECKING:
    from ghidra.program.model.address import GenericAddress
    from ghidra.program.model.listing import Function


T = TypeVar('T')


# ---------------------------------------------------------------------------
# Internal sentinel used by _tool_result_list_formatter to skip an item
# ---------------------------------------------------------------------------


class _Skip(Exception): ...


# ---------------------------------------------------------------------------
# Pagination helper (mirrors paginate_with_total in mcpserver.py)
# ---------------------------------------------------------------------------


def _paginate_with_total(
    items: Iterable[T],
    offset: int = 0,
    limit: int | None = None,
) -> tuple[list[T], int, int, int]:
    """Return (page, total, start, stop) for the given slice."""
    if not isinstance(items, Sequence):
        items = list(items)
    total = len(items)
    start = max(0, offset)
    if limit is None or limit < 0:
        stop = total
    else:
        stop = min(start + limit, total)
    return list(items[start:stop]), total, start, stop


# ---------------------------------------------------------------------------
# Private helpers (module-level equivalents of GhidraMcpServer private methods)
# ---------------------------------------------------------------------------


def _get_address(backend: GhidraBackend, addr: Union[str, int]) -> 'GenericAddress':
    """Parse a hex address string or integer into a Ghidra GenericAddress."""
    addr_str = addr if isinstance(addr, str) else hex(addr)
    return backend.program.getAddressFactory().getAddress(addr_str)


def _get_function(
    backend: GhidraBackend,
    addr: str | None = '',
    name: str | None = '',
) -> 'Function':
    """Resolve a Ghidra Function by address or name.

    Raises GhidraError if the function cannot be found or neither argument
    is provided.
    """
    if addr:
        ea = _get_address(backend, addr)
        func: Function = backend.program.getFunctionManager().getFunctionContaining(ea)
        if func is None:
            raise GhidraError(f'ERROR: No function found at address {ea.offset:#x}.')
    elif name:
        func = backend.flat_api.getFunction(name)
        if func is None:
            raise GhidraError(f'ERROR: No function found with name {name}.')
    else:
        raise GhidraError('ERROR: Either a function name or address must be provided.')
    return func


def _get_func_ea(
    backend: GhidraBackend,
    addr: str | None = '',
    name: str | None = '',
) -> 'GenericAddress':
    """Resolve to the entry address of the function matching addr or name."""
    func = _get_function(backend, addr, name)
    return func.getEntryPoint()


def _tool_result_list_formatter(
    results_heading: str,
    entry_type: EntryTypes,
    entry_proc: Callable[[T], Dict[str, JsonValueTypes]],
    entries: Iterable[T],
    offset: int,
    limit: int = page_limit,
) -> ListResult:
    """Build a paginated ListResult from an iterable of raw Ghidra objects."""
    results: list[Dict[str, JsonValueTypes]] = []
    entries_page, total, start, stop = _paginate_with_total(entries, offset, limit)
    for entry in entries_page:
        try:
            result_entry = entry_proc(entry)
            result_entry['result_index'] = offset + len(results)
            result_entry['page_pos'] = len(results)
            results.append(result_entry)
        except _Skip:
            continue
    if not results:
        if offset > total:
            raise ToolError(
                f'No {results_heading} found because offset ({offset}) exceeds total ({total})'
            )
        return ListResult(
            summary=f'No {results_heading} found starting at position {offset}',
            entry_type=entry_type,
            schema_version=1,
            page_info=ResultPageInfo(
                offset=offset,
                limit=limit,
                num_returned=0,
                total_count=total,
                has_more=False,
                next_offset=None,
            ),
            items=[],
        )
    return ListResult(
        summary=f'{results_heading} {start}-{stop - 1} of {total}',
        entry_type=entry_type,
        schema_version=1,
        page_info=ResultPageInfo(
            offset=start,
            limit=limit,
            num_returned=stop - start,
            total_count=total,
            has_more=stop < total,
            next_offset=stop if (stop < total) else None,
        ),
        items=results,
    )


def _get_current_location(backend: GhidraBackend) -> CurrentLocation:
    """Return the current location, headless-aware.

    In headless mode falls back to the program entry point.
    In GUI mode uses the CodeViewerService cursor position.
    """
    program = backend.program

    if backend.is_headless:
        try:
            entry_it = program.getSymbolTable().getExternalEntryPointIterator()
            if entry_it.hasNext():
                entry_addr = entry_it.next()
            else:
                func_mgr = program.getFunctionManager()
                funcs = func_mgr.getFunctions(True)
                if funcs.hasNext():
                    entry_addr = funcs.next().getEntryPoint()
                else:
                    entry_addr = program.getImageBase()

            cur_loc = CurrentLocation(addr=f'{entry_addr.offset:#x}')
            func = cast(
                'Function | None',
                program.getFunctionManager().getFunctionContaining(entry_addr),
            )
            if func:
                dec_func = backend.get_decompiled_func(func=func)
                cur_loc.function = FunctionInfo(
                    name=dec_func.name,
                    entrypoint=dec_func.entrypoint,
                    signature=dec_func.signature,
                )
            return cur_loc
        except Exception:
            return CurrentLocation(addr=f'{program.getImageBase().offset:#x}')

    # GUI mode — use CodeViewerService
    from ghidra.app.services import CodeViewerService
    from ghidra.program.util import ProgramLocation as _ProgramLocation

    # Guard: confirm we have a current program before reaching for GUI services.
    backend.flat_api.getCurrentProgram()
    # Reach the code viewer via plugin_tool if available
    # PluginBackend exposes plugin_tool as self._tool; we avoid coupling to the
    # concrete class here by catching AttributeError.
    tool = getattr(backend, '_tool', None)
    if tool is None:
        return CurrentLocation(addr=f'{program.getImageBase().offset:#x}')

    code_viewer: Any = tool.getService(CodeViewerService.class_)
    if code_viewer is None:
        return CurrentLocation(addr=f'{program.getImageBase().offset:#x}')

    location = cast('_ProgramLocation | None', code_viewer.getCurrentLocation())
    if location is None:
        return CurrentLocation(addr=f'{program.getImageBase().offset:#x}')

    cur_loc = CurrentLocation(addr=f'{location.getAddress().offset:#x}')
    func = cast(
        'Function | None',
        program.getFunctionManager().getFunctionContaining(location.getAddress()),
    )
    if func:
        dec_func = backend.get_decompiled_func(func=func)
        cur_loc.function = FunctionInfo(
            name=dec_func.name,
            entrypoint=dec_func.entrypoint,
            signature=dec_func.signature,
        )
    return cur_loc


def _normalize_format(format_str: str) -> str:
    """Normalise Ghidra's verbose format string to a short label."""
    if 'Portable Executable' in format_str or 'PE' in format_str:
        return 'PE'
    elif 'ELF' in format_str:
        return 'ELF'
    elif 'Mach-O' in format_str or 'Mac OS X' in format_str:
        return 'Mach-O'
    elif 'COFF' in format_str:
        return 'COFF'
    return format_str


# ---------------------------------------------------------------------------
# Sub-dispatchers for list_entries
# ---------------------------------------------------------------------------


def _list_functions(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
    match_filter: str = '',
) -> ListResult:
    from ghidra.program.model.listing import Function as _Function

    def process_func(func: '_Function') -> Dict[str, JsonValueTypes]:
        return {
            'type': 'function',
            'name': func.getName(),
            'addr': f'{func.getEntryPoint().offset:#x}',
        }

    match_info = f" matching '{match_filter}'" if match_filter else ''
    return _tool_result_list_formatter(
        f'Functions{match_info}',
        'function',
        process_func,
        filter(
            lambda f: (
                (match_filter.lower() in f.name.lower()) if match_filter else True
            ),
            cast(
                Iterable['_Function'],
                backend.program.getFunctionManager().getFunctions(True),
            ),
        ),
        offset,
        limit,
    )


def _list_segments(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    from ghidra.program.model.mem import MemoryBlock as _MemoryBlock

    def process_segment(block: '_MemoryBlock') -> Dict[str, JsonValueTypes]:
        return {
            'type': 'memory_segment',
            'name': block.getName(),
            'start': f'{block.getStart().offset:#x}',
            'end': f'{block.getEnd().offset:#x}',
        }

    return _tool_result_list_formatter(
        'Memory Segments',
        'memory_segment',
        process_segment,
        backend.program.getMemory().getBlocks(),
        offset,
        limit,
    )


def _list_imports(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    from ghidra.program.model.symbol import Symbol as _Symbol

    def process_symbol(entry: '_Symbol') -> Dict[str, JsonValueTypes]:
        return {
            'type': 'import',
            'name': entry.name,
            'addr': f'{entry.address.offset:#x}',
            'symbol_type': str(entry.getSymbolType()),
        }

    return _tool_result_list_formatter(
        'Imported Symbols',
        'import',
        process_symbol,
        backend.program.getSymbolTable().getExternalSymbols(),
        offset,
        limit,
    )


def _list_exports(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    from ghidra.program.model.symbol import Symbol as _Symbol

    def process_symbol(entry: '_Symbol') -> Dict[str, JsonValueTypes]:
        return {
            'type': 'export',
            'name': entry.name,
            'addr': f'{entry.address.offset:#x}',
            'symbol_type': str(entry.getSymbolType()),
        }

    return _tool_result_list_formatter(
        'Exported Symbols',
        'export',
        process_symbol,
        backend.program.getSymbolTable().getAllSymbols(True),
        offset,
        limit,
    )


def _list_strings(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
    match_filter: str = '',
) -> ListResult:
    data_iter = backend.program.getListing().getDefinedData(True)

    def string_data_filter(data: Any) -> bool:
        if data and data.hasStringValue():
            if match_filter:
                data_string = str(data.getValue()) if (data and data.getValue()) else ''
                return match_filter.lower() in data_string.lower()
            return True
        return False

    def process_string(entry: Any) -> Dict[str, JsonValueTypes]:
        value = (
            str(entry.getValue())
            if (entry and entry.hasStringValue() and entry.getValue())
            else ''
        )
        return {
            'type': 'string',
            'value': repr(value),
            'addr': f'{entry.getAddress().offset:#x}',
        }

    matching_info = f' matching {repr(match_filter)}' if match_filter else ''
    return _tool_result_list_formatter(
        f'Strings{matching_info}',
        'string',
        process_string,
        filter(string_data_filter, cast(Iterable[Any], data_iter)),
        offset,
        limit,
    )


def _list_classes(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    from ghidra.program.model.symbol import SymbolType as _SymbolType

    def process_symbol(entry: Any) -> Dict[str, JsonValueTypes]:
        return {
            'type': 'class',
            'name': entry.getName(True),
            'addr': f'{entry.getAddress().offset:#x}',
            'symbol_type': str(entry.getSymbolType()),
        }

    return _tool_result_list_formatter(
        'Classes',
        'class',
        process_symbol,
        filter(
            lambda s: s.getSymbolType() == _SymbolType.CLASS,
            backend.program.getSymbolTable().getAllSymbols(True),
        ),
        offset,
        limit,
    )


def _list_namespaces(
    backend: GhidraBackend,
    offset: int = 0,
    limit: int = page_limit,
) -> ListResult:
    from ghidra.program.model.symbol import SymbolType as _SymbolType

    def process_symbol(entry: Any) -> Dict[str, JsonValueTypes]:
        return {
            'type': 'namespace',
            'name': entry.name,
            'addr': f'{entry.address.offset:#x}',
            'symbol_type': str(entry.getSymbolType()),
        }

    return _tool_result_list_formatter(
        'Namespaces',
        'namespace',
        process_symbol,
        filter(
            lambda s: s.getSymbolType() == _SymbolType.NAMESPACE,
            backend.program.getSymbolTable().getAllSymbols(True),
        ),
        offset,
        limit,
    )


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


async def list_entries(
    backend: GhidraBackend,
    entry_type: Annotated[EntryTypes, Field(description='Type of entry to fetch')],
    offset: Annotated[
        str | int | None,
        Field(description='Starting position for pagination (default 0)'),
    ] = 0,
    limit: Annotated[
        int, Field(description='Maximum results to return (default 500)')
    ] = 500,
    match_filter: Annotated[
        str | None,
        Field(
            description='Optionally return only entries containing the filter string in the name'
        ),
    ] = '',
) -> ListResult:
    """Get a paginated list of binary entries by type.

    RETURNS: ListResult with items[], page_info (has_more, next_offset), total_count

    PARAMETERS:
    - entry_type: Type of entry to list
    - offset: Starting position for pagination (default 0)
    - limit: Maximum results to return (default 500)
    - match_filter: Substring filter (works for function, string, and type entry_types)

    VALID entry_type VALUES: function, memory_segment, import, export, string, class, namespace, type

    EXAMPLES:
    - list(entry_type='function') -> first 500 functions
    - list(entry_type='function', limit=50) -> first 50 functions
    - list(entry_type='function', offset=100, limit=50) -> functions 100-149
    - list(entry_type='string', match_filter='error', limit=20) -> first 20 strings containing 'error'
    - list(entry_type='type', match_filter='Point') -> types with 'Point' in name or path"""
    offset = int(offset) if offset else 0
    if offset < 0:
        raise ToolError('offset must be non-negative')
    if limit <= 0:
        raise ToolError('limit must be positive')
    match_filter = match_filter or ''
    return await anyio.to_thread.run_sync(
        lambda: _list_entries_sync(backend, entry_type, offset, limit, match_filter)
    )


def _list_entries_sync(
    backend: GhidraBackend,
    entry_type: EntryTypes,
    offset: int,
    limit: int,
    match_filter: str,
) -> ListResult:
    """Sync implementation — runs in thread pool."""
    if entry_type == 'function':
        return _list_functions(backend, offset, limit, match_filter)
    elif entry_type == 'memory_segment':
        return _list_segments(backend, offset, limit)
    elif entry_type == 'import':
        return _list_imports(backend, offset, limit)
    elif entry_type == 'export':
        return _list_exports(backend, offset, limit)
    elif entry_type == 'string':
        return _list_strings(backend, offset, limit, match_filter)
    elif entry_type == 'class':
        return _list_classes(backend, offset, limit)
    elif entry_type == 'namespace':
        return _list_namespaces(backend, offset, limit)
    elif entry_type == 'type':
        from mcpyghidra.tools.types import list_types_result

        return list_types_result(backend, offset, limit, match_filter)
    else:
        raise ToolError(f'Unsupported entry type: {entry_type}')


async def cursor(backend: GhidraBackend) -> CurrentLocation:
    """Get current cursor position and function info.

    In headless mode falls back to the program entry point (no GUI cursor available).

    RETURNS: CurrentLocation with:
    - addr: Current hex address (e.g., "0x401000")
    - function: FunctionInfo if cursor is inside a function (name, entrypoint, signature), or null

    USE CASE: Find where the user is looking before taking contextual actions."""
    return await anyio.to_thread.run_sync(lambda: _cursor_sync(backend))


def _cursor_sync(backend: GhidraBackend) -> CurrentLocation:
    """Sync implementation — runs in thread pool."""
    return _get_current_location(backend)


async def context(backend: GhidraBackend) -> BinaryContext:
    """Get comprehensive context about the currently open binary.

    RETURNS: BinaryContext with complete information about:
    - current_location: Cursor position and current function
    - program: Binary file details (path, format, size, hash)
    - architecture: Processor, bitness, endianness
    - memory: Address space layout (base, entry point, min/max)
    - analysis: Database path, function count, symbols, analysis state
    - application: RE application name and version"""
    return await anyio.to_thread.run_sync(lambda: _context_sync(backend))


def _context_sync(backend: GhidraBackend) -> BinaryContext:
    """Sync implementation — runs in thread pool."""
    program = backend.program
    current_location = _get_current_location(backend)

    # Program info
    try:
        file_path = program.getExecutablePath()
    except Exception:
        file_path = None

    try:
        file_name = program.getName()
    except Exception:
        file_name = 'unknown'

    try:
        file_format = program.getExecutableFormat()
        file_format = _normalize_format(file_format)
    except Exception:
        file_format = 'unknown'

    file_size = None
    if file_path:
        try:
            import java.io.File

            file_size = int(java.io.File(file_path).length())
        except Exception:
            pass

    try:
        md5 = program.getExecutableMD5()
    except Exception:
        md5 = None

    program_info = ProgramInfo(
        file_path=file_path,
        file_name=file_name,
        file_format=file_format,
        file_size=file_size,
        md5=md5,
    )

    # Architecture info
    try:
        processor = program.getLanguage().getProcessor().toString()
    except Exception:
        processor = 'unknown'

    try:
        bitness = program.getDefaultPointerSize() * 8
    except Exception:
        bitness = 32

    try:
        endianness = 'big' if program.getLanguage().isBigEndian() else 'little'
    except Exception:
        endianness = 'unknown'

    try:
        compiler = program.getCompilerSpec().getCompilerSpecID().getIdAsString()
    except Exception:
        compiler = None

    architecture_info = ArchitectureInfo(
        processor=processor,
        bitness=bitness,
        endianness=endianness,
        compiler=compiler,
    )

    # Memory layout
    try:
        image_base = f'{program.getImageBase().offset:#x}'
    except Exception:
        image_base = '0x0'

    entry_point = '0x0'
    try:
        entry_it = program.getSymbolTable().getExternalEntryPointIterator()
        if entry_it.hasNext():
            entry_point = f'{entry_it.next().offset:#x}'
        else:
            func_mgr = program.getFunctionManager()
            funcs = func_mgr.getFunctions(True)
            if funcs.hasNext():
                first_func = funcs.next()
                entry_point = f'{first_func.getEntryPoint().offset:#x}'
            else:
                entry_point = image_base
    except Exception:
        entry_point = image_base

    try:
        min_address = f'{program.getMinAddress().offset:#x}'
    except Exception:
        min_address = '0x0'

    try:
        max_address = f'{program.getMaxAddress().offset:#x}'
    except Exception:
        max_address = '0xffffffff'

    memory_layout = MemoryLayout(
        image_base=image_base,
        entry_point=entry_point,
        min_address=min_address,
        max_address=max_address,
    )

    # Analysis state
    try:
        database_path = program.getDomainFile().getPathname()
    except Exception:
        database_path = 'unknown'

    try:
        function_count = program.getFunctionManager().getFunctionCount()
    except Exception:
        function_count = 0

    has_debug_symbols = False
    try:
        from ghidra.program.model.symbol import SymbolType as _SymbolType

        symtab = program.getSymbolTable()
        for sym in symtab.getAllSymbols(True):
            if sym.getSymbolType() == _SymbolType.FILE:
                has_debug_symbols = True
                break
    except Exception:
        pass

    has_type_libraries = False
    try:
        dtm = program.getDataTypeManager()
        type_count = dtm.getDataTypeCount(True)
        has_type_libraries = type_count > 100
    except Exception:
        pass

    analysis_state = AnalysisState(
        database_path=database_path,
        function_count=function_count,
        has_debug_symbols=has_debug_symbols,
        has_type_libraries=has_type_libraries,
        analysis_complete=None,
    )

    # Application info
    try:
        from ghidra.framework import Application

        app_name = Application.getName()
        app_version = Application.getApplicationVersion()
    except Exception:
        app_name = 'Ghidra'
        app_version = 'unknown'

    application = ApplicationInfo(name=app_name, version=app_version)

    return BinaryContext(
        current_location=current_location,
        program=program_info,
        architecture=architecture_info,
        memory=memory_layout,
        analysis=analysis_state,
        application=application,
    )


async def funcs(
    backend: GhidraBackend,
    items: list[str],
) -> list[dict]:
    """Get function info by address or name. Accepts a list of addresses or names.

    Each entry in items is either:
    - A hex address (starts with '0x' or is all hex digits) → look up by address
    - A function name string → look up by name

    RETURNS: list of dicts, each with:
    - name, entrypoint, signature: function details (on success)
    - target, error: input target and error message (on failure)"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _funcs_sync(backend, items))


def _funcs_sync(backend: GhidraBackend, items: list[str]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for target in items:
        try:
            stripped = target.strip()
            is_addr = stripped.startswith('0x') or (
                len(stripped) > 0
                and all(c in '0123456789abcdefABCDEF' for c in stripped)
            )
            if is_addr:
                func = _get_function(backend, addr=stripped, name='')
            else:
                func = _get_function(backend, addr='', name=stripped)
            dec_func = backend.get_decompiled_func(func)
            results.append({
                'name': dec_func.name,
                'entrypoint': dec_func.entrypoint,
                'signature': dec_func.signature,
                'error': None,
            })
        except Exception as e:
            results.append({'target': target, 'error': str(e)})
    return results
