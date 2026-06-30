"""Type tools: type_info, list_types_result, create_struct, add_field.

All functions take ``backend: GhidraBackend`` as their first argument.
These are standalone functions — no class needed — registered via the
tool-registration layer in server.py.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

import anyio
from mcp.server.fastmcp.exceptions import ToolError

from mcpyghidra.backend import GhidraBackend
from mcpyghidra.models import (
    EnumValue,
    FieldAdditionResult,
    MemberInfo,
    StructureCreationResult,
    TypeDetails,
    TypeSummary,
)

if TYPE_CHECKING:
    from mcpyghidra.models import ListResult


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _normalize_type_kind(data_type: Any) -> str:
    """Normalize Ghidra type kind to standard values.

    Returns one of: struct, union, enum, typedef, primitive, pointer, array, function, unknown
    """
    from ghidra.program.model.data import (
        Array,
        Enum as GhidraEnum,
        FunctionDefinition,
        Pointer,
        Structure,
        TypeDef,
        Union as GhidraUnion,
    )

    if isinstance(data_type, Structure):
        return 'struct'
    elif isinstance(data_type, GhidraUnion):
        return 'union'
    elif isinstance(data_type, GhidraEnum):
        return 'enum'
    elif isinstance(data_type, TypeDef):
        return 'typedef'
    elif isinstance(data_type, Pointer):
        return 'pointer'
    elif isinstance(data_type, Array):
        return 'array'
    elif isinstance(data_type, FunctionDefinition):
        return 'function'
    else:
        dt_path = str(data_type.getPathName()) if data_type.getPathName() else ''
        if 'BuiltInTypes' in dt_path:
            return 'primitive'
        dt_name = data_type.getName().lower()
        primitives = [
            'int',
            'char',
            'byte',
            'short',
            'long',
            'float',
            'double',
            'void',
            'bool',
            'uint',
            'uchar',
            'ushort',
            'ulong',
            'undefined',
        ]
        if any(prim in dt_name for prim in primitives):
            return 'primitive'
        return 'unknown'


def _get_type_summary(data_type: Any) -> TypeSummary:
    """Create a TypeSummary from a Ghidra DataType."""
    name = data_type.getName()
    full_path = str(data_type.getPathName()) if data_type.getPathName() else name
    kind = _normalize_type_kind(data_type)
    try:
        size = data_type.getLength()
        if size <= 0:
            size = None
    except Exception:
        size = None
    type_string = data_type.getDisplayName()
    return TypeSummary(
        name=name,
        full_path=full_path,
        type_string=type_string,
        kind=kind,
        size=size,
    )


def _get_type_details(data_type: Any) -> TypeDetails:
    """Get detailed information about a Ghidra DataType."""
    from ghidra.program.model.data import (
        Enum as GhidraEnum,
        Structure,
        TypeDef,
        Union as GhidraUnion,
    )

    name = data_type.getName()
    full_path = str(data_type.getPathName()) if data_type.getPathName() else name
    kind = _normalize_type_kind(data_type)
    try:
        size = data_type.getLength()
        if size <= 0:
            size = None
    except Exception:
        size = None
    comment = data_type.getDescription()
    if not comment or str(comment).strip() == '':
        comment = None
    else:
        comment = str(comment)

    members = None
    values = None
    underlying_type = None

    if isinstance(data_type, (Structure, GhidraUnion)):
        members = []
        components = (
            data_type.getComponents() if hasattr(data_type, 'getComponents') else []
        )
        for comp in components:
            comp_dt = comp.getDataType()
            comp_name = comp.getFieldName()
            if not comp_name:
                comp_name = (
                    comp.getDefaultFieldName()
                    if hasattr(comp, 'getDefaultFieldName')
                    else f'field_{comp.getOffset()}'
                )
            members.append(
                MemberInfo(
                    name=comp_name,
                    type_string=comp_dt.getDisplayName(),
                    offset=comp.getOffset(),
                    size=comp.getLength() if comp.getLength() > 0 else None,
                )
            )
    elif isinstance(data_type, GhidraEnum):
        values = []
        enum_names = data_type.getNames()
        if enum_names:
            for enum_name in enum_names:
                enum_val = data_type.getValue(enum_name)
                values.append(EnumValue(name=enum_name, value=int(enum_val)))
    elif isinstance(data_type, TypeDef):
        base_type = data_type.getDataType()
        if base_type:
            underlying_type = base_type.getDisplayName()

    return TypeDetails(
        name=name,
        full_path=full_path,
        type_string=data_type.getDisplayName(),
        kind=kind,
        size=size,
        comment=comment,
        members=members,
        values=values,
        underlying_type=underlying_type,
    )


def _find_data_type(backend: GhidraBackend, type_name: str) -> Any:
    """Find a data type by name (accepts short name or full path).

    Searches across all available data type managers:
    - Program types
    - Built-in types
    - Imported archives (.gdt files)
    """
    all_managers = backend.get_data_type_managers()
    data_types = []
    for dtm in all_managers:
        data_types.extend(dtm.getAllDataTypes())

    for dt in data_types:
        if dt.getName() == type_name:
            return dt
        path = dt.getPathName()
        if path and str(path) == type_name:
            return dt

    for dt in data_types:
        path = dt.getPathName()
        if path and str(path).endswith('/' + type_name):
            return dt

    return None


def _build_type_map(dtm: Any) -> dict:
    """Build type_map for common C types using the given DataTypeManager for pointer sizing."""
    from ghidra.program.model.data import (
        ByteDataType,
        CharDataType,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
        LongDataType,
        LongLongDataType,
        PointerDataType,
        ShortDataType,
        SignedByteDataType,
        UnsignedCharDataType,
        UnsignedIntegerDataType,
        UnsignedLongDataType,
        UnsignedLongLongDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    return {
        'int': IntegerDataType.dataType,
        'char': CharDataType.dataType,
        'short': ShortDataType.dataType,
        'long': LongDataType.dataType,
        'byte': ByteDataType.dataType,
        'unsigned int': UnsignedIntegerDataType.dataType,
        'unsigned char': UnsignedCharDataType.dataType,
        'unsigned short': UnsignedShortDataType.dataType,
        'unsigned long': UnsignedLongDataType.dataType,
        'int8_t': SignedByteDataType.dataType,
        'int16_t': ShortDataType.dataType,
        'int32_t': IntegerDataType.dataType,
        'int64_t': LongLongDataType.dataType,
        'uint8_t': UnsignedCharDataType.dataType,
        'uint16_t': UnsignedShortDataType.dataType,
        'uint32_t': UnsignedIntegerDataType.dataType,
        'uint64_t': UnsignedLongLongDataType.dataType,
        'float': FloatDataType.dataType,
        'double': DoubleDataType.dataType,
        'void *': PointerDataType(VoidDataType.dataType),
        'void*': PointerDataType(VoidDataType.dataType),
        'char *': PointerDataType(CharDataType.dataType),
        'char*': PointerDataType(CharDataType.dataType),
    }


def _resolve_field_type(field_type_str: str, dtm: Any, type_map: dict) -> Any:
    """Resolve a C type string to a Ghidra DataType.

    Returns None if the type cannot be resolved.
    """
    from ghidra.program.model.data import CategoryPath, PointerDataType, VoidDataType

    if field_type_str in type_map:
        return type_map[field_type_str]

    field_dt = dtm.getDataType('/' + field_type_str)
    if field_dt is None and '/' not in field_type_str:
        field_dt = dtm.getDataType(CategoryPath('/'), field_type_str)

    if field_dt is None and '*' in field_type_str:
        field_dt = PointerDataType(VoidDataType.dataType)

    return field_dt


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


def _iter_type_summaries(
    backend: GhidraBackend,
    pattern: str | None,
) -> list[TypeSummary]:
    """Enumerate all types, optionally filtered by pattern (case-insensitive substring).

    Strips leading/trailing * from pattern (glob-style callers). Returns sorted list.
    """
    if pattern:
        pattern = pattern.strip('*')

    all_managers = backend.get_data_type_managers()

    results: list[TypeSummary] = []
    for dtm in all_managers:
        all_type_iter = dtm.getAllDataTypes()
        for data_type in all_type_iter:
            name = data_type.getName()
            full_path = (
                str(data_type.getPathName()) if data_type.getPathName() else name
            )
            if pattern:
                pattern_lower = pattern.lower()
                if (
                    pattern_lower not in name.lower()
                    and pattern_lower not in full_path.lower()
                ):
                    continue
            results.append(_get_type_summary(data_type))

    results.sort(key=lambda s: s.name.lower())
    return results


def list_types_result(
    backend: GhidraBackend,
    offset: int,
    limit: int,
    match_filter: str = '',
) -> 'ListResult':
    """Enumerate types as a paginated ListResult (backs list(entry_type='type'))."""
    from mcpyghidra.tools.core import _tool_result_list_formatter

    summaries = _iter_type_summaries(backend, match_filter or None)

    def proc(ts: 'TypeSummary') -> dict:
        return {
            'type': 'type',
            'name': ts.name,
            'full_path': ts.full_path,
            'type_string': ts.type_string,
            'kind': ts.kind,
            'size': ts.size,
        }

    return _tool_result_list_formatter('types', 'type', proc, summaries, offset, limit)


async def type_info(
    backend: GhidraBackend,
    items: list[str],
) -> list[dict]:
    """Get type details. Batched: accepts list of type names.

    Each item in items is a type name (short name or full path).

    RETURNS: list of dicts, each with TypeDetails fields (on success) or
    - target, error: input target and error message (on failure)"""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _type_info_sync(backend, items))


def _type_info_sync(backend: GhidraBackend, items: list[str]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    results: list[dict] = []
    for type_name in items:
        try:
            if not type_name or not type_name.strip():
                raise ToolError('type_name cannot be empty')
            data_type = _find_data_type(backend, type_name)
            if data_type is None:
                raise ToolError(f"Type '{type_name}' not found")
            details = _get_type_details(data_type)
            out = details.model_dump()
            out['error'] = None
            results.append(out)
        except Exception as e:
            results.append({'target': type_name, 'error': str(e)})
    return results


async def create_struct(
    backend: GhidraBackend,
    name: str,
    size: int = 0,
    fields: list[dict] | None = None,
    packed: bool = False,
) -> StructureCreationResult:
    """Create a new structure type in the Ghidra type database.

    Use this tool to define custom structures that match memory layouts
    discovered during analysis. After creation, use update_vars
    to apply the structure type to variables.

    Returns:
        StructureCreationResult with name, size, created flag, and message.

    Example - Empty struct:
        create_struct(name="NetworkPacket", size=64)

    Example - Struct with fields:
        create_struct(
            name="NetworkPacket",
            fields=[
                {"name": "header_ptr", "type": "void *", "offset": 0},
                {"name": "length", "type": "int", "offset": 8},
                {"name": "flags", "type": "unsigned int", "offset": 12}
            ]
        )

    Example - Packed struct:
        create_struct(name="PackedData", size=16, packed=True)"""
    return await anyio.to_thread.run_sync(
        lambda: _create_struct_sync(backend, name, size, fields, packed)
    )


def _create_struct_sync(
    backend: GhidraBackend,
    name: str,
    size: int,
    fields: list[dict] | None,
    packed: bool,
) -> StructureCreationResult:
    """Sync implementation — runs in thread pool."""
    from ghidra.program.model.data import (
        CategoryPath,
        DataTypeConflictHandler,
        StructureDataType,
    )

    dtm = backend.program.getDataTypeManager()

    existing = dtm.getDataType(CategoryPath('/'), name)
    if existing is not None:
        return StructureCreationResult(
            name=name,
            size=existing.getLength(),
            created=False,
            message=f"Structure '{name}' already exists",
        )

    min_size = size
    if min_size == 0 and fields:
        for f in fields:
            field_offset = f.get('offset', 0)
            estimated_size = 8 if '*' in f.get('type', '') else 4
            min_size = max(min_size, field_offset + estimated_size)

    struct = StructureDataType(CategoryPath('/'), name, min_size if min_size > 0 else 0)
    if packed:
        struct.setPackingEnabled(True)
        struct.setExplicitPackingValue(1)

    type_map = _build_type_map(dtm)

    if fields:
        for f in fields:
            field_type_str = f.get('type', '')
            field_name = f.get('name', '')
            field_offset = f.get('offset', 0)
            field_comment = f.get('comment', '')

            field_type = _resolve_field_type(field_type_str, dtm, type_map)
            if field_type is not None:
                try:
                    struct.replaceAtOffset(
                        field_offset,
                        field_type,
                        field_type.getLength(),
                        field_name,
                        field_comment,
                    )
                except Exception:
                    backend.log(
                        'warn',
                        f'Failed to add field {field_name} at offset {field_offset}',
                    )
            else:
                backend.log(
                    'warn',
                    f"Could not resolve type '{field_type_str}' for field {field_name}",
                )

    with backend.create_transaction('Create struct'):
        dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)

    return StructureCreationResult(
        name=name,
        size=struct.getLength(),
        created=True,
        message=f"Structure '{name}' created successfully",
    )


async def add_field(
    backend: GhidraBackend,
    items: list[dict],
) -> list[dict]:
    """Add field(s) to struct. Batched: each item {struct_name, field_name, field_type, offset, comment?}.

    If a field already exists at the specified offset, it will be replaced.
    If the structure is not large enough, it will be expanded automatically.

    RETURNS: list of dicts, each with FieldAdditionResult fields."""
    if not isinstance(items, list):
        items = [items]
    return await anyio.to_thread.run_sync(lambda: _add_field_sync(backend, items))


def _add_field_sync(backend: GhidraBackend, items: list[dict]) -> list[dict]:
    """Sync implementation — runs in thread pool."""
    from ghidra.program.model.data import CategoryPath, DataTypeConflictHandler

    results: list[dict] = []
    dtm = backend.program.getDataTypeManager()
    type_map = _build_type_map(dtm)

    with backend.create_transaction('batch add_field'):
        for item in items:
            struct_name = item.get('struct_name', '')
            field_name = item.get('field_name', '')
            field_type_str = item.get('field_type', '')
            offset = item.get('offset', 0)
            comment = item.get('comment', '')

            struct = dtm.getDataType(CategoryPath('/'), struct_name)
            if struct is None:
                results.append(
                    FieldAdditionResult(
                        struct_name=struct_name,
                        field_name=field_name,
                        offset=offset,
                        size=0,
                        success=False,
                        message=f"Structure '{struct_name}' not found",
                    ).model_dump()
                )
                continue

            field_dt = _resolve_field_type(field_type_str, dtm, type_map)
            if field_dt is None:
                results.append(
                    FieldAdditionResult(
                        struct_name=struct_name,
                        field_name=field_name,
                        offset=offset,
                        size=0,
                        success=False,
                        message=f'Unknown type: {field_type_str}',
                    ).model_dump()
                )
                continue

            try:
                struct_copy = struct.copy(dtm)
                needed_size = offset + field_dt.getLength()
                if struct_copy.getLength() < needed_size:
                    struct_copy.growStructure(needed_size - struct_copy.getLength())
                struct_copy.replaceAtOffset(
                    offset, field_dt, field_dt.getLength(), field_name, comment
                )
                dtm.addDataType(struct_copy, DataTypeConflictHandler.REPLACE_HANDLER)
                results.append(
                    FieldAdditionResult(
                        struct_name=struct_name,
                        field_name=field_name,
                        offset=offset,
                        size=field_dt.getLength(),
                        success=True,
                        message=f"Field '{field_name}' added successfully",
                    ).model_dump()
                )
            except Exception as e:
                results.append(
                    FieldAdditionResult(
                        struct_name=struct_name,
                        field_name=field_name,
                        offset=offset,
                        size=field_dt.getLength() if field_dt else 0,
                        success=False,
                        message=f'Failed to add field: {str(e)}',
                    ).model_dump()
                )
    return results
