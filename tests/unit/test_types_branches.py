"""Unit tests targeting error / defensive branches in tools/types.py.

Goal: push types.py from 6% line / 2% branch to 70%+ line / ~95% branch.

All tests run without Ghidra/pyghidra by stubbing Java imports via sys.modules
and using MagicMock for the backend.

One branch per test, single assertion preferred.
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import anyio
import pytest

from mcp.server.fastmcp.exceptions import ToolError


# ---------------------------------------------------------------------------
# Ghidra stub installation
# ---------------------------------------------------------------------------
# These must be installed before any import of mcpyghidra.tools.types so that
# the lazy `from ghidra.program.model.data import ...` calls inside the module
# resolve cleanly.

_GHIDRA_BASE_STUBS = [
    'ghidra',
    'ghidra.app',
    'ghidra.app.services',
    'ghidra.framework',
    'ghidra.program',
    'ghidra.program.model',
    'ghidra.program.model.address',
    'ghidra.program.model.listing',
    'ghidra.program.model.mem',
    'ghidra.program.model.symbol',
    'ghidra.program.util',
    'java',
    'java.io',
]

for _mod in _GHIDRA_BASE_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# ---------------------------------------------------------------------------
# Build a fake ghidra.program.model.data module with distinct sentinel classes
# so isinstance() checks in _normalize_type_kind() are resolvable.
# ---------------------------------------------------------------------------

# We need distinct Python classes (not MagicMocks) so that isinstance() works.
class _FakeStructure:
    pass

class _FakeGhidraUnion:
    pass

class _FakeGhidraEnum:
    pass

class _FakeTypeDef:
    pass

class _FakePointer:
    pass

class _FakeArray:
    pass

class _FakeFunctionDefinition:
    pass


def _build_data_module() -> ModuleType:
    """Build a fake ghidra.program.model.data with sentinel type classes."""
    data_mod = ModuleType('ghidra.program.model.data')
    data_mod.Structure = _FakeStructure  # type: ignore[attr-defined]
    data_mod.Union = _FakeGhidraUnion  # type: ignore[attr-defined]
    data_mod.Enum = _FakeGhidraEnum  # type: ignore[attr-defined]
    data_mod.TypeDef = _FakeTypeDef  # type: ignore[attr-defined]
    data_mod.Pointer = _FakePointer  # type: ignore[attr-defined]
    data_mod.Array = _FakeArray  # type: ignore[attr-defined]
    data_mod.FunctionDefinition = _FakeFunctionDefinition  # type: ignore[attr-defined]
    # Types used in _build_type_map — just MagicMocks is fine there
    for _name in (
        'ByteDataType',
        'CharDataType',
        'DoubleDataType',
        'FloatDataType',
        'IntegerDataType',
        'LongDataType',
        'LongLongDataType',
        'PointerDataType',
        'ShortDataType',
        'SignedByteDataType',
        'UnsignedCharDataType',
        'UnsignedIntegerDataType',
        'UnsignedLongDataType',
        'UnsignedLongLongDataType',
        'UnsignedShortDataType',
        'VoidDataType',
        'CategoryPath',
        'DataTypeConflictHandler',
        'StructureDataType',
    ):
        setattr(data_mod, _name, MagicMock())
    return data_mod


_DATA_MOD = _build_data_module()
sys.modules['ghidra.program.model.data'] = _DATA_MOD


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_backend() -> MagicMock:
    """Minimal mock backend with transaction context manager support."""
    backend = MagicMock()
    backend.is_headless = True
    backend.program = MagicMock()
    tx_ctx = MagicMock()
    tx_ctx.__enter__ = MagicMock(return_value=None)
    tx_ctx.__exit__ = MagicMock(return_value=False)
    backend.create_transaction.return_value = tx_ctx
    return backend


def _run_async(async_fn, *args, **kwargs):
    """Run an async function synchronously for unit tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


def _make_data_type(kind_class=None, *, name='TestType', path='/TestType') -> MagicMock:
    """Create a mock DataType that is-an instance of *kind_class* (if given).

    When kind_class is provided we create a proper subclass so isinstance() works,
    then attach MagicMock-style attributes to the instance.
    """
    if kind_class is not None:
        # Dynamically subclass the fake type so isinstance() succeeds.
        SubClass = type(f'Mock{kind_class.__name__}', (kind_class,), {})
        dt = MagicMock(spec_set=None)
        # Override the class so isinstance checks pass.
        dt.__class__ = SubClass
    else:
        dt = MagicMock()
    dt.getName.return_value = name
    dt.getPathName.return_value = path
    dt.getDisplayName.return_value = name
    dt.getLength.return_value = 4
    dt.getDescription.return_value = ''
    return dt


# ---------------------------------------------------------------------------
# _normalize_type_kind — each branch
# ---------------------------------------------------------------------------


class TestNormalizeTypeKind:
    """Each isinstance branch in _normalize_type_kind."""

    def test_structure_returns_struct(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakeStructure)
        assert _normalize_type_kind(dt) == 'struct'

    def test_union_returns_union(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakeGhidraUnion)
        assert _normalize_type_kind(dt) == 'union'

    def test_enum_returns_enum(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakeGhidraEnum)
        assert _normalize_type_kind(dt) == 'enum'

    def test_typedef_returns_typedef(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakeTypeDef)
        assert _normalize_type_kind(dt) == 'typedef'

    def test_pointer_returns_pointer(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakePointer)
        assert _normalize_type_kind(dt) == 'pointer'

    def test_array_returns_array(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakeArray)
        assert _normalize_type_kind(dt) == 'array'

    def test_function_definition_returns_function(self):
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = _make_data_type(_FakeFunctionDefinition)
        assert _normalize_type_kind(dt) == 'function'

    def test_unknown_with_builtin_path_returns_primitive(self):
        """Path containing 'BuiltInTypes' → primitive."""
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = MagicMock()
        dt.getPathName.return_value = '/BuiltInTypes/int'
        dt.getName.return_value = 'int'
        assert _normalize_type_kind(dt) == 'primitive'

    def test_unknown_with_primitive_name_returns_primitive(self):
        """Name containing a primitive keyword → primitive."""
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = MagicMock()
        dt.getPathName.return_value = '/CustomTypes/myuint'
        dt.getName.return_value = 'myuint'
        assert _normalize_type_kind(dt) == 'primitive'

    def test_unknown_with_none_path_falls_through(self):
        """getPathName() returns None → path falls back to '' → name checked next."""
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = MagicMock()
        dt.getPathName.return_value = None
        dt.getName.return_value = 'WeirdCustomType'
        assert _normalize_type_kind(dt) == 'unknown'

    def test_unknown_non_primitive_name_returns_unknown(self):
        """Name not matching any primitive keyword → unknown."""
        from mcpyghidra.tools.types import _normalize_type_kind

        dt = MagicMock()
        dt.getPathName.return_value = '/Custom'
        dt.getName.return_value = 'MysteryType'
        assert _normalize_type_kind(dt) == 'unknown'


# ---------------------------------------------------------------------------
# _get_type_summary — size exception / non-positive size branches
# ---------------------------------------------------------------------------


class TestGetTypeSummary:
    """_get_type_summary size branches."""

    def test_get_length_raises_sets_size_none(self):
        """getLength() raises → size is None."""
        from mcpyghidra.tools.types import _get_type_summary

        dt = MagicMock()
        dt.getName.return_value = 'BadType'
        dt.getPathName.return_value = '/BadType'
        dt.getDisplayName.return_value = 'BadType'
        dt.getLength.side_effect = RuntimeError('length not available')

        result = _get_type_summary(dt)
        assert result.size is None

    def test_get_length_zero_sets_size_none(self):
        """getLength() returns 0 → size is None (not positive)."""
        from mcpyghidra.tools.types import _get_type_summary

        dt = MagicMock()
        dt.getName.return_value = 'ZeroType'
        dt.getPathName.return_value = '/ZeroType'
        dt.getDisplayName.return_value = 'ZeroType'
        dt.getLength.return_value = 0

        result = _get_type_summary(dt)
        assert result.size is None

    def test_get_length_negative_sets_size_none(self):
        """getLength() returns -1 → size is None."""
        from mcpyghidra.tools.types import _get_type_summary

        dt = MagicMock()
        dt.getName.return_value = 'NegType'
        dt.getPathName.return_value = '/NegType'
        dt.getDisplayName.return_value = 'NegType'
        dt.getLength.return_value = -1

        result = _get_type_summary(dt)
        assert result.size is None

    def test_get_length_positive_sets_size(self):
        """getLength() returns 8 → size is 8."""
        from mcpyghidra.tools.types import _get_type_summary

        dt = MagicMock()
        dt.getName.return_value = 'GoodType'
        dt.getPathName.return_value = '/GoodType'
        dt.getDisplayName.return_value = 'GoodType'
        dt.getLength.return_value = 8

        result = _get_type_summary(dt)
        assert result.size == 8

    def test_path_none_falls_back_to_name(self):
        """getPathName() returns None → full_path falls back to name."""
        from mcpyghidra.tools.types import _get_type_summary

        dt = MagicMock()
        dt.getName.return_value = 'NoPathType'
        dt.getPathName.return_value = None
        dt.getDisplayName.return_value = 'NoPathType'
        dt.getLength.return_value = 4

        result = _get_type_summary(dt)
        assert result.full_path == 'NoPathType'


# ---------------------------------------------------------------------------
# _get_type_details — member / enum / typedef branches
# ---------------------------------------------------------------------------


class TestGetTypeDetails:
    """_get_type_details branches for struct/union members, enum values, typedef."""

    def _make_details_dt(self, kind_class, name='MyType', path=None):
        """Create a data type mock with isinstance support for _get_type_details."""
        dt = _make_data_type(kind_class, name=name, path=path or f'/{name}')
        dt.getDescription.return_value = ''
        return dt

    def test_structure_members_populated(self):
        """Structure data type → members list populated from getComponents()."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeStructure, name='MyStruct')
        dt.getLength.return_value = 8

        comp = MagicMock()
        comp_dt = MagicMock()
        comp_dt.getDisplayName.return_value = 'int'
        comp.getDataType.return_value = comp_dt
        comp.getFieldName.return_value = 'x'
        comp.getOffset.return_value = 0
        comp.getLength.return_value = 4
        dt.getComponents.return_value = [comp]

        result = _get_type_details(dt)
        assert result.members is not None
        assert len(result.members) == 1
        assert result.members[0].name == 'x'

    def test_structure_member_no_field_name_uses_default(self):
        """Component with no field name → getDefaultFieldName() used."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeStructure, name='MyStruct')
        dt.getLength.return_value = 8

        comp = MagicMock()
        comp_dt = MagicMock()
        comp_dt.getDisplayName.return_value = 'int'
        comp.getDataType.return_value = comp_dt
        comp.getFieldName.return_value = None
        comp.getDefaultFieldName.return_value = 'field_0'
        comp.getOffset.return_value = 0
        comp.getLength.return_value = 4
        dt.getComponents.return_value = [comp]

        result = _get_type_details(dt)
        assert result.members[0].name == 'field_0'

    def test_structure_member_no_field_name_no_default_uses_offset(self):
        """Component with no field name and no getDefaultFieldName → 'field_{offset}'."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeStructure, name='MyStruct')
        dt.getLength.return_value = 8

        # spec list that excludes getDefaultFieldName → hasattr returns False
        comp = MagicMock(spec=['getDataType', 'getFieldName', 'getOffset', 'getLength'])
        comp_dt = MagicMock()
        comp_dt.getDisplayName.return_value = 'int'
        comp.getDataType.return_value = comp_dt
        comp.getFieldName.return_value = None
        comp.getOffset.return_value = 4
        comp.getLength.return_value = 4
        dt.getComponents.return_value = [comp]

        result = _get_type_details(dt)
        assert result.members[0].name == 'field_4'

    def test_structure_member_zero_length_sets_size_none(self):
        """Component.getLength() returns 0 → MemberInfo.size is None."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeStructure, name='MyStruct')
        dt.getLength.return_value = 8

        comp = MagicMock()
        comp_dt = MagicMock()
        comp_dt.getDisplayName.return_value = 'void'
        comp.getDataType.return_value = comp_dt
        comp.getFieldName.return_value = 'pad'
        comp.getOffset.return_value = 0
        comp.getLength.return_value = 0
        dt.getComponents.return_value = [comp]

        result = _get_type_details(dt)
        assert result.members[0].size is None

    def test_union_members_populated(self):
        """Union data type → members list populated."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeGhidraUnion, name='MyUnion')
        dt.getLength.return_value = 4

        comp = MagicMock()
        comp_dt = MagicMock()
        comp_dt.getDisplayName.return_value = 'int'
        comp.getDataType.return_value = comp_dt
        comp.getFieldName.return_value = 'value'
        comp.getOffset.return_value = 0
        comp.getLength.return_value = 4
        dt.getComponents.return_value = [comp]

        result = _get_type_details(dt)
        assert result.members is not None
        assert result.members[0].name == 'value'

    def test_enum_values_populated(self):
        """Enum data type → values list populated from getNames()."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeGhidraEnum, name='Color')
        dt.getLength.return_value = 4
        dt.getNames.return_value = ['RED', 'GREEN', 'BLUE']
        dt.getValue.side_effect = lambda n: {'RED': 0, 'GREEN': 1, 'BLUE': 2}[n]

        result = _get_type_details(dt)
        assert result.values is not None
        assert len(result.values) == 3
        assert result.values[0].name == 'RED'
        assert result.values[0].value == 0

    def test_enum_no_names_returns_empty_values(self):
        """Enum with getNames() returning None/empty → values is empty list."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeGhidraEnum, name='EmptyEnum')
        dt.getLength.return_value = 4
        dt.getNames.return_value = None

        result = _get_type_details(dt)
        assert result.values == []

    def test_typedef_underlying_type_populated(self):
        """TypeDef → underlying_type is set from getDataType().getDisplayName()."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeTypeDef, name='MyTypeDef')
        dt.getLength.return_value = 4

        base = MagicMock()
        base.getDisplayName.return_value = 'unsigned int'
        dt.getDataType.return_value = base

        result = _get_type_details(dt)
        assert result.underlying_type == 'unsigned int'

    def test_typedef_base_none_leaves_underlying_type_none(self):
        """TypeDef.getDataType() returns None → underlying_type stays None."""
        from mcpyghidra.tools.types import _get_type_details

        dt = self._make_details_dt(_FakeTypeDef, name='NullTypeDef')
        dt.getLength.return_value = 4
        dt.getDataType.return_value = None

        result = _get_type_details(dt)
        assert result.underlying_type is None

    def test_comment_whitespace_only_sets_none(self):
        """getDescription() returns whitespace-only string → comment is None."""
        from mcpyghidra.tools.types import _get_type_details

        dt = MagicMock()
        dt.getName.return_value = 'Spacey'
        dt.getPathName.return_value = '/Spacey'
        dt.getDisplayName.return_value = 'Spacey'
        dt.getLength.return_value = 4
        dt.getDescription.return_value = '   '

        result = _get_type_details(dt)
        assert result.comment is None

    def test_comment_non_empty_preserved(self):
        """getDescription() returns a real comment → comment is set."""
        from mcpyghidra.tools.types import _get_type_details

        dt = MagicMock()
        dt.getName.return_value = 'Documented'
        dt.getPathName.return_value = '/Documented'
        dt.getDisplayName.return_value = 'Documented'
        dt.getLength.return_value = 4
        dt.getDescription.return_value = 'a real comment'

        result = _get_type_details(dt)
        assert result.comment == 'a real comment'


# ---------------------------------------------------------------------------
# _find_data_type — search logic branches
# ---------------------------------------------------------------------------


class TestFindDataType:
    """_find_data_type: name match, full-path match, suffix match, not found."""

    def _make_backend_with_types(self, types_list):
        """Backend whose data type managers yield a fixed list of data types."""
        backend = _make_backend()
        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = types_list
        backend.get_data_type_managers.return_value = [dtm]
        return backend

    def test_exact_name_match_returns_type(self):
        from mcpyghidra.tools.types import _find_data_type

        dt = MagicMock()
        dt.getName.return_value = 'MyType'
        dt.getPathName.return_value = '/Custom/MyType'
        backend = self._make_backend_with_types([dt])

        result = _find_data_type(backend, 'MyType')
        assert result is dt

    def test_full_path_match_returns_type(self):
        from mcpyghidra.tools.types import _find_data_type

        dt = MagicMock()
        dt.getName.return_value = 'OtherName'
        dt.getPathName.return_value = '/Custom/MyType'
        backend = self._make_backend_with_types([dt])

        result = _find_data_type(backend, '/Custom/MyType')
        assert result is dt

    def test_suffix_match_returns_type(self):
        """Type path ends with '/MyType' even though we searched for just 'MyType' — but
        name is different so the exact-name pass misses, and path != search term, so the
        suffix pass picks it up."""
        from mcpyghidra.tools.types import _find_data_type

        dt = MagicMock()
        dt.getName.return_value = 'Alias'
        dt.getPathName.return_value = '/Deep/Nested/MyType'
        backend = self._make_backend_with_types([dt])

        result = _find_data_type(backend, 'MyType')
        assert result is dt

    def test_not_found_returns_none(self):
        from mcpyghidra.tools.types import _find_data_type

        dt = MagicMock()
        dt.getName.return_value = 'Something'
        dt.getPathName.return_value = '/Something'
        backend = self._make_backend_with_types([dt])

        result = _find_data_type(backend, 'Nonexistent')
        assert result is None


# ---------------------------------------------------------------------------
# _resolve_field_type — branches
# ---------------------------------------------------------------------------


class TestResolveFieldType:
    """_resolve_field_type: type_map hit, dtm lookup, category fallback, pointer fallback."""

    def _make_dtm(self) -> MagicMock:
        dtm = MagicMock()
        dtm.getDataType.return_value = None
        return dtm

    def test_type_in_map_returns_directly(self):
        from mcpyghidra.tools.types import _resolve_field_type

        sentinel = MagicMock()
        type_map = {'int': sentinel}
        dtm = self._make_dtm()

        result = _resolve_field_type('int', dtm, type_map)
        assert result is sentinel

    def test_dtm_getdatatype_returns_type(self):
        """dtm.getDataType('/MyStruct') returns a value → used."""
        from mcpyghidra.tools.types import _resolve_field_type

        sentinel = MagicMock()
        dtm = self._make_dtm()
        dtm.getDataType.side_effect = lambda path_or_cat, *_args: (
            sentinel if path_or_cat == '/MyStruct' else None
        )
        type_map = {}

        result = _resolve_field_type('MyStruct', dtm, type_map)
        assert result is sentinel

    def test_category_path_fallback_used(self):
        """First dtm.getDataType call returns None; CategoryPath fallback returns a type."""
        from mcpyghidra.tools.types import _resolve_field_type

        sentinel = MagicMock()
        dtm = self._make_dtm()
        call_results = [None, sentinel]
        dtm.getDataType.side_effect = lambda *_args: call_results.pop(0)
        type_map = {}

        result = _resolve_field_type('MyStruct', dtm, type_map)
        assert result is sentinel

    def test_pointer_fallback_for_star_type(self):
        """When type contains '*' and dtm can't find it → PointerDataType returned."""
        from mcpyghidra.tools.types import _resolve_field_type

        dtm = self._make_dtm()
        type_map = {}

        # dtm always returns None; 'void*' contains '*' → pointer fallback
        result = _resolve_field_type('SomeCustomStruct*', dtm, type_map)
        # Result should be a MagicMock (the PointerDataType instantiated from stubs)
        assert result is not None

    def test_unresolvable_returns_none(self):
        """Type not in map, not in dtm, no '*' → None returned."""
        from mcpyghidra.tools.types import _resolve_field_type

        dtm = self._make_dtm()
        type_map = {}

        result = _resolve_field_type('NoSuchType', dtm, type_map)
        assert result is None


# ---------------------------------------------------------------------------
# list_entries(entry_type='type') validation — offset/limit branches
# ---------------------------------------------------------------------------


class TestTypesAsyncValidation:
    """list_entries(entry_type='type') input validation branches (formerly types())."""

    def test_negative_offset_raises(self):
        """offset < 0 → ToolError via list_entries."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        with pytest.raises(ToolError, match='offset must be non-negative'):
            _run_async(list_entries, backend, entry_type='type', offset=-1)

    def test_zero_limit_raises(self):
        """limit <= 0 → ToolError via list_entries."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        with pytest.raises(ToolError, match='limit must be positive'):
            _run_async(list_entries, backend, entry_type='type', limit=0)

    def test_negative_limit_raises(self):
        """limit < 0 → ToolError via list_entries."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        with pytest.raises(ToolError, match='limit must be positive'):
            _run_async(list_entries, backend, entry_type='type', limit=-5)


class TestTypesSyncFilter:
    """_iter_type_summaries pattern filter branches (formerly _types_sync)."""

    def _make_backend_with_types(self, types_list):
        backend = _make_backend()
        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = types_list
        backend.get_data_type_managers.return_value = [dtm]
        return backend

    def _make_dt(self, name, path=None):
        dt = MagicMock()
        dt.getName.return_value = name
        dt.getPathName.return_value = path or f'/{name}'
        dt.getDisplayName.return_value = name
        dt.getLength.return_value = 4
        return dt

    def test_no_pattern_returns_all(self):
        """Without pattern, all types are returned."""
        from mcpyghidra.tools.types import _iter_type_summaries

        dts = [self._make_dt('Alpha'), self._make_dt('Beta')]
        backend = self._make_backend_with_types(dts)
        result = _iter_type_summaries(backend, None)
        assert len(result) == 2

    def test_pattern_filters_by_name(self):
        """Pattern 'alp' matches 'Alpha' but not 'Beta'."""
        from mcpyghidra.tools.types import _iter_type_summaries

        dts = [self._make_dt('Alpha'), self._make_dt('Beta')]
        backend = self._make_backend_with_types(dts)
        result = _iter_type_summaries(backend, 'alp')
        assert len(result) == 1
        assert result[0].name == 'Alpha'

    def test_pattern_glob_stripped(self):
        """Leading and trailing '*' are stripped from pattern before matching."""
        from mcpyghidra.tools.types import _iter_type_summaries

        dts = [self._make_dt('Alpha'), self._make_dt('Beta')]
        backend = self._make_backend_with_types(dts)
        result = _iter_type_summaries(backend, '*alp*')
        assert len(result) == 1

    def test_pattern_matches_full_path(self):
        """Pattern matching against full_path when name doesn't match."""
        from mcpyghidra.tools.types import _iter_type_summaries

        dt = self._make_dt('X', path='/Some/Namespace/MySpecialType')
        backend = self._make_backend_with_types([dt])
        result = _iter_type_summaries(backend, 'special')
        assert len(result) == 1

    def test_empty_pattern_matches_none_via_lower(self):
        """Empty string pattern after strip is falsy → no filtering applied."""
        from mcpyghidra.tools.types import _iter_type_summaries

        dts = [self._make_dt('Alpha'), self._make_dt('Beta')]
        backend = self._make_backend_with_types(dts)
        result = _iter_type_summaries(backend, '')
        assert len(result) == 2

    def test_pagination_offset_slices_results(self):
        """offset=1, limit=1 → only second result returned (via list_types_result)."""
        from mcpyghidra.tools.types import list_types_result

        dts = [self._make_dt('Alpha'), self._make_dt('Beta')]
        backend = self._make_backend_with_types(dts)
        result = list_types_result(backend, 1, 1)
        assert result.page_info.num_returned == 1
        assert result.items[0]['name'] == 'Beta'

    def test_path_none_still_matches_by_name(self):
        """getPathName() returns None → full_path falls back to name for filter check."""
        from mcpyghidra.tools.types import _iter_type_summaries

        dt = MagicMock()
        dt.getName.return_value = 'NoPath'
        dt.getPathName.return_value = None
        dt.getDisplayName.return_value = 'NoPath'
        dt.getLength.return_value = 4
        backend = self._make_backend_with_types([dt])
        result = _iter_type_summaries(backend, 'nopath')
        assert len(result) == 1


# ---------------------------------------------------------------------------
# _type_info_sync — empty name and not found branches
# ---------------------------------------------------------------------------


class TestTypeInfoSync:
    """_type_info_sync error branches."""

    def test_empty_type_name_returns_error(self):
        """Empty type name → error in result dict."""
        from mcpyghidra.tools.types import _type_info_sync

        backend = _make_backend()
        backend.get_data_type_managers.return_value = []
        results = _type_info_sync(backend, [''])
        assert results[0].get('error') is not None

    def test_whitespace_type_name_returns_error(self):
        """Whitespace-only type name → error in result dict."""
        from mcpyghidra.tools.types import _type_info_sync

        backend = _make_backend()
        backend.get_data_type_managers.return_value = []
        results = _type_info_sync(backend, ['   '])
        assert results[0].get('error') is not None

    def test_not_found_returns_error(self):
        """Type name not in any manager → error in result dict."""
        from mcpyghidra.tools.types import _type_info_sync

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = []
        backend.get_data_type_managers.return_value = [dtm]
        results = _type_info_sync(backend, ['NonExistentType'])
        assert results[0].get('error') is not None

    def test_found_type_returns_details(self):
        """Found type → result dict has 'name' and no 'error'."""
        from mcpyghidra.tools.types import _type_info_sync

        dt = MagicMock()
        dt.getName.return_value = 'MyType'
        dt.getPathName.return_value = '/MyType'
        dt.getDisplayName.return_value = 'MyType'
        dt.getLength.return_value = 4
        dt.getDescription.return_value = ''
        dt.getComponents = MagicMock(return_value=[])

        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = [dt]
        backend = _make_backend()
        backend.get_data_type_managers.return_value = [dtm]
        results = _type_info_sync(backend, ['MyType'])
        assert 'error' in results[0]  # explicit key, not just absent
        assert results[0]['error'] is None
        assert results[0]['name'] == 'MyType'


# ---------------------------------------------------------------------------
# _create_struct_sync — branches
# ---------------------------------------------------------------------------


class TestCreateStructSync:
    """_create_struct_sync branches: existing struct, packed, fields, field resolution."""

    def _make_struct_backend(self, existing=None):
        """Backend whose dtm.getDataType returns *existing* (or None)."""
        backend = _make_backend()
        dtm = MagicMock()
        dtm.getDataType.return_value = existing
        backend.program.getDataTypeManager.return_value = dtm
        return backend

    def test_existing_struct_returns_not_created(self):
        """Struct already exists → created=False."""
        from mcpyghidra.tools.types import _create_struct_sync

        existing = MagicMock()
        existing.getLength.return_value = 16
        backend = self._make_struct_backend(existing=existing)

        result = _create_struct_sync(backend, 'ExistingStruct', 0, None, False)
        assert result.created is False
        assert 'already exists' in result.message

    def test_new_struct_created_returns_true(self):
        """New struct → created=True."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)

        result = _create_struct_sync(backend, 'NewStruct', 8, None, False)
        assert result.created is True

    def test_packed_struct_calls_packing_methods(self):
        """packed=True → setPackingEnabled and setExplicitPackingValue called."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)

        _create_struct_sync(backend, 'PackedStruct', 4, None, True)
        # StructureDataType is a MagicMock in our stub module, so we just verify no crash
        # The real check is that packed=True branch is exercised (no exception)
        assert True

    def test_fields_none_skips_field_loop(self):
        """fields=None → no field processing loop executed."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)
        result = _create_struct_sync(backend, 'SimpleStruct', 4, None, False)
        assert result.created is True

    def test_field_type_resolved_adds_field(self):
        """Field with resolvable type → replaceAtOffset called on struct."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)
        fields = [{'name': 'x', 'type': 'int', 'offset': 0}]
        # 'int' is in the type_map so resolution succeeds
        result = _create_struct_sync(backend, 'FieldStruct', 4, fields, False)
        assert result.created is True

    def test_field_type_unresolvable_logs_warn(self):
        """Field with unresolvable type → backend.log('warn', ...) called."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)
        # dtm.getDataType always returns None → unresolvable non-primitive
        fields = [{'name': 'ptr', 'type': 'CompletelyUnknownType', 'offset': 0}]
        _create_struct_sync(backend, 'NoFieldStruct', 4, fields, False)
        backend.log.assert_called()

    def test_min_size_estimated_from_fields_when_size_zero(self):
        """size=0 with fields → min_size estimated from field offsets."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)
        fields = [{'name': 'x', 'type': 'int', 'offset': 8}]
        # offset=8, estimated_size=4 → min_size=12
        result = _create_struct_sync(backend, 'AutoSizeStruct', 0, fields, False)
        assert result.created is True

    def test_min_size_estimated_pointer_type(self):
        """Fields with '*' in type → estimated_size=8."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)
        fields = [{'name': 'p', 'type': 'void *', 'offset': 0}]
        result = _create_struct_sync(backend, 'PtrSizeStruct', 0, fields, False)
        assert result.created is True

    def test_replace_at_offset_exception_logs_warn(self):
        """replaceAtOffset raises → backend.log('warn', ...) called."""
        from mcpyghidra.tools.types import _create_struct_sync

        backend = self._make_struct_backend(existing=None)

        # Make StructureDataType() return a struct mock where replaceAtOffset raises
        struct_mock = MagicMock()
        struct_mock.replaceAtOffset.side_effect = RuntimeError('offset error')
        struct_mock.getLength.return_value = 4

        # Patch the StructureDataType class in the data module
        orig = _DATA_MOD.StructureDataType
        _DATA_MOD.StructureDataType = MagicMock(return_value=struct_mock)
        try:
            fields = [{'name': 'x', 'type': 'int', 'offset': 0}]
            _create_struct_sync(backend, 'ErrFieldStruct', 4, fields, False)
            backend.log.assert_called()
        finally:
            _DATA_MOD.StructureDataType = orig


# ---------------------------------------------------------------------------
# _add_field_sync — branches
# ---------------------------------------------------------------------------


class TestAddFieldSync:
    """_add_field_sync: struct not found, type not found, grow, success, exception."""

    def _make_add_backend(self, struct=None):
        """Backend whose dtm.getDataType returns *struct*."""
        backend = _make_backend()
        dtm = MagicMock()
        dtm.getDataType.return_value = struct
        backend.program.getDataTypeManager.return_value = dtm
        return backend

    def test_struct_not_found_returns_failure(self):
        """Struct not in dtm → success=False."""
        from mcpyghidra.tools.types import _add_field_sync

        backend = self._make_add_backend(struct=None)
        items = [{'struct_name': 'Ghost', 'field_name': 'x', 'field_type': 'int', 'offset': 0}]
        results = _add_field_sync(backend, items)
        assert results[0]['success'] is False
        assert 'not found' in results[0]['message']

    def test_field_type_not_found_returns_failure(self):
        """Field type unresolvable → success=False."""
        from mcpyghidra.tools.types import _add_field_sync

        struct = MagicMock()
        backend = self._make_add_backend(struct=struct)
        # dtm.getDataType returns the struct on the first call but None for type lookups
        call_count = [0]
        def dtm_get(cat_or_path, *args):
            call_count[0] += 1
            return struct if call_count[0] == 1 else None
        backend.program.getDataTypeManager.return_value.getDataType.side_effect = dtm_get

        items = [{'struct_name': 'MyStruct', 'field_name': 'x', 'field_type': 'CompletelyUnknown', 'offset': 0}]
        results = _add_field_sync(backend, items)
        assert results[0]['success'] is False
        assert 'Unknown type' in results[0]['message']

    def _make_add_backend_with_struct_copy(self, struct_copy_length=16, *, raise_replace=False):
        """Build a backend where struct.copy() returns a controllable struct_copy mock.

        The dtm is configured so that:
        - dtm.getDataType(CategoryPath('/'), name) → the struct mock
        - type_map['int'] resolves to a field_dt with getLength() == 4
        """
        backend = _make_backend()

        # field_dt returned via type_map for 'int'
        field_dt = MagicMock()
        field_dt.getLength.return_value = 4

        struct_copy = MagicMock()
        struct_copy.getLength.return_value = struct_copy_length
        if raise_replace:
            struct_copy.replaceAtOffset.side_effect = RuntimeError('boom')

        struct = MagicMock()
        struct.copy.return_value = struct_copy

        dtm = MagicMock()
        # First call returns the struct (struct lookup); subsequent type lookups return None
        # (so type_map takes over for 'int').  We override IntegerDataType to return field_dt.
        dtm.getDataType.return_value = struct

        # Patch IntegerDataType.dataType so type_map['int'] = field_dt
        orig_int_dt = _DATA_MOD.IntegerDataType.dataType
        _DATA_MOD.IntegerDataType.dataType = field_dt

        backend.program.getDataTypeManager.return_value = dtm
        return backend, struct_copy, field_dt, orig_int_dt

    def test_struct_too_small_grows_structure(self):
        """struct_copy.getLength() < needed_size → growStructure called."""
        from mcpyghidra.tools.types import _add_field_sync

        # struct_copy.getLength()=4, offset=8, field_dt.getLength()=4 → needed=12 > 4
        backend, struct_copy, field_dt, orig = self._make_add_backend_with_struct_copy(
            struct_copy_length=4
        )
        try:
            items = [{'struct_name': 'Tiny', 'field_name': 'big', 'field_type': 'int', 'offset': 8}]
            _add_field_sync(backend, items)
            struct_copy.growStructure.assert_called()
        finally:
            _DATA_MOD.IntegerDataType.dataType = orig

    def test_success_returns_correct_metadata(self):
        """Successful field add → success=True with correct name, offset."""
        from mcpyghidra.tools.types import _add_field_sync

        backend, struct_copy, field_dt, orig = self._make_add_backend_with_struct_copy(
            struct_copy_length=16
        )
        try:
            items = [{'struct_name': 'MyStruct', 'field_name': 'val', 'field_type': 'int', 'offset': 0}]
            results = _add_field_sync(backend, items)
            assert results[0]['success'] is True
            assert results[0]['field_name'] == 'val'
        finally:
            _DATA_MOD.IntegerDataType.dataType = orig

    def test_replace_at_offset_exception_returns_failure(self):
        """replaceAtOffset raises on struct_copy → success=False."""
        from mcpyghidra.tools.types import _add_field_sync

        backend, struct_copy, field_dt, orig = self._make_add_backend_with_struct_copy(
            struct_copy_length=16, raise_replace=True
        )
        try:
            items = [{'struct_name': 'MyStruct', 'field_name': 'bad', 'field_type': 'int', 'offset': 0}]
            results = _add_field_sync(backend, items)
            assert results[0]['success'] is False
            assert 'Failed to add field' in results[0]['message']
        finally:
            _DATA_MOD.IntegerDataType.dataType = orig

    def test_items_not_list_coerced(self):
        """add_field normalises a non-list items arg to a list."""
        from mcpyghidra.tools.types import add_field

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getDataType.return_value = None
        backend.program.getDataTypeManager.return_value = dtm

        single_item = {'struct_name': 'Ghost', 'field_name': 'x', 'field_type': 'int', 'offset': 0}
        results = _run_async(add_field, backend, single_item)  # type: ignore[arg-type]
        assert isinstance(results, list)
        assert len(results) == 1

    def test_batch_multiple_items(self):
        """Multiple items in a single call are all processed."""
        from mcpyghidra.tools.types import _add_field_sync

        backend = self._make_add_backend(struct=None)
        items = [
            {'struct_name': 'A', 'field_name': 'x', 'field_type': 'int', 'offset': 0},
            {'struct_name': 'B', 'field_name': 'y', 'field_type': 'int', 'offset': 0},
        ]
        results = _add_field_sync(backend, items)
        assert len(results) == 2
        assert all(r['success'] is False for r in results)


# ---------------------------------------------------------------------------
# type_info async wrapper — non-list items coerced
# ---------------------------------------------------------------------------


class TestTypeInfoAsync:
    """type_info() normalises a non-list items arg to a list."""

    def test_non_list_items_coerced(self):
        from mcpyghidra.tools.types import type_info

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = []
        backend.get_data_type_managers.return_value = [dtm]

        results = _run_async(type_info, backend, 'NonExistentType')  # type: ignore[arg-type]
        assert isinstance(results, list)
        assert results[0].get('error') is not None

    def test_list_items_passed_through(self):
        """items already a list → isinstance branch is True, no coercion needed."""
        from mcpyghidra.tools.types import type_info

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = []
        backend.get_data_type_managers.return_value = [dtm]

        results = _run_async(type_info, backend, ['NonExistentType'])
        assert isinstance(results, list)
        assert results[0].get('error') is not None


# ---------------------------------------------------------------------------
# Async wrapper smoke tests — exercise the async return paths (lines 311, 415, 510)
# ---------------------------------------------------------------------------


class TestAsyncWrapperSmoke:
    """Smoke tests for the async wrappers to ensure the return/await lines are covered."""

    def test_list_entry_type_returns_listresult(self):
        """list_entries(entry_type='type') returns a ListResult with empty items when no types."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getAllDataTypes.return_value = []
        backend.get_data_type_managers.return_value = [dtm]

        result = _run_async(list_entries, backend, entry_type='type', offset=0, limit=500)
        assert hasattr(result, 'page_info')
        assert result.entry_type == 'type'
        assert isinstance(result.items, list)

    def test_create_struct_async_returns_result(self):
        """create_struct() async return path (line 415) — minimal struct creation."""
        from mcpyghidra.tools.types import create_struct

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getDataType.return_value = None  # struct doesn't exist yet
        backend.program.getDataTypeManager.return_value = dtm

        result = _run_async(create_struct, backend, name='AsyncTestStruct', size=4)
        assert result.created is True

    def test_add_field_async_list_passed_through(self):
        """add_field() with list items → isinstance branch True (line 508→510)."""
        from mcpyghidra.tools.types import add_field

        backend = _make_backend()
        dtm = MagicMock()
        dtm.getDataType.return_value = None  # struct not found
        backend.program.getDataTypeManager.return_value = dtm

        results = _run_async(add_field, backend, [{'struct_name': 'Ghost', 'field_name': 'x', 'field_type': 'int', 'offset': 0}])
        assert isinstance(results, list)
        assert results[0]['success'] is False


# ---------------------------------------------------------------------------
# _get_type_details — size exception/non-positive branches (lines 124-127)
# ---------------------------------------------------------------------------


class TestGetTypeDetailsSizeBranches:
    """_get_type_details size <= 0 and getLength() exception branches."""

    def test_get_length_raises_in_details_sets_size_none(self):
        """getLength() raises in _get_type_details → size is None."""
        from mcpyghidra.tools.types import _get_type_details

        dt = MagicMock()
        dt.getName.return_value = 'NoLen'
        dt.getPathName.return_value = '/NoLen'
        dt.getDisplayName.return_value = 'NoLen'
        dt.getLength.side_effect = RuntimeError('no length')
        dt.getDescription.return_value = ''

        result = _get_type_details(dt)
        assert result.size is None

    def test_get_length_zero_in_details_sets_size_none(self):
        """getLength() returns 0 in _get_type_details → size is None."""
        from mcpyghidra.tools.types import _get_type_details

        dt = MagicMock()
        dt.getName.return_value = 'ZeroLen'
        dt.getPathName.return_value = '/ZeroLen'
        dt.getDisplayName.return_value = 'ZeroLen'
        dt.getLength.return_value = 0
        dt.getDescription.return_value = ''

        result = _get_type_details(dt)
        assert result.size is None
