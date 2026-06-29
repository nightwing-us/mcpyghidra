"""Integration tests for type tools: list(entry_type='type'), type_info, create_struct, add_field.

Tests call tool functions directly on the HeadlessBackend instance. Struct creation
tests use unique names to avoid collisions.
"""
from __future__ import annotations


from mcpyghidra.tools.core import list_entries
from mcpyghidra.tools.types import add_field, create_struct, type_info
from tests.integration.helpers import assert_non_empty, run_async


# Unique struct names to avoid collisions across test runs
_TEST_STRUCT_NAME = 'McpTestPoint_Integration'
_TEST_STRUCT_FIELD_NAME = 'McpTestRect_Integration'


class TestListTypes:
    """list_entries(backend, entry_type='type', ...) — enumerate types via ListResult API."""

    def test_list_types_no_filter_returns_results(self, backend):
        """Without filter, list(entry_type='type') should return a non-empty ListResult."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=500)
        assert hasattr(result, 'page_info'), 'Expected ListResult with page_info'
        assert result.entry_type == 'type'
        assert len(result.items) > 0, 'Expected at least one type item'

    def test_list_types_items_have_expected_fields(self, backend):
        """Each item dict should have the expected type fields."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=10)
        assert len(result.items) > 0
        for item in result.items:
            assert 'name' in item, f'Item missing "name": {item!r}'
            assert 'full_path' in item, f'Item missing "full_path": {item!r}'
            assert 'type_string' in item, f'Item missing "type_string": {item!r}'
            assert 'kind' in item, f'Item missing "kind": {item!r}'
            assert isinstance(item['name'], str)
            assert_non_empty(item['name'])

    def test_list_types_with_match_filter_int(self, backend):
        """match_filter 'int' should return types containing 'int'."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=100,
                           match_filter='int')
        assert len(result.items) > 0, 'Expected types matching "int" filter'
        for item in result.items:
            assert 'int' in item['name'].lower() or 'int' in item['full_path'].lower(), (
                f'Type "{item["name"]}" does not match filter "int": full_path={item["full_path"]!r}'
            )

    def test_list_types_with_match_filter_char(self, backend):
        """match_filter 'char' should return char-related types."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=50,
                           match_filter='char')
        assert len(result.items) > 0, 'Expected types matching "char" filter'

    def test_list_types_pagination_offset(self, backend):
        """Two pages with different offsets should not be identical."""
        page1 = run_async(list_entries, backend, entry_type='type', offset=0, limit=5)
        page2 = run_async(list_entries, backend, entry_type='type', offset=5, limit=5)

        if page1.page_info.num_returned == 5 and page2.page_info.num_returned > 0:
            names_p1 = {item['name'] for item in page1.items}
            names_p2 = {item['name'] for item in page2.items}
            assert names_p1 != names_p2, (
                'Pages at offset=0 and offset=5 should return different types'
            )

    def test_list_types_limit_respected(self, backend):
        """Returned item count should not exceed limit."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=3)
        assert len(result.items) <= 3, (
            f'Expected at most 3 results with limit=3, got {len(result.items)}'
        )

    def test_list_types_glob_pattern_stripped(self, backend):
        """match_filter with glob asterisks should work (asterisks are stripped)."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=50,
                           match_filter='*int*')
        assert len(result.items) > 0, 'Expected results for glob filter "*int*"'

    def test_list_types_nonexistent_pattern_returns_empty(self, backend):
        """A filter that matches nothing should return empty items list."""
        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=500,
                           match_filter='xyzzy_nonexistent_type_12345')
        assert len(result.items) == 0, (
            f'Expected empty items for nonexistent filter, got: {[i["name"] for i in result.items]}'
        )


class TestGetTypeInfo:
    """type_info(backend, [type_name])[0] — retrieve detailed type information."""

    def test_get_type_info_int(self, backend):
        """Built-in 'int' type should be found and have basic details."""
        result = run_async(type_info, backend, ['int'])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert 'name' in result
        assert 'int' in result['name'].lower(), (
            f'Expected "int" in type name, got: {result["name"]!r}'
        )

    def test_get_type_info_returns_type_details_fields(self, backend):
        """TypeDetails dict should have all expected fields."""
        result = run_async(type_info, backend, ['int'])[0]
        assert result.get('error') is None
        for field in ('name', 'full_path', 'type_string', 'kind', 'size', 'comment', 'members', 'values'):
            assert field in result, f'TypeDetails missing field "{field}": {result!r}'

    def test_get_type_info_int_has_size(self, backend):
        """'int' should have a non-None, positive size."""
        result = run_async(type_info, backend, ['int'])[0]
        assert result.get('error') is None
        assert result['size'] is not None, 'Expected size to be set for int'
        assert result['size'] > 0, f'Expected positive size for int, got: {result["size"]}'

    def test_get_type_info_char(self, backend):
        """Built-in 'char' type should be found."""
        result = run_async(type_info, backend, ['char'])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert 'char' in result['name'].lower(), (
            f'Expected "char" in type name, got: {result["name"]!r}'
        )
        assert result['size'] is not None and result['size'] > 0

    def test_get_type_info_nonexistent_returns_error(self, backend):
        """Requesting a nonexistent type should return a dict with error set."""
        result = run_async(type_info, backend, ['xyzzy_nonexistent_type_12345'])[0]
        assert result.get('error') is not None, (
            'Expected error for nonexistent type, got none'
        )

    def test_get_type_info_empty_name_returns_error(self, backend):
        """Empty type_name should return a dict with error set."""
        result = run_async(type_info, backend, [''])[0]
        assert result.get('error') is not None, (
            'Expected error for empty type_name, got none'
        )

    def test_get_type_info_kind_is_non_empty_string(self, backend):
        """kind field should be a non-empty string."""
        result = run_async(type_info, backend, ['int'])[0]
        assert result.get('error') is None
        assert isinstance(result['kind'], str)
        assert_non_empty(result['kind'])

    def test_get_type_info_batch(self, backend):
        """Batched call returns list of results in order."""
        results = run_async(type_info, backend, ['int', 'char'])
        assert isinstance(results, list)
        assert len(results) == 2
        assert results[0].get('error') is None
        assert results[1].get('error') is None
        assert 'int' in results[0]['name'].lower()
        assert 'char' in results[1]['name'].lower()


class TestCreateStruct:
    """create_struct — create a new struct in the type database."""

    def test_create_struct_returns_creation_result(self, backend):
        """create_struct should return a StructureCreationResult."""
        result = run_async(create_struct, backend, name=_TEST_STRUCT_NAME, size=8)
        assert result is not None
        assert hasattr(result, 'name'), f'Missing "name" field: {result!r}'
        assert hasattr(result, 'size'), f'Missing "size" field: {result!r}'
        assert hasattr(result, 'created'), f'Missing "created" field: {result!r}'
        assert hasattr(result, 'message'), f'Missing "message" field: {result!r}'

    def test_create_struct_created_flag(self, backend):
        """First creation should have created=True (or struct already exists from prior run)."""
        result = run_async(create_struct, backend, name=_TEST_STRUCT_NAME, size=8)
        assert isinstance(result.created, bool)
        assert result.name == _TEST_STRUCT_NAME, (
            f'Expected struct name {_TEST_STRUCT_NAME!r}, got: {result.name!r}'
        )

    def test_create_struct_with_fields(self, backend):
        """create_struct with initial fields should succeed."""
        struct_name = f'{_TEST_STRUCT_NAME}_WithFields'
        result = run_async(create_struct,
            backend,
            name=struct_name,
            size=8,
            fields=[
                {'name': 'x', 'type': 'int', 'offset': 0},
                {'name': 'y', 'type': 'int', 'offset': 4},
            ],
        )
        assert result is not None
        assert isinstance(result.name, str)
        assert result.name == struct_name, (
            f'Expected struct name {struct_name!r}, got: {result.name!r}'
        )
        assert result.size >= 8, (
            f'Expected size >= 8 for struct with two ints, got: {result.size}'
        )

    def test_create_struct_visible_via_type_info(self, backend):
        """After creation, the struct should be findable via type_info."""
        run_async(create_struct, backend, name=_TEST_STRUCT_NAME, size=8)

        result = run_async(type_info, backend, [_TEST_STRUCT_NAME])[0]
        assert result.get('error') is None, f'Unexpected error: {result.get("error")}'
        assert result['name'] == _TEST_STRUCT_NAME, (
            f'Expected type name {_TEST_STRUCT_NAME!r}, got: {result["name"]!r}'
        )

    def test_create_struct_visible_in_types(self, backend):
        """After creation, the struct should appear in list(entry_type='type') with match_filter."""
        run_async(create_struct, backend, name=_TEST_STRUCT_NAME, size=8)

        result = run_async(list_entries, backend, entry_type='type', offset=0, limit=500,
                           match_filter=_TEST_STRUCT_NAME)
        names = [item['name'] for item in result.items]
        assert _TEST_STRUCT_NAME in names, (
            f'Expected {_TEST_STRUCT_NAME!r} in list(type) results, got: {names}'
        )

    def test_create_struct_duplicate_returns_existing(self, backend):
        """Creating the same struct twice should return created=False on second call."""
        run_async(create_struct, backend, name=_TEST_STRUCT_NAME, size=8)

        result = run_async(create_struct, backend, name=_TEST_STRUCT_NAME, size=8)
        assert result.created is False, (
            f'Expected created=False for duplicate struct, got created={result.created!r}'
        )
        assert _TEST_STRUCT_NAME in result.message, (
            f'Expected struct name in message: {result.message!r}'
        )


class TestAddField:
    """add_field — add fields to an existing struct."""

    def test_add_field_returns_field_addition_result(self, backend):
        """add_field should return a dict with FieldAdditionResult fields."""
        struct_name = _TEST_STRUCT_FIELD_NAME
        run_async(create_struct, backend, name=struct_name, size=16)

        result = run_async(add_field, backend, [{
            'struct_name': struct_name,
            'field_name': 'left',
            'field_type': 'int',
            'offset': 0,
        }])[0]
        assert result is not None
        assert 'struct_name' in result, f'Missing "struct_name": {result!r}'
        assert 'field_name' in result, f'Missing "field_name": {result!r}'
        assert 'offset' in result, f'Missing "offset": {result!r}'
        assert 'size' in result, f'Missing "size": {result!r}'
        assert 'success' in result, f'Missing "success": {result!r}'
        assert 'message' in result, f'Missing "message": {result!r}'

    def test_add_field_success_flag(self, backend):
        """Adding a valid field should have success=True."""
        struct_name = _TEST_STRUCT_FIELD_NAME
        run_async(create_struct, backend, name=struct_name, size=16)

        result = run_async(add_field, backend, [{
            'struct_name': struct_name,
            'field_name': 'top',
            'field_type': 'int',
            'offset': 4,
        }])[0]
        assert result['success'] is True, (
            f'Expected success=True when adding valid field, got: {result["success"]!r}. '
            f'Message: {result["message"]!r}'
        )

    def test_add_field_correct_metadata(self, backend):
        """Result should reflect the added field metadata."""
        struct_name = _TEST_STRUCT_FIELD_NAME
        run_async(create_struct, backend, name=struct_name, size=16)

        result = run_async(add_field, backend, [{
            'struct_name': struct_name,
            'field_name': 'right',
            'field_type': 'int',
            'offset': 8,
        }])[0]
        assert result['struct_name'] == struct_name, (
            f'Expected struct_name={struct_name!r}, got: {result["struct_name"]!r}'
        )
        assert result['field_name'] == 'right', (
            f'Expected field_name="right", got: {result["field_name"]!r}'
        )
        assert result['offset'] == 8, f'Expected offset=8, got: {result["offset"]}'

    def test_add_field_visible_in_type_info_members(self, backend):
        """After adding a field, it should appear in type_info members."""
        struct_name = _TEST_STRUCT_FIELD_NAME
        run_async(create_struct, backend, name=struct_name, size=16)

        field_name = 'bottom'
        run_async(add_field, backend, [{
            'struct_name': struct_name,
            'field_name': field_name,
            'field_type': 'int',
            'offset': 12,
        }])

        result = run_async(type_info, backend, [struct_name])[0]
        assert result.get('error') is None, (
            f'Expected no error for struct {struct_name!r}, got: {result.get("error")}'
        )
        members = result.get('members')
        assert members is not None, (
            f'Expected members list for struct {struct_name!r}, got None'
        )
        member_names = [m['name'] for m in members]
        assert field_name in member_names, (
            f'Expected field "{field_name}" in members {member_names!r}'
        )

    def test_add_field_nonexistent_struct_returns_failure(self, backend):
        """Adding a field to a nonexistent struct should return success=False."""
        result = run_async(add_field, backend, [{
            'struct_name': 'xyzzy_no_such_struct_99999',
            'field_name': 'x',
            'field_type': 'int',
            'offset': 0,
        }])[0]
        assert result['success'] is False, (
            f'Expected success=False for nonexistent struct, got: {result["success"]!r}'
        )

    def test_add_field_with_comment(self, backend):
        """add_field accepts an optional comment."""
        struct_name = _TEST_STRUCT_FIELD_NAME
        run_async(create_struct, backend, name=struct_name, size=20)

        result = run_async(add_field, backend, [{
            'struct_name': struct_name,
            'field_name': 'reserved',
            'field_type': 'int',
            'offset': 16,
            'comment': 'reserved for future use',
        }])[0]
        assert isinstance(result['success'], bool)


# ---------------------------------------------------------------------------
# list(entry_type='type') — new ListResult-based API
# ---------------------------------------------------------------------------


def test_list_entry_type_type_returns_listresult(typed_backend):
    from mcpyghidra.tools.core import list_entries
    from tests.integration.helpers import run_async
    result = run_async(list_entries, typed_backend, entry_type='type', offset=0, limit=500)
    # ListResult envelope, not a bare list:
    assert hasattr(result, 'page_info')
    assert result.entry_type == 'type'
    names = [item['name'] for item in result.items]
    assert any('Point' in n for n in names), f'expected Point-ish type, got {names[:20]}'


def test_list_entry_type_type_match_filter(typed_backend):
    from mcpyghidra.tools.core import list_entries
    from tests.integration.helpers import run_async
    result = run_async(list_entries, typed_backend, entry_type='type', offset=0, limit=500,
                       match_filter='Point')
    assert all('point' in item['name'].lower() or 'point' in item.get('full_path', '').lower()
               for item in result.items)
