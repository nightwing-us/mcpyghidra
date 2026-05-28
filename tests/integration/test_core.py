"""Integration tests for core listing and context tools.

Tests call tool functions directly on the HeadlessBackend instance provided by
the session-scoped ``backend`` fixture in conftest.py. pyghidra must be available.
"""
from __future__ import annotations


from mcpyghidra.tools.core import context, list_entries
from tests.integration.helpers import assert_non_empty, assert_valid_address, run_async


class TestListFunctions:
    """list_entries(backend, entry_type='function', ...) returns a paginated ListResult."""

    def test_list_functions_basic(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=10)
        assert result is not None
        assert result.entry_type == 'function'
        assert isinstance(result.items, list)
        assert len(result.items) > 0
        assert len(result.items) <= 10

    def test_list_functions_items_are_dicts(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=10)
        for item in result.items:
            assert isinstance(item, dict), f'Expected dict, got {type(item).__name__}'
            assert 'name' in item, f'Item missing "name" key: {item!r}'
            assert 'address' in item, f'Item missing "address" key: {item!r}'

    def test_list_functions_addresses_are_hex(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=10)
        for item in result.items:
            assert_valid_address(item['address'])

    def test_list_functions_has_page_info(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=10)
        assert result.page_info is not None
        assert hasattr(result.page_info, 'total_count')
        assert result.page_info.total_count > 0

    def test_list_functions_finds_main(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='main')
        names = [item['name'] for item in result.items]
        assert 'main' in names, f'Expected "main" in function names, got: {names}'

    def test_list_functions_finds_check_password(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='check_password')
        names = [item['name'] for item in result.items]
        assert 'check_password' in names, f'Expected "check_password" in names, got: {names}'

    def test_list_functions_match_filter_excludes_others(self, backend):
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=500, match_filter='main')
        for item in result.items:
            assert 'main' in item['name'].lower(), (
                f'Filter "main" should only return items containing "main", got: {item["name"]!r}'
            )

    def test_list_functions_pagination_two_pages(self, backend):
        """Two pages with different offsets should not overlap."""
        page1 = run_async(list_entries, backend, entry_type='function', offset=0, limit=2)
        page2 = run_async(list_entries, backend, entry_type='function', offset=2, limit=2)

        if len(page1.items) == 2 and len(page2.items) > 0:
            names_p1 = {item['name'] for item in page1.items}
            names_p2 = {item['name'] for item in page2.items}
            assert names_p1 != names_p2, 'Pages at offset=0 and offset=2 should differ'

    def test_list_functions_page2_offset_matches(self, backend):
        """page_info.next_offset should advance on first page."""
        result = run_async(list_entries, backend, entry_type='function', offset=0, limit=5)
        if result.page_info.has_more:
            assert result.page_info.next_offset is not None
            assert result.page_info.next_offset == 5


class TestListStrings:
    """list_entries(backend, entry_type='string', ...) returns found strings."""

    def test_list_strings_basic(self, backend):
        result = run_async(list_entries, backend, entry_type='string', offset=0, limit=50)
        assert result is not None
        assert result.entry_type == 'string'
        assert isinstance(result.items, list)
        assert len(result.items) > 0

    def test_list_strings_items_have_value(self, backend):
        result = run_async(list_entries, backend, entry_type='string', offset=0, limit=50)
        for item in result.items:
            assert isinstance(item, dict)
            assert 'value' in item or 'name' in item, f'String item missing value/name key: {item!r}'

    def test_list_strings_finds_secret(self, backend):
        result = run_async(list_entries, backend, entry_type='string', offset=0, limit=500, match_filter='secret')
        assert len(result.items) > 0, 'Expected to find at least one string containing "secret"'
        values = [str(item.get('value', item.get('name', ''))) for item in result.items]
        assert any('secret' in v.lower() for v in values), (
            f'Expected a string containing "secret", found: {values}'
        )

    def test_list_strings_has_page_info(self, backend):
        result = run_async(list_entries, backend, entry_type='string', offset=0, limit=50)
        assert result.page_info is not None
        assert result.page_info.total_count >= 0


class TestListImports:
    """list_entries(backend, entry_type='import', ...) returns imported symbols."""

    def test_list_imports_basic(self, backend):
        result = run_async(list_entries, backend, entry_type='import', offset=0, limit=50)
        assert result is not None
        assert result.entry_type == 'import'
        assert isinstance(result.items, list)

    def test_list_imports_items_have_name(self, backend):
        result = run_async(list_entries, backend, entry_type='import', offset=0, limit=50)
        for item in result.items:
            assert isinstance(item, dict)
            assert 'name' in item, f'Import item missing "name" key: {item!r}'

    def test_list_imports_has_page_info(self, backend):
        result = run_async(list_entries, backend, entry_type='import', offset=0, limit=50)
        assert result.page_info is not None
        assert result.page_info.total_count >= 0


class TestGetContext:
    """context(backend) returns BinaryContext with program, arch, memory."""

    def test_get_context_returns_binary_context(self, backend):
        ctx = run_async(context, backend)
        assert ctx is not None

    def test_get_context_program_info(self, backend):
        ctx = run_async(context, backend)
        assert ctx.program is not None
        assert_non_empty(ctx.program.file_name)
        assert isinstance(ctx.program.file_name, str)

    def test_get_context_program_file_name_contains_crackme(self, backend):
        ctx = run_async(context, backend)
        assert 'crackme' in ctx.program.file_name.lower(), (
            f'Expected "crackme" in file_name, got: {ctx.program.file_name!r}'
        )

    def test_get_context_architecture(self, backend):
        ctx = run_async(context, backend)
        assert ctx.architecture is not None
        assert_non_empty(ctx.architecture.processor)
        assert ctx.architecture.bitness in (16, 32, 64), (
            f'Unexpected bitness: {ctx.architecture.bitness}'
        )
        assert ctx.architecture.endianness in ('little', 'big'), (
            f'Unexpected endianness: {ctx.architecture.endianness!r}'
        )

    def test_get_context_memory(self, backend):
        ctx = run_async(context, backend)
        assert ctx.memory is not None
        assert_valid_address(ctx.memory.image_base)
        assert_valid_address(ctx.memory.min_address)
        assert_valid_address(ctx.memory.max_address)

    def test_get_context_analysis(self, backend):
        ctx = run_async(context, backend)
        assert ctx.analysis is not None
        assert ctx.analysis.function_count > 0

    def test_get_context_application(self, backend):
        ctx = run_async(context, backend)
        assert ctx.application is not None
        assert_non_empty(ctx.application.name)
