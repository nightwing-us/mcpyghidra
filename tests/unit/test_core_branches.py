"""Unit tests for defensive / error branches in tools/core.py.

These tests run without Ghidra/pyghidra by mocking GhidraBackend and all
Java-type dependencies.  Each test targets exactly ONE branch.

Coverage goal: tools/core.py from 8% line / 0% branch → 70%+ line / ~100% branch.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcpyghidra.backend import GhidraError


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_backend(*, is_headless: bool = True) -> MagicMock:
    """Minimal mock GhidraBackend sufficient for core tool helpers."""
    backend = MagicMock()
    backend.is_headless = is_headless
    backend.program = MagicMock()
    backend.flat_api = MagicMock()
    return backend


# Stub out every ghidra.* sub-package used inside core.py lazy imports so
# they don't cause ModuleNotFoundError when the helpers are exercised.
_GHIDRA_STUBS = [
    'ghidra',
    'ghidra.app',
    'ghidra.app.services',
    'ghidra.program',
    'ghidra.program.model',
    'ghidra.program.model.address',
    'ghidra.program.model.listing',
    'ghidra.program.model.mem',
    'ghidra.program.model.symbol',
    'ghidra.program.util',
    'java',
    'java.io',
    'java.io.File',
]

for _mod in _GHIDRA_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# ghidra.framework.Application must return real strings so Pydantic is happy.
_mock_application = MagicMock()
_mock_application.getName.return_value = 'Ghidra'
_mock_application.getApplicationVersion.return_value = '11.0'
_mock_ghidra_framework = MagicMock()
_mock_ghidra_framework.Application = _mock_application
sys.modules['ghidra.framework'] = _mock_ghidra_framework


# ---------------------------------------------------------------------------
# _get_function — name branch: function not found
# ---------------------------------------------------------------------------


class TestGetFunctionNameBranch:
    """_get_function raises GhidraError when looking up by name and not found."""

    def test_name_lookup_not_found_raises(self):
        """flat_api.getFunction returns None → GhidraError."""
        from mcpyghidra.tools.core import _get_function

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        with pytest.raises(GhidraError, match='No function found with name'):
            _get_function(backend, addr='', name='missing_func')

    def test_addr_lookup_not_found_raises(self):
        """getFunctionContaining returns None → GhidraError."""
        from mcpyghidra.tools.core import _get_function

        backend = _make_backend()
        mock_addr = MagicMock()
        mock_addr.offset = 0x1000
        backend.program.getAddressFactory.return_value.getAddress.return_value = mock_addr
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        with pytest.raises(GhidraError, match='No function found at address'):
            _get_function(backend, addr='0x1000', name='')

    def test_neither_addr_nor_name_raises(self):
        """Passing empty addr AND empty name → GhidraError."""
        from mcpyghidra.tools.core import _get_function

        backend = _make_backend()

        with pytest.raises(GhidraError, match='Either a function name or address must be provided'):
            _get_function(backend, addr='', name='')


# ---------------------------------------------------------------------------
# _paginate_with_total — offset > total → ToolError (via _tool_result_list_formatter)
# ---------------------------------------------------------------------------


class TestPaginateWithTotal:
    """_paginate_with_total itself returns an empty page when offset > total;
    _tool_result_list_formatter then raises ToolError."""

    def test_offset_beyond_total_raises_tool_error(self):
        """offset > total and entries produce no results → ToolError raised."""
        from mcpyghidra.tools.core import _tool_result_list_formatter

        # 0 entries, offset=999 → results list stays empty → offset > total → ToolError
        with pytest.raises(ToolError, match='offset.*exceeds total'):
            _tool_result_list_formatter(
                results_heading='Functions',
                entry_type='function',
                entry_proc=lambda e: {'type': 'function', 'name': str(e), 'address': '0x0'},
                entries=[],
                offset=999,
                limit=500,
            )

    def test_paginate_with_total_sequence(self):
        """Passing a Sequence skips the list() conversion branch."""
        from mcpyghidra.tools.core import _paginate_with_total

        items = [1, 2, 3, 4, 5]
        page, total, start, stop = _paginate_with_total(items, offset=1, limit=2)
        assert total == 5
        assert page == [2, 3]
        assert start == 1
        assert stop == 3

    def test_paginate_with_total_iterator(self):
        """Passing a non-Sequence (generator) triggers the list() conversion."""
        from mcpyghidra.tools.core import _paginate_with_total

        page, total, start, stop = _paginate_with_total(iter([10, 20, 30]), offset=0, limit=2)
        assert total == 3
        assert page == [10, 20]

    def test_paginate_no_limit(self):
        """limit=None → stop == total."""
        from mcpyghidra.tools.core import _paginate_with_total

        page, total, start, stop = _paginate_with_total([1, 2, 3], offset=0, limit=None)
        assert stop == total == 3
        assert page == [1, 2, 3]

    def test_paginate_negative_limit(self):
        """limit=-1 → treated as no limit."""
        from mcpyghidra.tools.core import _paginate_with_total

        page, total, _start, stop = _paginate_with_total([1, 2], offset=0, limit=-1)
        assert stop == total == 2


# ---------------------------------------------------------------------------
# _list_entries_sync — unsupported entry_type
# ---------------------------------------------------------------------------


class TestListEntriesSyncInvalidType:
    """_list_entries_sync raises ToolError for unknown entry_type literals."""

    def test_unknown_entry_type_raises(self):
        """entry_type not in the dispatch table → ToolError."""
        from mcpyghidra.tools.core import _list_entries_sync

        backend = _make_backend()
        # The type annotation is EntryTypes but we pass an invalid string to hit the else branch.
        with pytest.raises(ToolError, match='Unsupported entry type'):
            _list_entries_sync(backend, 'totally_unknown', 0, 500, '')  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _list_strings — getValue() returns None (filter edge case)
# ---------------------------------------------------------------------------


class TestListStringsFilterEdge:
    """_list_strings skips entries where getValue() is None when match_filter is set."""

    def test_get_value_none_skips_entry_with_filter(self):
        """data.getValue() is None → data_string falls back to '' → filter mismatch → item excluded."""
        from mcpyghidra.tools.core import _list_strings

        backend = _make_backend()

        # Single data entry: has a string value but getValue() is None
        mock_data = MagicMock()
        mock_data.hasStringValue.return_value = True
        mock_data.getValue.return_value = None

        backend.program.getListing.return_value.getDefinedData.return_value = [mock_data]

        # With a match_filter that cannot match '' → item excluded → empty result (no ToolError
        # since offset=0 == total=0, not offset > total)
        result = _list_strings(backend, offset=0, limit=500, match_filter='secret')
        assert result.page_info.num_returned == 0

    def test_has_string_value_false_excluded(self):
        """data.hasStringValue() is False → filtered out entirely."""
        from mcpyghidra.tools.core import _list_strings

        backend = _make_backend()

        mock_data = MagicMock()
        mock_data.hasStringValue.return_value = False

        backend.program.getListing.return_value.getDefinedData.return_value = [mock_data]

        result = _list_strings(backend, offset=0, limit=500, match_filter='')
        assert result.page_info.num_returned == 0

    def test_process_string_get_value_none_yields_empty_string(self):
        """process_string uses '' when entry.getValue() is None."""
        from mcpyghidra.tools.core import _list_strings

        backend = _make_backend()

        mock_data = MagicMock()
        mock_data.hasStringValue.return_value = True
        mock_data.getValue.return_value = None
        mock_addr = MagicMock()
        mock_addr.offset = 0x400
        mock_data.getAddress.return_value = mock_addr

        backend.program.getListing.return_value.getDefinedData.return_value = [mock_data]

        # No match_filter → item passes the filter (hasStringValue=True, no filter check)
        result = _list_strings(backend, offset=0, limit=500, match_filter='')
        assert result.page_info.num_returned == 1
        assert result.items[0]['value'] == repr('')


# ---------------------------------------------------------------------------
# _get_current_location — GUI mode branches
# ---------------------------------------------------------------------------


class TestGetCurrentLocationGuiMode:
    """_get_current_location GUI mode: no _tool attr, code_viewer None, location None."""

    def _make_gui_backend(self) -> MagicMock:
        backend = _make_backend(is_headless=False)
        mock_base = MagicMock()
        mock_base.offset = 0x400000
        backend.program.getImageBase.return_value = mock_base
        return backend

    def test_no_tool_attr_returns_image_base(self):
        """When backend has no _tool attr, falls back to image base address."""
        from mcpyghidra.tools.core import _get_current_location

        backend = self._make_gui_backend()
        # Ensure getattr(backend, '_tool', None) returns None
        del backend._tool  # Remove auto-created MagicMock attribute
        backend._tool = None  # noqa: SIM910 — explicit None

        with patch.dict(sys.modules, {
            'ghidra.app.services': MagicMock(),
            'ghidra.program.util': MagicMock(),
        }):
            result = _get_current_location(backend)

        assert result.addr == '0x400000'

    def test_code_viewer_none_returns_image_base(self):
        """tool.getService returns None → falls back to image base."""
        from mcpyghidra.tools.core import _get_current_location

        backend = self._make_gui_backend()

        mock_tool = MagicMock()
        mock_tool.getService.return_value = None
        backend._tool = mock_tool

        mock_cv_service = MagicMock()
        mock_cv_service.class_ = MagicMock()

        with patch.dict(sys.modules, {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
            'ghidra.program.util': MagicMock(),
        }):
            result = _get_current_location(backend)

        assert result.addr == '0x400000'

    def test_location_none_returns_image_base(self):
        """code_viewer.getCurrentLocation() returns None → falls back to image base."""
        from mcpyghidra.tools.core import _get_current_location

        backend = self._make_gui_backend()

        mock_code_viewer = MagicMock()
        mock_code_viewer.getCurrentLocation.return_value = None

        mock_tool = MagicMock()
        mock_tool.getService.return_value = mock_code_viewer
        backend._tool = mock_tool

        mock_cv_service = MagicMock()
        mock_cv_service.class_ = MagicMock()

        with patch.dict(sys.modules, {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
            'ghidra.program.util': MagicMock(),
        }):
            result = _get_current_location(backend)

        assert result.addr == '0x400000'

    def test_gui_location_with_no_function_returns_addr_only(self):
        """getCurrentLocation returns a location, but no function at that address."""
        from mcpyghidra.tools.core import _get_current_location

        backend = self._make_gui_backend()

        mock_location = MagicMock()
        mock_addr = MagicMock()
        mock_addr.offset = 0x401000
        mock_location.getAddress.return_value = mock_addr

        mock_code_viewer = MagicMock()
        mock_code_viewer.getCurrentLocation.return_value = mock_location

        mock_tool = MagicMock()
        mock_tool.getService.return_value = mock_code_viewer
        backend._tool = mock_tool

        # No function at that address
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        mock_cv_service = MagicMock()
        mock_cv_service.class_ = MagicMock()

        with patch.dict(sys.modules, {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
            'ghidra.program.util': MagicMock(),
        }):
            result = _get_current_location(backend)

        assert result.addr == '0x401000'
        assert result.function is None

    def test_gui_location_with_function_populates_function_info(self):
        """getCurrentLocation with a function at address → FunctionInfo populated."""
        from mcpyghidra.tools.core import _get_current_location

        backend = self._make_gui_backend()

        mock_location = MagicMock()
        mock_addr = MagicMock()
        mock_addr.offset = 0x401000
        mock_location.getAddress.return_value = mock_addr

        mock_code_viewer = MagicMock()
        mock_code_viewer.getCurrentLocation.return_value = mock_location

        mock_tool = MagicMock()
        mock_tool.getService.return_value = mock_code_viewer
        backend._tool = mock_tool

        mock_func = MagicMock()
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = mock_func

        mock_dec = MagicMock()
        mock_dec.name = 'gui_func'
        mock_dec.entrypoint = '0x401000'
        mock_dec.signature = 'void gui_func()'
        backend.get_decompiled_func.return_value = mock_dec

        mock_cv_service = MagicMock()
        mock_cv_service.class_ = MagicMock()

        with patch.dict(sys.modules, {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
            'ghidra.program.util': MagicMock(),
        }):
            result = _get_current_location(backend)

        assert result.addr == '0x401000'
        assert result.function is not None
        assert result.function.name == 'gui_func'


# ---------------------------------------------------------------------------
# _context_sync — individual try-except fallback branches
# ---------------------------------------------------------------------------


class TestContextSyncFallbacks:
    """Each try-except block in _context_sync returns the documented fallback."""

    def _make_context_backend(self) -> MagicMock:
        """Backend where all calls succeed (default happy path).

        Every program method that feeds into Pydantic models must return a
        properly-typed value so that only the specific call under test fails.
        """
        backend = _make_backend()

        # ---- _get_current_location (headless path) ----
        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = False
        mock_funcs_it = MagicMock()
        mock_funcs_it.hasNext.return_value = False

        mock_base = MagicMock()
        mock_base.offset = 0x400000
        backend.program.getImageBase.return_value = mock_base

        # Symbol table used for _get_current_location AND has_debug_symbols loop
        mock_st = MagicMock()
        mock_st.getExternalEntryPointIterator.return_value = mock_entry_it
        mock_st.getAllSymbols.return_value = iter([])
        backend.program.getSymbolTable.return_value = mock_st

        # Function manager
        mock_fm = MagicMock()
        mock_fm.getFunctions.return_value = mock_funcs_it
        mock_fm.getFunctionContaining.return_value = None
        mock_fm.getFunctionCount.return_value = 0
        backend.program.getFunctionManager.return_value = mock_fm

        # ---- ProgramInfo fields ----
        backend.program.getExecutablePath.return_value = '/path/to/binary'
        backend.program.getName.return_value = 'binary'
        backend.program.getExecutableFormat.return_value = 'ELF'
        backend.program.getExecutableMD5.return_value = 'abc123'

        # ---- ArchitectureInfo fields ----
        mock_lang = MagicMock()
        mock_lang.getProcessor.return_value.toString.return_value = 'x86'
        mock_lang.isBigEndian.return_value = False
        backend.program.getLanguage.return_value = mock_lang
        backend.program.getDefaultPointerSize.return_value = 8

        mock_compiler_spec = MagicMock()
        mock_compiler_spec.getCompilerSpecID.return_value.getIdAsString.return_value = 'gcc'
        backend.program.getCompilerSpec.return_value = mock_compiler_spec

        # ---- MemoryLayout fields ----
        mock_min_addr = MagicMock()
        mock_min_addr.offset = 0x400000
        backend.program.getMinAddress.return_value = mock_min_addr

        mock_max_addr = MagicMock()
        mock_max_addr.offset = 0x7FFFFFFF
        backend.program.getMaxAddress.return_value = mock_max_addr

        # ---- AnalysisState fields ----
        mock_domain_file = MagicMock()
        mock_domain_file.getPathname.return_value = '/project/binary.gpr'
        backend.program.getDomainFile.return_value = mock_domain_file

        mock_dtm = MagicMock()
        mock_dtm.getDataTypeCount.return_value = 50
        backend.program.getDataTypeManager.return_value = mock_dtm

        return backend

    def test_file_path_exception_returns_none(self):
        """getExecutablePath() raises → file_path is None."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getExecutablePath.side_effect = RuntimeError('no path')

        result = _context_sync(backend)
        assert result.program.file_path is None

    def test_file_name_exception_returns_unknown(self):
        """getName() raises → file_name is 'unknown'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getName.side_effect = RuntimeError('boom')

        result = _context_sync(backend)
        assert result.program.file_name == 'unknown'

    def test_file_format_exception_returns_unknown(self):
        """getExecutableFormat() raises → file_format is 'unknown'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getExecutableFormat.side_effect = RuntimeError('no format')

        result = _context_sync(backend)
        assert result.program.file_format == 'unknown'

    def test_processor_exception_returns_unknown(self):
        """getLanguage().getProcessor() raises → processor is 'unknown'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getLanguage.side_effect = RuntimeError('no lang')

        result = _context_sync(backend)
        assert result.architecture.processor == 'unknown'

    def test_bitness_exception_returns_32(self):
        """getDefaultPointerSize() raises → bitness defaults to 32."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        # Keep getLanguage returning proper strings for processor/endianness
        mock_lang = MagicMock()
        mock_lang.getProcessor.return_value.toString.return_value = 'x86'
        mock_lang.isBigEndian.return_value = False
        backend.program.getLanguage.return_value = mock_lang
        backend.program.getDefaultPointerSize.side_effect = RuntimeError('no ptr size')

        result = _context_sync(backend)
        assert result.architecture.bitness == 32

    def test_endianness_exception_returns_unknown(self):
        """isBigEndian() raises → endianness is 'unknown'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        mock_lang = MagicMock()
        mock_lang.getProcessor.return_value.toString.return_value = 'x86'
        mock_lang.isBigEndian.side_effect = RuntimeError('no endian')
        backend.program.getLanguage.return_value = mock_lang

        result = _context_sync(backend)
        assert result.architecture.endianness == 'unknown'

    def test_compiler_exception_returns_none(self):
        """getCompilerSpec() raises → compiler is None."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getCompilerSpec.side_effect = RuntimeError('no compiler')

        result = _context_sync(backend)
        assert result.architecture.compiler is None

    def test_image_base_exception_returns_zero(self):
        """getImageBase() raises for _context_sync's memory block → image_base is '0x0'.

        Strategy: make _get_current_location succeed (via normal headless path without
        needing getImageBase), then have getImageBase raise for _context_sync's own try.
        """
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()

        # Override the headless current-location path: give a valid entry iterator so
        # _get_current_location returns without calling getImageBase at all.
        mock_entry_addr = MagicMock()
        mock_entry_addr.offset = 0x401000
        mock_entry_it2 = MagicMock()
        mock_entry_it2.hasNext.return_value = True
        mock_entry_it2.next.return_value = mock_entry_addr

        mock_st2 = MagicMock()
        mock_st2.getExternalEntryPointIterator.return_value = mock_entry_it2
        mock_st2.getAllSymbols.return_value = iter([])
        backend.program.getSymbolTable.return_value = mock_st2

        # FunctionManager: no function at the entry addr so no decompile
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        # Now make getImageBase raise — _context_sync's try-except for image_base fires
        backend.program.getImageBase.side_effect = RuntimeError('no base')

        result = _context_sync(backend)
        assert result.memory.image_base == '0x0'

    def test_min_address_exception_returns_zero(self):
        """getMinAddress() raises → min_address is '0x0'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getMinAddress.side_effect = RuntimeError('no min')

        result = _context_sync(backend)
        assert result.memory.min_address == '0x0'

    def test_max_address_exception_returns_ffffffff(self):
        """getMaxAddress() raises → max_address is '0xffffffff'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getMaxAddress.side_effect = RuntimeError('no max')

        result = _context_sync(backend)
        assert result.memory.max_address == '0xffffffff'

    def test_database_path_exception_returns_unknown(self):
        """getDomainFile().getPathname() raises → database_path is 'unknown'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getDomainFile.side_effect = RuntimeError('no domain')

        result = _context_sync(backend)
        assert result.analysis.database_path == 'unknown'

    def test_function_count_exception_returns_zero(self):
        """getFunctionCount() raises → function_count is 0."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getFunctionManager.return_value.getFunctionCount.side_effect = (
            RuntimeError('no count')
        )

        result = _context_sync(backend)
        assert result.analysis.function_count == 0

    def test_application_info_exception_returns_ghidra_defaults(self):
        """Application.getName() raises → app_name='Ghidra', app_version='unknown'."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()

        # Replace the ghidra.framework module with one whose Application raises
        mock_app = MagicMock()
        mock_app.getName.side_effect = RuntimeError('no app')
        mock_framework_bad = MagicMock()
        mock_framework_bad.Application = mock_app

        with patch.dict(sys.modules, {'ghidra.framework': mock_framework_bad}):
            result = _context_sync(backend)

        assert result.application.name == 'Ghidra'
        assert result.application.version == 'unknown'

    def test_md5_exception_returns_none(self):
        """getExecutableMD5() raises → md5 is None."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getExecutableMD5.side_effect = RuntimeError('no md5')

        result = _context_sync(backend)
        assert result.program.md5 is None

    def test_entry_point_exception_falls_back_to_image_base(self):
        """getExternalEntryPointIterator() raises in _context_sync's entry_point try block.

        Strategy: patch the symbol-table so the first call (inside _get_current_location)
        returns a valid iterator, and the second call (inside _context_sync) raises.
        """
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()

        mock_base = MagicMock()
        mock_base.offset = 0x400000
        backend.program.getImageBase.return_value = mock_base

        # Prepare two different symbol-table objects: first succeeds, second raises.
        mock_entry_it_ok = MagicMock()
        mock_entry_it_ok.hasNext.return_value = False
        mock_st_ok = MagicMock()
        mock_st_ok.getExternalEntryPointIterator.return_value = mock_entry_it_ok
        mock_st_ok.getAllSymbols.return_value = iter([])

        mock_st_bad = MagicMock()
        mock_st_bad.getExternalEntryPointIterator.side_effect = RuntimeError('gone')
        mock_st_bad.getAllSymbols.return_value = iter([])

        call_count: list[int] = [0]

        def getSymbolTable_side_effect():
            call_count[0] += 1
            # Call 1 is from _get_current_location (headless), call 2+ from _context_sync.
            return mock_st_ok if call_count[0] == 1 else mock_st_bad

        backend.program.getSymbolTable.side_effect = getSymbolTable_side_effect

        result = _context_sync(backend)
        assert result.memory.entry_point == result.memory.image_base


# ---------------------------------------------------------------------------
# _funcs_sync — hex-like string detection (address vs name disambiguation)
# ---------------------------------------------------------------------------


class TestFuncsSyncAddressDetection:
    """_funcs_sync address detection: pure hex digits treated as address."""

    def test_pure_hex_digits_treated_as_address(self):
        """'deadbeef' (all hex chars, no 0x prefix) → looked up as address."""
        from mcpyghidra.tools.core import _funcs_sync

        backend = _make_backend()
        mock_addr = MagicMock()
        mock_addr.offset = 0xDEADBEEF
        backend.program.getAddressFactory.return_value.getAddress.return_value = mock_addr
        # Function not found at that address
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        results = _funcs_sync(backend, ['deadbeef'])
        assert len(results) == 1
        assert 'error' in results[0]
        # Confirm the error mentions an address, not a name
        assert 'address' in results[0]['error'].lower()

    def test_non_hex_string_treated_as_name(self):
        """'main' (not all hex chars) → looked up by name."""
        from mcpyghidra.tools.core import _funcs_sync

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        results = _funcs_sync(backend, ['main'])
        assert len(results) == 1
        assert 'error' in results[0]
        assert 'name' in results[0]['error'].lower()

    def test_0x_prefix_treated_as_address(self):
        """'0x1234' (starts with 0x) → looked up as address."""
        from mcpyghidra.tools.core import _funcs_sync

        backend = _make_backend()
        mock_addr = MagicMock()
        mock_addr.offset = 0x1234
        backend.program.getAddressFactory.return_value.getAddress.return_value = mock_addr
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        results = _funcs_sync(backend, ['0x1234'])
        assert len(results) == 1
        assert 'error' in results[0]
        assert 'address' in results[0]['error'].lower()

    def test_successful_function_lookup_by_name(self):
        """Name lookup succeeds → result dict has name, entrypoint, signature, error=None."""
        from mcpyghidra.tools.core import _funcs_sync

        backend = _make_backend()
        mock_func = MagicMock()
        backend.flat_api.getFunction.return_value = mock_func

        mock_dec = MagicMock()
        mock_dec.name = 'my_func'
        mock_dec.entrypoint = '0x1000'
        mock_dec.signature = 'void my_func()'
        backend.get_decompiled_func.return_value = mock_dec

        results = _funcs_sync(backend, ['my_func'])
        assert len(results) == 1
        assert results[0]['error'] is None
        assert results[0]['name'] == 'my_func'


# ---------------------------------------------------------------------------
# _normalize_format — branch coverage
# ---------------------------------------------------------------------------


class TestNormalizeFormat:
    """_normalize_format maps verbose format strings to short labels."""

    def test_pe_format(self):
        from mcpyghidra.tools.core import _normalize_format
        assert _normalize_format('Portable Executable (PE)') == 'PE'

    def test_elf_format(self):
        from mcpyghidra.tools.core import _normalize_format
        assert _normalize_format('ELF Linux') == 'ELF'

    def test_macho_format(self):
        from mcpyghidra.tools.core import _normalize_format
        assert _normalize_format('Mach-O ARM') == 'Mach-O'

    def test_macos_format(self):
        from mcpyghidra.tools.core import _normalize_format
        assert _normalize_format('Mac OS X Universal Binary') == 'Mach-O'

    def test_coff_format(self):
        from mcpyghidra.tools.core import _normalize_format
        assert _normalize_format('COFF') == 'COFF'

    def test_unknown_format_passthrough(self):
        from mcpyghidra.tools.core import _normalize_format
        assert _normalize_format('SomeObscureFormat') == 'SomeObscureFormat'


# ---------------------------------------------------------------------------
# _tool_result_list_formatter — _Skip exception branch
# ---------------------------------------------------------------------------


class TestToolResultListFormatterSkip:
    """entry_proc raising _Skip causes the item to be silently skipped."""

    def test_skip_exception_excludes_item(self):
        """A _Skip from entry_proc does not abort; the item is simply omitted."""
        from mcpyghidra.tools.core import _tool_result_list_formatter, _Skip

        def always_skip(entry):
            raise _Skip

        result = _tool_result_list_formatter(
            results_heading='Test',
            entry_type='function',
            entry_proc=always_skip,
            entries=['a', 'b', 'c'],
            offset=0,
            limit=500,
        )
        # All items were skipped; result should be empty (no ToolError since offset=0, total=3)
        assert result.page_info.num_returned == 0
        assert result.items == []

    def test_mixed_skip_and_success(self):
        """Only non-skipped items appear in result.items; skipped items are omitted."""
        from mcpyghidra.tools.core import _tool_result_list_formatter, _Skip

        def skip_odd(entry):
            if entry % 2 != 0:
                raise _Skip
            return {'type': 'function', 'name': str(entry), 'address': '0x0'}

        result = _tool_result_list_formatter(
            results_heading='Evens',
            entry_type='function',
            entry_proc=skip_odd,
            entries=[1, 2, 3, 4],
            offset=0,
            limit=500,
        )
        # items only contains even entries (skip_odd dropped odds)
        names = [item['name'] for item in result.items]
        assert names == ['2', '4']
        # num_returned is stop-start (the page slice size), skips do not shrink it
        assert len(result.items) == 2


# ---------------------------------------------------------------------------
# _get_current_location — headless fallback branches
# ---------------------------------------------------------------------------


class TestGetCurrentLocationHeadless:
    """Headless path fallback branches in _get_current_location."""

    def test_headless_no_entry_no_funcs_uses_image_base(self):
        """No entry points and no functions → addr is image base."""
        from mcpyghidra.tools.core import _get_current_location

        backend = _make_backend(is_headless=True)

        # Symbol table: no entry points
        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = False
        backend.program.getSymbolTable.return_value.getExternalEntryPointIterator.return_value = (
            mock_entry_it
        )

        # Function manager: no functions
        mock_funcs = MagicMock()
        mock_funcs.hasNext.return_value = False
        backend.program.getFunctionManager.return_value.getFunctions.return_value = mock_funcs

        # Image base
        mock_base = MagicMock()
        mock_base.offset = 0x400000
        backend.program.getImageBase.return_value = mock_base

        # No function at image base
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = _get_current_location(backend)
        assert result.addr == '0x400000'

    def test_headless_with_entry_point_and_function(self):
        """Entry point iterator has next → addr is entry address; function populated."""
        from mcpyghidra.tools.core import _get_current_location

        backend = _make_backend(is_headless=True)

        mock_entry_addr = MagicMock()
        mock_entry_addr.offset = 0x401000

        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = True
        mock_entry_it.next.return_value = mock_entry_addr
        backend.program.getSymbolTable.return_value.getExternalEntryPointIterator.return_value = (
            mock_entry_it
        )

        mock_func = MagicMock()
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = (
            mock_func
        )

        mock_dec = MagicMock()
        mock_dec.name = 'entry_func'
        mock_dec.entrypoint = '0x401000'
        mock_dec.signature = 'void entry_func()'
        backend.get_decompiled_func.return_value = mock_dec

        result = _get_current_location(backend)
        assert result.addr == '0x401000'
        assert result.function is not None
        assert result.function.name == 'entry_func'

    def test_headless_exception_falls_back_to_image_base(self):
        """Any exception inside the headless try block → CurrentLocation(image_base)."""
        from mcpyghidra.tools.core import _get_current_location

        backend = _make_backend(is_headless=True)
        # Make getSymbolTable raise immediately to trigger the except branch
        backend.program.getSymbolTable.side_effect = RuntimeError('crash')

        mock_base = MagicMock()
        mock_base.offset = 0x400000
        backend.program.getImageBase.return_value = mock_base

        result = _get_current_location(backend)
        assert result.addr == '0x400000'

    def test_headless_first_func_used_when_no_entry_point(self):
        """No entry points but functions exist → addr is first function's entry point."""
        from mcpyghidra.tools.core import _get_current_location

        backend = _make_backend(is_headless=True)

        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = False
        backend.program.getSymbolTable.return_value.getExternalEntryPointIterator.return_value = (
            mock_entry_it
        )

        mock_func_addr = MagicMock()
        mock_func_addr.offset = 0x402000

        mock_func = MagicMock()
        mock_func.getEntryPoint.return_value = mock_func_addr

        mock_funcs = MagicMock()
        mock_funcs.hasNext.return_value = True
        mock_funcs.next.return_value = mock_func

        backend.program.getFunctionManager.return_value.getFunctions.return_value = mock_funcs
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = _get_current_location(backend)
        assert result.addr == '0x402000'


# ---------------------------------------------------------------------------
# list_entries async validation branches
# ---------------------------------------------------------------------------


import anyio  # noqa: E402 — placed after mocks are installed


def _run_async(async_fn, *args, **kwargs):
    """Run an async tool function synchronously for unit tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


class TestListEntriesAsyncValidation:
    """list_entries async wrapper: offset/limit validation and null-coalescing."""

    def test_negative_offset_raises(self):
        """offset < 0 → ToolError."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        with pytest.raises(ToolError, match='offset must be non-negative'):
            _run_async(list_entries, backend, entry_type='function', offset=-1, limit=10)

    def test_zero_limit_raises(self):
        """limit <= 0 → ToolError."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        with pytest.raises(ToolError, match='limit must be positive'):
            _run_async(list_entries, backend, entry_type='function', offset=0, limit=0)

    def test_none_match_filter_coerced_to_empty(self):
        """match_filter=None is coerced to '' before dispatch."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        backend.program.getFunctionManager.return_value.getFunctions.return_value = iter([])

        # No ToolError expected; empty result returned
        result = _run_async(list_entries, backend, entry_type='function', offset=0, limit=10, match_filter=None)
        assert result.items == []

    def test_string_offset_coerced_to_int(self):
        """offset='0' (string) → converted to int 0 without raising."""
        from mcpyghidra.tools.core import list_entries

        backend = _make_backend()
        backend.program.getFunctionManager.return_value.getFunctions.return_value = iter([])

        # offset='0' exercises the int(offset) conversion branch; result is empty but valid
        result = _run_async(list_entries, backend, entry_type='function', offset='0', limit=10)
        assert result.page_info.offset == 0


# ---------------------------------------------------------------------------
# _list_entries_sync dispatch branches (remaining entry types)
# ---------------------------------------------------------------------------


class TestListEntriesSyncDispatch:
    """_list_entries_sync routes correctly to each sub-dispatcher."""

    def _make_empty_iter_backend(self) -> MagicMock:
        backend = _make_backend()
        backend.program.getMemory.return_value.getBlocks.return_value = []
        backend.program.getSymbolTable.return_value.getExternalSymbols.return_value = []
        backend.program.getSymbolTable.return_value.getAllSymbols.return_value = iter([])
        backend.program.getListing.return_value.getDefinedData.return_value = iter([])
        return backend

    def test_memory_segment_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        result = _list_entries_sync(backend, 'memory_segment', 0, 500, '')
        assert result.entry_type == 'memory_segment'

    def test_import_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        result = _list_entries_sync(backend, 'import', 0, 500, '')
        assert result.entry_type == 'import'

    def test_export_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        result = _list_entries_sync(backend, 'export', 0, 500, '')
        assert result.entry_type == 'export'

    def test_string_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        result = _list_entries_sync(backend, 'string', 0, 500, '')
        assert result.entry_type == 'string'

    def test_class_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        # _list_classes uses SymbolType.CLASS — the stub has it as a MagicMock attribute
        result = _list_entries_sync(backend, 'class', 0, 500, '')
        assert result.entry_type == 'class'

    def test_namespace_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        result = _list_entries_sync(backend, 'namespace', 0, 500, '')
        assert result.entry_type == 'namespace'

    def test_function_dispatch(self):
        from mcpyghidra.tools.core import _list_entries_sync

        backend = self._make_empty_iter_backend()
        backend.program.getFunctionManager.return_value.getFunctions.return_value = iter([])
        result = _list_entries_sync(backend, 'function', 0, 500, '')
        assert result.entry_type == 'function'


# ---------------------------------------------------------------------------
# _context_sync — file_size branch and debug-symbols / type-libraries branches
# ---------------------------------------------------------------------------


class TestContextSyncBranches:
    """Additional branches in _context_sync not covered by TestContextSyncFallbacks."""

    def _make_context_backend(self) -> MagicMock:
        """Re-use the same factory from TestContextSyncFallbacks (DRY via delegation)."""
        return TestContextSyncFallbacks()._make_context_backend()

    def test_has_debug_symbols_true_when_file_symbol_present(self):
        """has_debug_symbols is True when a FILE-type symbol is found."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()

        # Build a symbol whose getSymbolType() matches SymbolType.FILE
        mock_symbol_type_module = sys.modules['ghidra.program.model.symbol']
        file_type_sentinel = object()
        mock_symbol_type_module.SymbolType.FILE = file_type_sentinel

        mock_sym = MagicMock()
        mock_sym.getSymbolType.return_value = file_type_sentinel

        mock_st = MagicMock()
        mock_st.getExternalEntryPointIterator.return_value = MagicMock(hasNext=MagicMock(return_value=False))
        mock_st.getAllSymbols.return_value = iter([mock_sym])
        backend.program.getSymbolTable.return_value = mock_st

        result = _context_sync(backend)
        assert result.analysis.has_debug_symbols is True

    def test_has_type_libraries_true_when_many_types(self):
        """has_type_libraries is True when data type count > 100."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getDataTypeManager.return_value.getDataTypeCount.return_value = 101

        result = _context_sync(backend)
        assert result.analysis.has_type_libraries is True

    def test_has_type_libraries_false_when_few_types(self):
        """has_type_libraries is False when data type count <= 100."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getDataTypeManager.return_value.getDataTypeCount.return_value = 50

        result = _context_sync(backend)
        assert result.analysis.has_type_libraries is False

    def test_entry_point_from_func_manager_when_no_symbol_entry(self):
        """Entry point falls back to first function when symbol table has no entry."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()

        mock_ep_addr = MagicMock()
        mock_ep_addr.offset = 0x401000

        mock_first_func = MagicMock()
        mock_first_func.getEntryPoint.return_value = mock_ep_addr

        mock_funcs_it = MagicMock()
        mock_funcs_it.hasNext.return_value = True
        mock_funcs_it.next.return_value = mock_first_func

        # Symbol table: no external entry points; getFunctions has one
        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = False

        mock_st = MagicMock()
        mock_st.getExternalEntryPointIterator.return_value = mock_entry_it
        mock_st.getAllSymbols.return_value = iter([])
        backend.program.getSymbolTable.return_value = mock_st

        backend.program.getFunctionManager.return_value.getFunctions.return_value = mock_funcs_it

        result = _context_sync(backend)
        assert result.memory.entry_point == '0x401000'

    def test_file_size_set_when_java_file_succeeds(self):
        """When file_path is set and java.io.File returns a size, file_size is populated."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getExecutablePath.return_value = '/some/file'

        # core.py does `import java.io.File; int(java.io.File(path).length())`.
        # After the `import`, Python resolves `java` → sys.modules['java'] and then
        # traverses .io.File(…).length().  We must patch sys.modules['java'].io.File.
        mock_java_mod = sys.modules['java']
        mock_java_mod.io.File.return_value.length.return_value = 12345

        result = _context_sync(backend)
        assert result.program.file_size == 12345

    def test_file_size_none_when_java_file_raises(self):
        """When java.io.File constructor raises, file_size stays None (not fatal)."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()
        backend.program.getExecutablePath.return_value = '/some/file'

        mock_java_mod = sys.modules['java']
        mock_java_mod.io.File.side_effect = RuntimeError('no java')

        try:
            result = _context_sync(backend)
            assert result.program.file_size is None
        finally:
            mock_java_mod.io.File.side_effect = None

    def test_entry_point_is_image_base_when_no_funcs_and_no_symbol(self):
        """No entry symbol AND no functions → entry_point equals image_base."""
        from mcpyghidra.tools.core import _context_sync

        backend = self._make_context_backend()

        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = False
        mock_funcs_it = MagicMock()
        mock_funcs_it.hasNext.return_value = False

        mock_st = MagicMock()
        mock_st.getExternalEntryPointIterator.return_value = mock_entry_it
        mock_st.getAllSymbols.return_value = iter([])
        backend.program.getSymbolTable.return_value = mock_st

        backend.program.getFunctionManager.return_value.getFunctions.return_value = mock_funcs_it

        result = _context_sync(backend)
        assert result.memory.entry_point == result.memory.image_base


# ---------------------------------------------------------------------------
# _context_sync — big-endian branch
# ---------------------------------------------------------------------------


class TestContextSyncBigEndian:
    """endianness='big' branch in _context_sync."""

    def test_big_endian_reported(self):
        """isBigEndian() returns True → endianness is 'big'."""
        from mcpyghidra.tools.core import _context_sync

        backend = TestContextSyncFallbacks()._make_context_backend()
        mock_lang = MagicMock()
        mock_lang.getProcessor.return_value.toString.return_value = 'MIPS'
        mock_lang.isBigEndian.return_value = True
        backend.program.getLanguage.return_value = mock_lang

        result = _context_sync(backend)
        assert result.architecture.endianness == 'big'


# ---------------------------------------------------------------------------
# cursor / context async wrappers (smoke test only — logic is in sync helpers)
# ---------------------------------------------------------------------------


class TestAsyncWrappers:
    """cursor() and context() async wrappers delegate to sync helpers."""

    def test_cursor_returns_current_location(self):
        """cursor() is callable and returns a CurrentLocation."""
        from mcpyghidra.tools.core import cursor

        backend = _make_backend(is_headless=True)
        mock_entry_it = MagicMock()
        mock_entry_it.hasNext.return_value = False
        backend.program.getSymbolTable.return_value.getExternalEntryPointIterator.return_value = (
            mock_entry_it
        )
        mock_funcs_it = MagicMock()
        mock_funcs_it.hasNext.return_value = False
        backend.program.getFunctionManager.return_value.getFunctions.return_value = mock_funcs_it
        mock_base = MagicMock()
        mock_base.offset = 0x400000
        backend.program.getImageBase.return_value = mock_base
        backend.program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = _run_async(cursor, backend)
        assert result.addr == '0x400000'

    def test_funcs_single_string_coerced_to_list(self):
        """funcs() normalises a non-list items arg to a list."""
        from mcpyghidra.tools.core import funcs

        backend = _make_backend()
        backend.flat_api.getFunction.return_value = None

        # Passing a plain string (not a list) exercises the `if not isinstance(items, list)` branch
        results = _run_async(funcs, backend, 'not_a_list')  # type: ignore[arg-type]
        assert isinstance(results, list)
        assert len(results) == 1
