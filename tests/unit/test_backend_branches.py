"""Unit tests for backend.py — branch coverage expansion.

Targets: src/mcpyghidra/backend.py
Goal:    75%+ line / ~95% branch

All Java / Ghidra imports are mocked via sys.modules so tests run without a
live Ghidra environment.

Branches covered:

1.  GhidraBackend.__init__ — _decompiled_funcs and _batch_state initialised
2.  GhidraBackend.begin_batch / end_batch — clears _batch_state
3.  GhidraBackend.get_decompiled_func — cache hit (reset=False, func already cached)
4.  GhidraBackend.get_decompiled_func — cache miss → DecompiledFunction created
5.  GhidraBackend.get_decompiled_func — reset=True forces re-decompile even when cached
6.  GhidraBackend.clear_decompilation_cache — clears _decompiled_funcs
7.  GhidraBackend.create_transaction — returns GhidraTransactionContext
8.  HeadlessBackend.is_headless — always True
9.  HeadlessBackend.get_overwrite_policy — always 'ask'
10. HeadlessBackend.confirm_overwrite — anyio bridge succeeds → returns bool from async
11. HeadlessBackend.confirm_overwrite — anyio bridge raises → fallback True
12. HeadlessBackend.log — maps 'warn' → 'warning'; valid level passes through
13. HeadlessBackend.log — unknown level falls back to logger.info
14. HeadlessBackend.get_data_type_managers — returns list with program's DTM
15. PluginBackend.is_headless — CodeViewerService not None → False
16. PluginBackend.is_headless — getService returns None → True
17. PluginBackend.is_headless — getService raises → True
18. PluginBackend.get_overwrite_policy — policy found in OverwritePolicy enum
19. PluginBackend.get_overwrite_policy — raw value not in enum → 'ask'
20. PluginBackend.get_overwrite_policy — getOptions raises → 'ask'
21. PluginBackend.confirm_overwrite — MCP context present → anyio bridge called
22. PluginBackend.confirm_overwrite — MCP context present, bridge raises → True
23. PluginBackend.confirm_overwrite — no context, always_allow → True
24. PluginBackend.confirm_overwrite — no context, always_skip → False
25. PluginBackend.confirm_overwrite — no context, is_headless=True → True
26. PluginBackend.get_data_type_managers — service available, extra managers appended
27. PluginBackend.get_data_type_managers — service unavailable (import fails) → program DTM only
28. GhidraError — is an Exception subclass
"""
from __future__ import annotations

import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub Ghidra / Java / pyghidra packages used by backend.py
# NOTE: mcpyghidra.server is intentionally NOT stubbed here — it is provided
# per-test via the _mock_server_in_sys_modules autouse fixture below so that
# the real mcpyghidra.server module is never permanently replaced in
# sys.modules (which would break test_server_info.py and others).
# ---------------------------------------------------------------------------
_STUBS = [
    'ghidra',
    'ghidra.app',
    'ghidra.app.services',
    'ghidra.program',
    'ghidra.program.flatapi',
    'ghidra.util',
    'pyghidra_decaf',
    'pyghidra_decaf.tamer',
    'pyghidra_decaf.tamer.program',
    'anyio',
    'anyio.from_thread',
]
for _mod in _STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# ---------------------------------------------------------------------------
# Module-level mock server object used by per-test patch.dict and by the
# inline attribute assignments inside individual test functions.
# ---------------------------------------------------------------------------
_MOCK_SERVER = MagicMock()
_MOCK_SERVER.get_current_context = MagicMock(return_value=None)
_MOCK_SERVER.elicit_confirmation = AsyncMock(return_value=True)


@pytest.fixture(autouse=True)
def _mock_server_in_sys_modules():
    """Install _MOCK_SERVER as sys.modules['mcpyghidra.server'] for each test.

    Using patch.dict ensures the real mcpyghidra.server is restored after
    every test, regardless of how the test mutates the stub's attributes.
    """
    with patch.dict(sys.modules, {'mcpyghidra.server': _MOCK_SERVER}):
        yield

# ---------------------------------------------------------------------------
# Imports (after stubs are in place)
# ---------------------------------------------------------------------------
from mcpyghidra.backend import (  # noqa: E402
    GhidraBackend,
    GhidraError,
    HeadlessBackend,
    OverwritePolicy,
    PluginBackend,
)

# ---------------------------------------------------------------------------
# Concrete minimal subclass of GhidraBackend for testing abstract base
# ---------------------------------------------------------------------------


class _ConcreteBackend(GhidraBackend):
    """Minimal non-abstract subclass for testing GhidraBackend shared methods."""

    def __init__(self, program: Any = None) -> None:
        super().__init__()
        self._program = program or MagicMock()

    @property
    def program(self) -> Any:
        return self._program

    @property
    def flat_api(self) -> Any:
        return MagicMock()

    @property
    def is_headless(self) -> bool:
        return True

    def get_overwrite_policy(self):
        return 'ask'

    def confirm_overwrite(self, description: str) -> bool:
        return True

    def log(self, level: str, message: str) -> None:
        pass

    def get_data_type_managers(self) -> list:
        return []


# ---------------------------------------------------------------------------
# 1. GhidraError is an Exception subclass
# ---------------------------------------------------------------------------


def test_ghidra_error_is_exception():
    err = GhidraError('boom')
    assert isinstance(err, Exception)
    assert str(err) == 'boom'


# ---------------------------------------------------------------------------
# 2. GhidraBackend.__init__ sets up _decompiled_funcs and _batch_state
# ---------------------------------------------------------------------------


def test_ghidra_backend_init_state():
    backend = _ConcreteBackend()
    assert backend._decompiled_funcs == {}
    assert backend._batch_state == {}


# ---------------------------------------------------------------------------
# 3. begin_batch / end_batch clear _batch_state
# ---------------------------------------------------------------------------


def test_begin_batch_clears_state():
    backend = _ConcreteBackend()
    backend._batch_state = {'key': 'value'}
    backend.begin_batch()
    assert backend._batch_state == {}


def test_end_batch_clears_state():
    backend = _ConcreteBackend()
    backend._batch_state = {'x': 1}
    backend.end_batch()
    assert backend._batch_state == {}


# ---------------------------------------------------------------------------
# 4. create_transaction returns GhidraTransactionContext
# ---------------------------------------------------------------------------


def test_create_transaction_returns_context():
    backend = _ConcreteBackend()
    mock_ctx = MagicMock()
    mock_ctx_class = MagicMock(return_value=mock_ctx)
    sys.modules['pyghidra_decaf.tamer.program'].GhidraTransactionContext = mock_ctx_class

    result = backend.create_transaction('test desc')

    mock_ctx_class.assert_called_once_with(backend._program, 'test desc')
    assert result is mock_ctx


def test_create_transaction_default_desc():
    backend = _ConcreteBackend()
    mock_ctx = MagicMock()
    mock_ctx_class = MagicMock(return_value=mock_ctx)
    sys.modules['pyghidra_decaf.tamer.program'].GhidraTransactionContext = mock_ctx_class

    result = backend.create_transaction()  # default desc=''
    mock_ctx_class.assert_called_once_with(backend._program, '')
    assert result is mock_ctx


# ---------------------------------------------------------------------------
# 5. get_decompiled_func — cache miss → creates DecompiledFunction
# ---------------------------------------------------------------------------


def test_get_decompiled_func_cache_miss():
    backend = _ConcreteBackend()

    mock_dec = MagicMock()
    mock_dec_class = MagicMock(return_value=mock_dec)
    sys.modules['pyghidra_decaf.tamer.program'].DecompiledFunction = mock_dec_class

    mock_func = MagicMock()
    mock_func.getEntryPoint.return_value.offset = 0x1000

    result = backend.get_decompiled_func(mock_func)

    # flat_api is a property returning a new MagicMock each time, so we can't
    # compare object identity — just verify DecompiledFunction was called once
    # with mock_func as the second positional argument.
    mock_dec_class.assert_called_once()
    call_pos_args = mock_dec_class.call_args[0]  # positional args tuple
    assert call_pos_args[1] is mock_func
    assert result is mock_dec
    assert backend._decompiled_funcs[0x1000] is mock_dec


# ---------------------------------------------------------------------------
# 6. get_decompiled_func — cache hit (reset=False) → returns cached
# ---------------------------------------------------------------------------


def test_get_decompiled_func_cache_hit():
    backend = _ConcreteBackend()

    cached_dec = MagicMock()
    mock_dec_class = MagicMock()  # should NOT be called
    sys.modules['pyghidra_decaf.tamer.program'].DecompiledFunction = mock_dec_class

    mock_func = MagicMock()
    mock_func.getEntryPoint.return_value.offset = 0x2000
    backend._decompiled_funcs[0x2000] = cached_dec

    result = backend.get_decompiled_func(mock_func, reset=False)

    mock_dec_class.assert_not_called()
    assert result is cached_dec


# ---------------------------------------------------------------------------
# 7. get_decompiled_func — reset=True forces re-decompile even when cached
# ---------------------------------------------------------------------------


def test_get_decompiled_func_reset_true_re_decompiles():
    backend = _ConcreteBackend()

    old_dec = MagicMock()
    new_dec = MagicMock()
    mock_dec_class = MagicMock(return_value=new_dec)
    sys.modules['pyghidra_decaf.tamer.program'].DecompiledFunction = mock_dec_class

    mock_func = MagicMock()
    mock_func.getEntryPoint.return_value.offset = 0x3000
    backend._decompiled_funcs[0x3000] = old_dec

    result = backend.get_decompiled_func(mock_func, reset=True)

    mock_dec_class.assert_called_once()
    assert result is new_dec
    assert backend._decompiled_funcs[0x3000] is new_dec


# ---------------------------------------------------------------------------
# 8. clear_decompilation_cache — empties _decompiled_funcs
# ---------------------------------------------------------------------------


def test_clear_decompilation_cache():
    backend = _ConcreteBackend()
    backend._decompiled_funcs = {0x1000: MagicMock(), 0x2000: MagicMock()}
    backend.clear_decompilation_cache()
    assert backend._decompiled_funcs == {}


# ---------------------------------------------------------------------------
# HeadlessBackend tests
# (HeadlessBackend.__init__ calls FlatProgramAPI which we need to stub)
# ---------------------------------------------------------------------------


def _make_headless_backend() -> HeadlessBackend:
    """Create a HeadlessBackend with fully-mocked Java objects."""
    mock_program = MagicMock()
    mock_flat_api_class = MagicMock()
    sys.modules['ghidra.program.flatapi'].FlatProgramAPI = mock_flat_api_class
    return HeadlessBackend(mock_program)


def test_headless_is_headless_true():
    backend = _make_headless_backend()
    assert backend.is_headless is True


def test_headless_get_overwrite_policy_returns_ask():
    backend = _make_headless_backend()
    assert backend.get_overwrite_policy() == 'ask'


def test_headless_confirm_overwrite_bridge_succeeds():
    """anyio.from_thread.run() succeeds → returns the async result."""
    backend = _make_headless_backend()

    with patch('anyio.from_thread') as mock_anyio_from_thread:
        mock_anyio_from_thread.run.return_value = False  # async returns False → skip
        result = backend.confirm_overwrite('rename foo at 0x1000?')

    assert result is False
    mock_anyio_from_thread.run.assert_called_once()


def test_headless_confirm_overwrite_bridge_raises_returns_true():
    """anyio.from_thread.run() raises (no portal) → fallback True."""
    backend = _make_headless_backend()

    with patch('anyio.from_thread') as mock_anyio_from_thread:
        mock_anyio_from_thread.run.side_effect = RuntimeError('no portal')
        result = backend.confirm_overwrite('rename foo at 0x1000?')

    assert result is True


def test_headless_log_warn_maps_to_warning():
    """log('warn', ...) must call logger.warning, not logger.warn."""
    backend = _make_headless_backend()
    with patch.object(backend._logger, 'warning') as mock_warn, \
         patch.object(backend._logger, 'warn', create=True) as mock_warn_bad:
        backend.log('warn', 'test message')
        mock_warn.assert_called_once_with('test message')
        mock_warn_bad.assert_not_called()


def test_headless_log_info_level():
    """log('info', ...) calls logger.info."""
    backend = _make_headless_backend()
    with patch.object(backend._logger, 'info') as mock_info:
        backend.log('info', 'hello')
        mock_info.assert_called_once_with('hello')


def test_headless_log_unknown_level_falls_back_to_info():
    """log('bogus', ...) uses getattr fallback → logger.info."""
    backend = _make_headless_backend()
    with patch.object(backend._logger, 'info') as mock_info:
        backend.log('bogus_level', 'fallback msg')
        mock_info.assert_called_once_with('fallback msg')


def test_headless_program_property_returns_program():
    """HeadlessBackend.program returns the program passed at construction."""
    backend = _make_headless_backend()
    assert backend.program is backend._program


def test_headless_flat_api_property_returns_flat_api():
    """HeadlessBackend.flat_api returns the cached FlatProgramAPI."""
    backend = _make_headless_backend()
    flat = backend.flat_api
    assert flat is backend._flat_api


def test_headless_get_data_type_managers():
    backend = _make_headless_backend()
    mock_dtm = MagicMock()
    backend._program.getDataTypeManager.return_value = mock_dtm
    managers = backend.get_data_type_managers()
    assert managers == [mock_dtm]


# ---------------------------------------------------------------------------
# PluginBackend tests
# ---------------------------------------------------------------------------


def _make_plugin_backend() -> PluginBackend:
    mock_tool = MagicMock()
    mock_plugin = MagicMock()
    return PluginBackend(mock_tool, mock_plugin)


def test_plugin_is_headless_false_when_service_available():
    """getService(CodeViewerService) returns non-None → is_headless is False."""
    backend = _make_plugin_backend()
    mock_service = MagicMock()
    backend._tool.getService.return_value = mock_service

    mock_cv_service = MagicMock()
    mock_cv_service.class_ = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
    }):
        result = backend.is_headless

    assert result is False


def test_plugin_is_headless_true_when_service_none():
    """getService(CodeViewerService) returns None → is_headless is True."""
    backend = _make_plugin_backend()
    backend._tool.getService.return_value = None

    mock_cv_service = MagicMock()
    mock_cv_service.class_ = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
    }):
        result = backend.is_headless

    assert result is True


def test_plugin_is_headless_true_when_getservice_raises():
    """getService raises → is_headless returns True (except branch)."""
    backend = _make_plugin_backend()
    backend._tool.getService.side_effect = RuntimeError('service crash')

    mock_cv_service = MagicMock()
    mock_cv_service.class_ = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
    }):
        result = backend.is_headless

    assert result is True


def test_plugin_get_overwrite_policy_always_allow():
    """Raw options value 'Always Allow' → 'always_allow'."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'Always Allow'
    backend._tool.getOptions.return_value = mock_options

    result = backend.get_overwrite_policy()
    assert result == 'always_allow'


def test_plugin_get_overwrite_policy_always_skip():
    """Raw options value 'Always Skip' → 'always_skip'."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'Always Skip'
    backend._tool.getOptions.return_value = mock_options

    result = backend.get_overwrite_policy()
    assert result == 'always_skip'


def test_plugin_get_overwrite_policy_ask():
    """Raw options value 'Ask' → 'ask'."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'Ask'
    backend._tool.getOptions.return_value = mock_options

    result = backend.get_overwrite_policy()
    assert result == 'ask'


def test_plugin_get_overwrite_policy_unknown_raw_returns_ask():
    """Raw value not in OverwritePolicy enum → falls through loop → 'ask'."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'SomeUnknownPolicy'
    backend._tool.getOptions.return_value = mock_options

    result = backend.get_overwrite_policy()
    assert result == 'ask'


def test_plugin_get_overwrite_policy_exception_returns_ask():
    """getOptions raises → except branch → 'ask'."""
    backend = _make_plugin_backend()
    backend._tool.getOptions.side_effect = RuntimeError('options crash')

    result = backend.get_overwrite_policy()
    assert result == 'ask'


def test_plugin_confirm_overwrite_mcp_context_present_bridge_succeeds():
    """MCP context present + anyio bridge succeeds → returns bridge result.

    get_current_context is imported via `from mcpyghidra.server import
    get_current_context` inside confirm_overwrite, so we patch the attribute
    on the already-stubbed mcpyghidra.server module directly.
    """
    backend = _make_plugin_backend()

    _MOCK_SERVER.get_current_context = MagicMock(return_value=MagicMock())
    with patch('anyio.from_thread.run', return_value=True):
        result = backend.confirm_overwrite('Confirm renaming old (FUNCTION) at 0x1000 to new?')

    assert result is True


def test_plugin_confirm_overwrite_mcp_context_present_bridge_raises():
    """MCP context present + anyio bridge raises → fallback True."""
    backend = _make_plugin_backend()

    _MOCK_SERVER.get_current_context = MagicMock(return_value=MagicMock())
    with patch('anyio.from_thread.run', side_effect=RuntimeError('no portal')):
        result = backend.confirm_overwrite('Confirm overwrite?')

    assert result is True


def test_plugin_confirm_overwrite_no_context_always_allow():
    """No MCP context + policy=always_allow → True."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'Always Allow'
    backend._tool.getOptions.return_value = mock_options

    _MOCK_SERVER.get_current_context = MagicMock(return_value=None)

    result = backend.confirm_overwrite('description')

    assert result is True


def test_plugin_confirm_overwrite_no_context_always_skip():
    """No MCP context + policy=always_skip → False."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'Always Skip'
    backend._tool.getOptions.return_value = mock_options

    _MOCK_SERVER.get_current_context = MagicMock(return_value=None)

    result = backend.confirm_overwrite('description')

    assert result is False


def test_plugin_confirm_overwrite_no_context_ask_is_headless_true():
    """No context + policy=ask + is_headless → True (no GUI dialog)."""
    backend = _make_plugin_backend()
    mock_options = MagicMock()
    mock_options.getString.return_value = 'Ask'
    backend._tool.getOptions.return_value = mock_options

    # Make is_headless return True
    backend._tool.getService.side_effect = RuntimeError('no service')

    _MOCK_SERVER.get_current_context = MagicMock(return_value=None)

    mock_cv_service = MagicMock()
    mock_cv_service.class_ = MagicMock()

    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service),
    }):
        result = backend.confirm_overwrite('description')

    assert result is True


# ---------------------------------------------------------------------------
# PluginBackend.program property
# ---------------------------------------------------------------------------


def test_plugin_program_raises_when_pm_none():
    """ProgramManager service is None → GhidraError."""
    backend = _make_plugin_backend()
    backend._tool.getService.return_value = None

    mock_pm_class = MagicMock()
    mock_pm_class.class_ = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(ProgramManager=mock_pm_class),
    }):
        with pytest.raises(GhidraError, match='Program Manager service not available'):
            _ = backend.program


def test_plugin_program_raises_when_no_current_program():
    """ProgramManager.getCurrentProgram() is None → GhidraError."""
    backend = _make_plugin_backend()

    mock_pm_instance = MagicMock()
    mock_pm_instance.getCurrentProgram.return_value = None
    backend._tool.getService.return_value = mock_pm_instance

    mock_pm_class = MagicMock()
    mock_pm_class.class_ = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(ProgramManager=mock_pm_class),
    }):
        with pytest.raises(GhidraError, match='No program is open'):
            _ = backend.program


def test_plugin_program_returns_current_program():
    """ProgramManager.getCurrentProgram() returns a program → returned."""
    backend = _make_plugin_backend()

    mock_prog = MagicMock()
    mock_pm_instance = MagicMock()
    mock_pm_instance.getCurrentProgram.return_value = mock_prog
    backend._tool.getService.return_value = mock_pm_instance

    mock_pm_class = MagicMock()
    mock_pm_class.class_ = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(ProgramManager=mock_pm_class),
    }):
        result = backend.program

    assert result is mock_prog


# ---------------------------------------------------------------------------
# PluginBackend.flat_api property — cache miss and cache hit
# ---------------------------------------------------------------------------


def _plugin_backend_with_program(mock_prog: MagicMock) -> PluginBackend:
    """Helper: PluginBackend whose .program always returns mock_prog."""
    backend = _make_plugin_backend()

    mock_pm_instance = MagicMock()
    mock_pm_instance.getCurrentProgram.return_value = mock_prog
    backend._tool.getService.return_value = mock_pm_instance

    mock_pm_class = MagicMock()
    mock_pm_class.class_ = MagicMock()
    sys.modules['ghidra.app.services'] = MagicMock(
        ProgramManager=mock_pm_class,
        DataTypeManagerService=MagicMock(),
        CodeViewerService=MagicMock(),
    )
    return backend


def test_plugin_flat_api_cache_miss_allocates_new():
    """First access to flat_api creates FlatProgramAPI and caches it."""
    mock_prog = MagicMock()
    backend = _plugin_backend_with_program(mock_prog)

    mock_flat_api = MagicMock()
    mock_flat_api_class = MagicMock(return_value=mock_flat_api)
    with patch.dict(sys.modules, {
        'ghidra.program.flatapi': MagicMock(FlatProgramAPI=mock_flat_api_class),
    }):
        result = backend.flat_api

    mock_flat_api_class.assert_called_once_with(mock_prog)
    assert result is mock_flat_api
    assert backend._flat_api is mock_flat_api
    assert backend._flat_api_program is mock_prog


def test_plugin_flat_api_cache_hit_reuses_existing():
    """Second access with same program reuses cached FlatProgramAPI."""
    mock_prog = MagicMock()
    backend = _plugin_backend_with_program(mock_prog)

    cached_api = MagicMock()
    backend._flat_api = cached_api
    backend._flat_api_program = mock_prog  # same program → cache hit

    mock_flat_api_class = MagicMock()
    with patch.dict(sys.modules, {
        'ghidra.program.flatapi': MagicMock(FlatProgramAPI=mock_flat_api_class),
    }):
        result = backend.flat_api

    mock_flat_api_class.assert_not_called()
    assert result is cached_api


def test_plugin_flat_api_invalidates_when_program_changes():
    """flat_api rebuilds when program object changes (different identity)."""
    mock_prog1 = MagicMock()
    mock_prog2 = MagicMock()
    backend = _plugin_backend_with_program(mock_prog2)  # now returns prog2

    old_api = MagicMock()
    backend._flat_api = old_api
    backend._flat_api_program = mock_prog1  # different from current prog2 → rebuild

    new_api = MagicMock()
    mock_flat_api_class = MagicMock(return_value=new_api)
    with patch.dict(sys.modules, {
        'ghidra.program.flatapi': MagicMock(FlatProgramAPI=mock_flat_api_class),
    }):
        result = backend.flat_api

    mock_flat_api_class.assert_called_once_with(mock_prog2)
    assert result is new_api


# ---------------------------------------------------------------------------
# PluginBackend.log
# ---------------------------------------------------------------------------


def test_plugin_log_info():
    """log('info', ...) calls Msg.info(plugin, message)."""
    backend = _make_plugin_backend()

    mock_msg = MagicMock()
    with patch.dict(sys.modules, {'ghidra.util': MagicMock(Msg=mock_msg)}):
        backend.log('info', 'test info message')

    mock_msg.info.assert_called_once_with(backend._plugin, 'test info message')


def test_plugin_log_warn_maps_to_warning():
    """log('warn', ...) must call Msg.warning (not Msg.warn)."""
    backend = _make_plugin_backend()

    mock_msg = MagicMock()
    with patch.dict(sys.modules, {'ghidra.util': MagicMock(Msg=mock_msg)}):
        backend.log('warn', 'a warning')

    mock_msg.warning.assert_called_once_with(backend._plugin, 'a warning')
    mock_msg.warn.assert_not_called()


def test_plugin_log_error():
    """log('error', ...) calls Msg.error."""
    backend = _make_plugin_backend()

    mock_msg = MagicMock()
    with patch.dict(sys.modules, {'ghidra.util': MagicMock(Msg=mock_msg)}):
        backend.log('error', 'an error')

    mock_msg.error.assert_called_once_with(backend._plugin, 'an error')


def test_plugin_get_data_type_managers_service_available():
    """DataTypeManagerService available → extra managers included."""
    backend = _make_plugin_backend()

    mock_program = MagicMock()
    mock_program_dtm = MagicMock()
    mock_program.getDataTypeManager.return_value = mock_program_dtm

    mock_extra_dtm = MagicMock()
    mock_dtm_service = MagicMock()
    mock_dtm_service.getDataTypeManagers.return_value = [mock_program_dtm, mock_extra_dtm]

    mock_service_class = MagicMock()
    mock_service_class.class_ = MagicMock()
    backend._tool.getService.return_value = mock_dtm_service

    # Patch program property to return our mock
    with patch.object(type(backend), 'program', new_callable=lambda: property(lambda self: mock_program)), \
         patch.dict(sys.modules, {
             'ghidra.app.services': MagicMock(DataTypeManagerService=mock_service_class),
         }):
        managers = backend.get_data_type_managers()

    # mock_program_dtm is skipped (== managers[0]); mock_extra_dtm is appended
    assert mock_program_dtm in managers
    assert mock_extra_dtm in managers


def test_plugin_get_data_type_managers_service_none():
    """DataTypeManagerService.getService returns None → no extra managers."""
    backend = _make_plugin_backend()

    mock_program = MagicMock()
    mock_program_dtm = MagicMock()
    mock_program.getDataTypeManager.return_value = mock_program_dtm

    mock_dtm_service_class = MagicMock()
    mock_dtm_service_class.class_ = MagicMock()
    # getService returns None for DataTypeManagerService
    backend._tool.getService.return_value = None

    with patch.object(type(backend), 'program', new_callable=lambda: property(lambda self: mock_program)), \
         patch.dict(sys.modules, {
             'ghidra.app.services': MagicMock(DataTypeManagerService=mock_dtm_service_class),
         }):
        managers = backend.get_data_type_managers()

    assert managers == [mock_program_dtm]


def test_plugin_get_data_type_managers_service_unavailable():
    """DataTypeManagerService import raises → falls back to program DTM only."""
    backend = _make_plugin_backend()

    mock_program = MagicMock()
    mock_program_dtm = MagicMock()
    mock_program.getDataTypeManager.return_value = mock_program_dtm

    with patch.object(type(backend), 'program', new_callable=lambda: property(lambda self: mock_program)):
        # Patch the import to raise so the except branch is triggered
        with patch.dict(sys.modules, {'ghidra.app.services': None}):
            # None module → attribute access raises TypeError → caught by except
            managers = backend.get_data_type_managers()

    assert managers == [mock_program_dtm]


# ---------------------------------------------------------------------------
# PluginBackend._show_overwrite_dialog_from_description — regex branches
# ---------------------------------------------------------------------------


def test_show_overwrite_dialog_from_description_regex_match():
    """Description matches the expected format → symbol_name and addr extracted."""
    backend = _make_plugin_backend()

    # Patch _show_overwrite_dialog to avoid Swing/EDT
    backend._show_overwrite_dialog = MagicMock(return_value=True)
    description = 'Confirm renaming old_sym (FUNCTION) at 0x1000 to new_sym?'

    result = backend._show_overwrite_dialog_from_description(description)

    # Should extract 'old_sym' and '0x1000'
    backend._show_overwrite_dialog.assert_called_once_with('old_sym', '0x1000')
    assert result is True


def test_show_overwrite_dialog_from_description_no_regex_match():
    """Description doesn't match the regex → fallback to truncated description."""
    backend = _make_plugin_backend()

    backend._show_overwrite_dialog = MagicMock(return_value=False)
    description = 'Some unrelated description that does not match the pattern'

    result = backend._show_overwrite_dialog_from_description(description)

    # Fallback: symbol_name = description[:50], addr = 'unknown'
    backend._show_overwrite_dialog.assert_called_once_with(description[:50], 'unknown')
    assert result is False


# ---------------------------------------------------------------------------
# _confirm_overwrite_async — HeadlessBackend and PluginBackend
# These are simple one-line async methods; we test them with anyio.run.
# ---------------------------------------------------------------------------


import anyio  # noqa: E402


def _run_async(coro):
    """Run a coroutine synchronously."""
    async def _wrapper():
        return await coro
    return anyio.run(_wrapper)


def test_headless_confirm_overwrite_async():
    """HeadlessBackend._confirm_overwrite_async delegates to elicit_confirmation."""
    backend = _make_headless_backend()

    mock_elicit = AsyncMock(return_value=True)
    _MOCK_SERVER.elicit_confirmation = mock_elicit

    result = _run_async(backend._confirm_overwrite_async('test description'))

    mock_elicit.assert_called_once_with('test description', backend._batch_state)
    assert result is True


def test_plugin_confirm_overwrite_async():
    """PluginBackend._confirm_overwrite_async delegates to elicit_confirmation."""
    backend = _make_plugin_backend()

    mock_elicit = AsyncMock(return_value=False)
    _MOCK_SERVER.elicit_confirmation = mock_elicit

    result = _run_async(backend._confirm_overwrite_async('rename description'))

    mock_elicit.assert_called_once_with('rename description', backend._batch_state)
    assert result is False


def test_plugin_confirm_overwrite_no_context_ask_is_headless_false_shows_dialog():
    """No context + policy=ask + is_headless=False → _show_overwrite_dialog_from_description."""
    backend = _make_plugin_backend()

    mock_options = MagicMock()
    mock_options.getString.return_value = 'Ask'
    backend._tool.getOptions.return_value = mock_options

    # is_headless=False: getService returns a non-None CodeViewerService
    mock_cv_service_class = MagicMock()
    mock_cv_service_class.class_ = MagicMock()
    backend._tool.getService.return_value = MagicMock()  # not None → is_headless=False

    _MOCK_SERVER.get_current_context = MagicMock(return_value=None)

    # Patch _show_overwrite_dialog_from_description to avoid actual Swing call
    backend._show_overwrite_dialog_from_description = MagicMock(return_value=True)

    with patch.dict(sys.modules, {
        'ghidra.app.services': MagicMock(CodeViewerService=mock_cv_service_class),
    }):
        result = backend.confirm_overwrite('Confirm renaming x (FUNCTION) at 0x1 to y?')

    backend._show_overwrite_dialog_from_description.assert_called_once()
    assert result is True


# ---------------------------------------------------------------------------
# PluginBackend._show_overwrite_dialog — all result branches
#
# Swing.runNow is mocked to call the inner _show_on_edt synchronously.
# docking.widgets, ghidra.util (Swing), mcp.server.fastmcp.exceptions all stubbed.
# ---------------------------------------------------------------------------


def _stub_dialog_modules(option_one_val: int, option_two_val: int, cancel_val: int):
    """Install stub modules for the three imports inside _show_overwrite_dialog."""
    mock_option_dialog = MagicMock()
    mock_option_dialog.OPTION_ONE = option_one_val
    mock_option_dialog.OPTION_TWO = option_two_val
    mock_option_dialog.CANCEL_OPTION = cancel_val

    mock_docking_widgets = MagicMock()
    mock_docking_widgets.OptionDialog = mock_option_dialog
    mock_docking_widgets.OptionDialogBuilder = MagicMock()

    mock_ghidra_util_swing = MagicMock()
    # Make Swing.runNow call the callback synchronously
    mock_ghidra_util_swing.Swing.runNow.side_effect = lambda fn: fn()

    sys.modules['docking'] = MagicMock()
    sys.modules['docking.widgets'] = mock_docking_widgets
    sys.modules['ghidra.util'] = mock_ghidra_util_swing

    return mock_option_dialog, mock_docking_widgets, mock_ghidra_util_swing


def test_show_overwrite_dialog_option_one_returns_true():
    """Dialog result == OPTION_ONE → True (overwrite)."""
    backend = _make_plugin_backend()
    mock_od, mock_dw, mock_gu = _stub_dialog_modules(1, 2, 0)

    # Builder returns OPTION_ONE from show()
    mock_builder_instance = MagicMock()
    mock_builder_instance.show.return_value = mock_od.OPTION_ONE
    mock_dw.OptionDialogBuilder.return_value = mock_builder_instance

    result = backend._show_overwrite_dialog('old_sym', '0x1000')

    assert result is True


def test_show_overwrite_dialog_option_two_returns_false():
    """Dialog result == OPTION_TWO → False (skip)."""
    backend = _make_plugin_backend()
    mock_od, mock_dw, mock_gu = _stub_dialog_modules(1, 2, 0)

    mock_builder_instance = MagicMock()
    mock_builder_instance.show.return_value = mock_od.OPTION_TWO
    mock_dw.OptionDialogBuilder.return_value = mock_builder_instance

    result = backend._show_overwrite_dialog('old_sym', '0x1000')

    assert result is False


def test_show_overwrite_dialog_cancel_raises_tool_error():
    """Dialog result == CANCEL_OPTION (0) → ToolError raised."""
    from mcp.server.fastmcp.exceptions import ToolError

    backend = _make_plugin_backend()
    mock_od, mock_dw, mock_gu = _stub_dialog_modules(1, 2, 0)

    mock_builder_instance = MagicMock()
    mock_builder_instance.show.return_value = mock_od.CANCEL_OPTION
    mock_dw.OptionDialogBuilder.return_value = mock_builder_instance

    with pytest.raises(ToolError, match="User cancelled overwrite of 'old_sym' at 0x1000"):
        backend._show_overwrite_dialog('old_sym', '0x1000')


def test_show_overwrite_dialog_reuses_existing_builder():
    """When _overwrite_dialog_builder already set → setMessage called, not constructor."""
    backend = _make_plugin_backend()
    mock_od, mock_dw, mock_gu = _stub_dialog_modules(1, 2, 0)

    existing_builder = MagicMock()
    existing_builder.show.return_value = mock_od.OPTION_ONE
    backend._overwrite_dialog_builder = existing_builder

    result = backend._show_overwrite_dialog('sym', '0x200')

    existing_builder.setMessage.assert_called_once()
    mock_dw.OptionDialogBuilder.assert_not_called()
    assert result is True


def test_show_overwrite_dialog_edt_exception_triggers_cancel():
    """Exception inside _show_on_edt → result stays CANCEL_OPTION → ToolError."""
    from mcp.server.fastmcp.exceptions import ToolError

    backend = _make_plugin_backend()
    mock_od, mock_dw, mock_gu = _stub_dialog_modules(1, 2, 0)

    # Make the builder constructor raise inside _show_on_edt
    mock_dw.OptionDialogBuilder.side_effect = RuntimeError('Swing crash')

    # log() will be called for the error; stub it to avoid side effects
    backend.log = MagicMock()

    with pytest.raises(ToolError):
        backend._show_overwrite_dialog('sym', '0x300')


# ---------------------------------------------------------------------------
# OverwritePolicy enum — all three values
# ---------------------------------------------------------------------------


def test_overwrite_policy_values():
    assert OverwritePolicy.ASK.value == 'Ask'
    assert OverwritePolicy.ALWAYS_ALLOW.value == 'Always Allow'
    assert OverwritePolicy.ALWAYS_SKIP.value == 'Always Skip'
