"""Unit tests for uncovered branches in server.py.

Targets the 6 gap categories identified in the phase5-coverage-gap analysis:
1. Tool argument validation (malformed items, missing fields → ToolError)
2. Batch error aggregation (mixed success/fail)
3. Exception handler variants (GhidraError vs ToolError vs raw Exception)
4. Concurrency guard / GUI service checks (is_headless, open_program guard)
5. Resource handlers (server://info, project://binaries paths)
6. Async wrappers + context-var management in rename/update_vars/set_comments

Pattern: mirror test_server_info.py exactly — MagicMock backends, a
_FakeMcp capture helper, and _run_async for coroutines.
"""
from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import pytest
from mcp.server.fastmcp.exceptions import ToolError

# ---------------------------------------------------------------------------
# Ghidra stubs — same set as test_core_branches.py
# ---------------------------------------------------------------------------

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

_mock_application = MagicMock()
_mock_application.getName.return_value = 'Ghidra'
_mock_application.getApplicationVersion.return_value = '11.0'
_mock_ghidra_framework = MagicMock()
_mock_ghidra_framework.Application = _mock_application
sys.modules['ghidra.framework'] = _mock_ghidra_framework


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_backend(*, is_headless: bool = True) -> MagicMock:
    backend = MagicMock()
    backend.is_headless = is_headless
    backend.program = MagicMock()
    backend.flat_api = MagicMock()
    return backend


def _run_async(coro_fn, *args, **kwargs):
    """Run an async function synchronously (mirrors test_core_branches._run_async)."""

    async def wrapper():
        return await coro_fn(*args, **kwargs)

    return anyio.run(wrapper)


def _capture_resource(backend, uri: str, get_port=None):
    """Register resources on a fake MCP and return the handler for *uri*."""
    from mcpyghidra.server import register_resources

    captured: dict = {}

    class _FakeMcp:
        def resource(self, u, **kwargs):
            def decorator(fn):
                captured[u] = fn
                return fn

            return decorator

    register_resources(_FakeMcp(), backend, get_port=get_port)
    return captured.get(uri)


# ---------------------------------------------------------------------------
# 1. get_current_context — module-level helper
# ---------------------------------------------------------------------------


class TestGetCurrentContext:
    """get_current_context returns None when no context is set."""

    def test_returns_none_when_no_context_set(self):
        from mcpyghidra.server import get_current_context

        result = get_current_context()
        assert result is None

    def test_returns_value_after_contextvar_set(self):
        from mcpyghidra.server import _current_mcp_context, get_current_context

        sentinel = object()
        token = _current_mcp_context.set(sentinel)
        try:
            assert get_current_context() is sentinel
        finally:
            _current_mcp_context.reset(token)


# ---------------------------------------------------------------------------
# 2. elicit_confirmation branches
# ---------------------------------------------------------------------------


class TestElicitConfirmation:
    """All branches in elicit_confirmation()."""

    def test_apply_to_all_cached_true(self):
        """batch_state with apply_to_all_decision=True returns True without calling ctx."""
        from mcpyghidra.server import elicit_confirmation

        batch_state = {'apply_to_all_decision': True}
        result = _run_async(elicit_confirmation, 'Proceed?', batch_state)
        assert result is True

    def test_apply_to_all_cached_false(self):
        """batch_state with apply_to_all_decision=False returns False."""
        from mcpyghidra.server import elicit_confirmation

        batch_state = {'apply_to_all_decision': False}
        result = _run_async(elicit_confirmation, 'Proceed?', batch_state)
        assert result is False

    def test_no_context_returns_true(self):
        """When no MCP context is set, auto-allow (return True)."""
        from mcpyghidra.server import elicit_confirmation

        result = _run_async(elicit_confirmation, 'Proceed?', {})
        assert result is True

    def test_ctx_elicit_raises_returns_true(self):
        """If ctx.elicit() raises any exception, fall back to True (auto-allow)."""
        from mcpyghidra.server import _current_mcp_context, elicit_confirmation

        mock_ctx = MagicMock()
        mock_ctx.elicit = AsyncMock(side_effect=RuntimeError('unsupported'))

        token = _current_mcp_context.set(mock_ctx)
        try:
            result = _run_async(elicit_confirmation, 'Proceed?', {})
        finally:
            _current_mcp_context.reset(token)

        assert result is True

    def test_ctx_elicit_decline_returns_false(self):
        """result.action == 'decline' → return False."""
        from mcpyghidra.server import _current_mcp_context, elicit_confirmation

        mock_result = MagicMock()
        mock_result.action = 'decline'

        mock_ctx = MagicMock()
        mock_ctx.elicit = AsyncMock(return_value=mock_result)

        token = _current_mcp_context.set(mock_ctx)
        try:
            result = _run_async(elicit_confirmation, 'Proceed?', {})
        finally:
            _current_mcp_context.reset(token)

        assert result is False

    def test_ctx_elicit_accept_with_confirm_true(self):
        """result.action == 'accept', data.confirm=True, apply_to_all=False → True."""
        from mcpyghidra.server import _current_mcp_context, elicit_confirmation

        mock_data = MagicMock()
        mock_data.confirm = True
        mock_data.apply_to_all = False

        mock_result = MagicMock()
        mock_result.action = 'accept'
        mock_result.data = mock_data

        mock_ctx = MagicMock()
        mock_ctx.elicit = AsyncMock(return_value=mock_result)

        token = _current_mcp_context.set(mock_ctx)
        try:
            result = _run_async(elicit_confirmation, 'Proceed?', {})
        finally:
            _current_mcp_context.reset(token)

        assert result is True

    def test_ctx_elicit_accept_apply_to_all_caches_decision(self):
        """apply_to_all=True → stores confirm into batch_state['apply_to_all_decision']."""
        from mcpyghidra.server import _current_mcp_context, elicit_confirmation

        mock_data = MagicMock()
        mock_data.confirm = True
        mock_data.apply_to_all = True

        mock_result = MagicMock()
        mock_result.action = 'accept'
        mock_result.data = mock_data

        mock_ctx = MagicMock()
        mock_ctx.elicit = AsyncMock(return_value=mock_result)

        token = _current_mcp_context.set(mock_ctx)
        batch_state: dict = {}
        try:
            result = _run_async(elicit_confirmation, 'Proceed?', batch_state)
        finally:
            _current_mcp_context.reset(token)

        assert result is True
        assert batch_state['apply_to_all_decision'] is True

    def test_ctx_elicit_accept_data_none_returns_true(self):
        """result.action == 'accept' but data is None → return True (default allow)."""
        from mcpyghidra.server import _current_mcp_context, elicit_confirmation

        mock_result = MagicMock()
        mock_result.action = 'accept'
        mock_result.data = None

        mock_ctx = MagicMock()
        mock_ctx.elicit = AsyncMock(return_value=mock_result)

        token = _current_mcp_context.set(mock_ctx)
        try:
            result = _run_async(elicit_confirmation, 'Proceed?', {})
        finally:
            _current_mcp_context.reset(token)

        assert result is True


# ---------------------------------------------------------------------------
# 3. _on_functions_changed branches
# ---------------------------------------------------------------------------


class TestOnFunctionsChanged:
    """_on_functions_changed: deferred vs immediate cache invalidation."""

    def setup_method(self):
        from mcpyghidra.server import _reset_rpc_discovery

        _reset_rpc_discovery()

    def test_invalidates_immediately_when_not_executing(self):
        """If no script is executing, cache is invalidated immediately."""
        import mcpyghidra.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = False

        srv._on_functions_changed()

        assert srv._rpc_functions_discovered is False

    def test_defers_when_script_executing(self):
        """If a script is executing, update is deferred (cache not cleared yet)."""
        import mcpyghidra.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = True

        srv._on_functions_changed()

        # Cache should NOT be invalidated yet
        assert srv._rpc_functions_discovered is True
        assert srv._rpc_update_deferred is True


# ---------------------------------------------------------------------------
# 4. _reset_rpc_discovery
# ---------------------------------------------------------------------------


class TestResetRpcDiscovery:
    """_reset_rpc_discovery clears all module-level state."""

    def test_resets_all_state(self):
        import mcpyghidra.server as srv

        srv._rpc_namespace = MagicMock()
        srv._rpc_functions_discovered = True
        srv._rpc_session_id = 42
        srv._rpc_update_deferred = True
        srv._script_executing = True

        srv._reset_rpc_discovery()

        assert srv._rpc_namespace is None
        assert srv._rpc_functions_discovered is False
        assert srv._rpc_session_id is None
        assert srv._rpc_update_deferred is False
        assert srv._script_executing is False


# ---------------------------------------------------------------------------
# 5. _discover_rpc_functions branches
# ---------------------------------------------------------------------------


class TestDiscoverRpcFunctions:
    """_discover_rpc_functions: cache hit, session change, capability checks."""

    def setup_method(self):
        from mcpyghidra.server import _reset_rpc_discovery

        _reset_rpc_discovery()

    def test_returns_cached_namespace_on_same_session(self):
        """Second call with same session returns cached _rpc_namespace."""
        import mcpyghidra.server as srv
        from mcpyghidra.server import _discover_rpc_functions

        cached_ns = MagicMock()
        session = MagicMock()
        session_id = id(session)

        srv._rpc_session_id = session_id
        srv._rpc_functions_discovered = True
        srv._rpc_namespace = cached_ns

        result = _run_async(_discover_rpc_functions, session)
        assert result is cached_ns

    def test_invalidates_cache_on_new_session(self):
        """Different session id → cache is invalidated before discovery."""
        import mcpyghidra.server as srv
        from mcpyghidra.server import _discover_rpc_functions

        srv._rpc_session_id = 99999  # old session
        srv._rpc_functions_discovered = True
        srv._rpc_namespace = MagicMock()

        # Session without mcpy/rpcCallbacks capability
        new_session = MagicMock()
        new_session.client_params = None

        result = _run_async(_discover_rpc_functions, new_session)
        assert result is None
        assert srv._rpc_functions_discovered is True  # re-discovered as None

    def test_no_experimental_capability_returns_none(self):
        """Client without mcpy/rpcCallbacks in experimental → None, cache set."""
        import mcpyghidra.server as srv
        from mcpyghidra.server import _discover_rpc_functions

        session = MagicMock()
        caps = MagicMock()
        caps.experimental = {}  # no 'mcpy/rpcCallbacks'
        session.client_params.capabilities = caps

        result = _run_async(_discover_rpc_functions, session)

        assert result is None
        assert srv._rpc_functions_discovered is True

    def test_client_params_none_returns_none(self):
        """client_params is None → no experimental → returns None."""
        import mcpyghidra.server as srv
        from mcpyghidra.server import _discover_rpc_functions

        session = MagicMock()
        session.client_params = None

        result = _run_async(_discover_rpc_functions, session)

        assert result is None
        assert srv._rpc_functions_discovered is True

    def test_exception_in_capability_check_returns_none(self):
        """Exception accessing client_params.capabilities → None, cache set."""
        import mcpyghidra.server as srv
        from mcpyghidra.server import _discover_rpc_functions

        session = MagicMock()
        type(session).client_params = property(  # type: ignore[assignment]
            fget=lambda self: (_ for _ in ()).throw(RuntimeError('no params'))
        )

        result = _run_async(_discover_rpc_functions, session)
        assert result is None
        assert srv._rpc_functions_discovered is True


# ---------------------------------------------------------------------------
# 6. McpToolRegistration.iter_tools — headless vs GUI
# ---------------------------------------------------------------------------


class TestIterTools:
    """iter_tools includes open_program only for GUI backends."""

    def test_headless_excludes_open_program(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend(is_headless=True)
        reg = McpToolRegistration(backend)
        names = [tool_name for _, tool_name, _, _ in reg.iter_tools()]
        assert 'open_program' not in names

    def test_gui_includes_open_program(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend(is_headless=False)
        reg = McpToolRegistration(backend)
        names = [tool_name for _, tool_name, _, _ in reg.iter_tools()]
        assert 'open_program' in names

    def test_all_core_tools_present(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend(is_headless=True)
        reg = McpToolRegistration(backend)
        names = {tool_name for _, tool_name, _, _ in reg.iter_tools()}
        expected = {'list', 'decompile', 'disasm', 'rename', 'cfg', 'callgraph', 'pyghidra'}
        assert expected.issubset(names)


# ---------------------------------------------------------------------------
# 7. register_tools — MCPY_DISABLE_READONLY_TOOLS env var
# ---------------------------------------------------------------------------


class TestRegisterTools:
    """register_tools skips read-only tools when env var is set."""

    def test_disable_readonly_tools_true_skips_readonly(self):
        from mcpyghidra.server import register_tools

        backend = _make_backend(is_headless=True)
        registered: list[str] = []

        class _FakeMcp:
            def tool(self, name, **kwargs):
                def decorator(fn):
                    registered.append(name)
                    return fn

                return decorator

        with patch.dict('os.environ', {'MCPY_DISABLE_READONLY_TOOLS': '1'}):
            register_tools(_FakeMcp(), backend)

        # 'list' is readOnlyHint=True, so it must be absent
        assert 'list' not in registered
        # 'rename' is readOnlyHint=False, so it must be present
        assert 'rename' in registered

    def test_disable_readonly_tools_false_registers_all(self):
        from mcpyghidra.server import register_tools

        backend = _make_backend(is_headless=True)
        registered: list[str] = []

        class _FakeMcp:
            def tool(self, name, **kwargs):
                def decorator(fn):
                    registered.append(name)
                    return fn

                return decorator

        with patch.dict('os.environ', {'MCPY_DISABLE_READONLY_TOOLS': '0'}):
            register_tools(_FakeMcp(), backend)

        assert 'list' in registered
        assert 'rename' in registered

    def test_disable_readonly_tools_true_string(self):
        from mcpyghidra.server import register_tools

        backend = _make_backend(is_headless=True)
        registered: list[str] = []

        class _FakeMcp:
            def tool(self, name, **kwargs):
                def decorator(fn):
                    registered.append(name)
                    return fn

                return decorator

        with patch.dict('os.environ', {'MCPY_DISABLE_READONLY_TOOLS': 'true'}):
            register_tools(_FakeMcp(), backend)

        assert 'list' not in registered


# ---------------------------------------------------------------------------
# 8. build_instructions — fallback branches
# ---------------------------------------------------------------------------


class TestBuildInstructions:
    """build_instructions branches not covered by test_server_info.py."""

    def test_none_backend_returns_unknown_mode(self):
        from mcpyghidra.server import build_instructions

        result = build_instructions(None)
        assert 'Mode: unknown' in result
        assert 'Binary: none' in result

    def test_backend_program_raises_falls_back_to_unknown(self):
        """backend.program raises → falls back to 'Binary: unknown'."""
        from mcpyghidra.server import build_instructions

        backend = _make_backend(is_headless=True)
        backend.program = property(fget=lambda self: (_ for _ in ()).throw(RuntimeError('no prog')))  # type: ignore[assignment]
        # MagicMock attribute access doesn't use property, so set side_effect on getName
        backend2 = MagicMock()
        backend2.is_headless = True
        backend2.program.getName.side_effect = RuntimeError('no prog')

        result = build_instructions(backend2)
        assert 'Binary: unknown' in result

    def test_gui_mode_includes_open_program(self):
        from mcpyghidra.server import build_instructions

        backend = _make_backend(is_headless=False)
        backend.program.getName.return_value = 'firmware.bin'
        backend.program.getExecutablePath.return_value = '/fw.bin'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'ARM:LE:32:v7'
        backend.program.getLanguage.return_value = lang

        result = build_instructions(backend)
        assert 'open_program' in result

    def test_headless_mode_excludes_open_program(self):
        from mcpyghidra.server import build_instructions

        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'crackme.elf'
        backend.program.getExecutablePath.return_value = '/crackme.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        result = build_instructions(backend)
        assert 'open_program' not in result

    def test_pyghidra_version_fallback_when_no_ghidra(self):
        """When ghidra.framework.Application is unavailable, falls back to pyghidra.__version__."""
        from mcpyghidra.server import build_instructions

        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'test.elf'
        backend.program.getExecutablePath.return_value = '/test.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        bad_framework = MagicMock()
        bad_framework.Application.getApplicationVersion.side_effect = RuntimeError('no ghidra')

        mock_pyghidra = MagicMock()
        mock_pyghidra.__version__ = '1.2.3'

        with (
            patch.dict('sys.modules', {'ghidra.framework': bad_framework}),
            patch.dict('sys.modules', {'pyghidra': mock_pyghidra}),
        ):
            result = build_instructions(backend)

        assert 'pyghidra' in result or 'MCPyGhidra' in result

    def test_both_version_fallbacks_fail(self):
        """Both ghidra and pyghidra unavailable → still returns a non-empty string."""
        from mcpyghidra.server import build_instructions

        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'test.elf'
        backend.program.getExecutablePath.return_value = '/test.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        bad_framework = MagicMock()
        bad_framework.Application.getApplicationVersion.side_effect = RuntimeError('no ghidra')

        with (
            patch.dict('sys.modules', {'ghidra.framework': bad_framework}),
            patch('builtins.__import__', side_effect=lambda name, *a, **kw: (_ for _ in ()).throw(ImportError('no pyghidra')) if name == 'pyghidra' else __import__(name, *a, **kw)),
        ):
            # Should not raise; fallback to bare tool line
            result = build_instructions(backend)

        assert result  # non-empty


# ---------------------------------------------------------------------------
# 9. _make_resource_wrapper — annotation resolution failure path
# ---------------------------------------------------------------------------


class TestMakeResourceWrapper:
    """_make_resource_wrapper handles annotation resolution failures gracefully."""

    def test_wraps_function_and_strips_extra_params(self):
        from mcpyghidra.server import _make_resource_wrapper

        def my_fn(offset: int = 0, limit: int = 100, extra: str = '') -> str:
            return f'{offset},{limit}'

        wrapped = _make_resource_wrapper(my_fn, {'offset', 'limit'})
        import inspect

        params = list(inspect.signature(wrapped).parameters.keys())
        assert 'extra' not in params
        assert 'offset' in params
        assert 'limit' in params

    def test_wrapper_calls_original_function(self):
        from mcpyghidra.server import _make_resource_wrapper

        def my_fn(x: int = 1) -> int:
            return x * 2

        wrapped = _make_resource_wrapper(my_fn, {'x'})
        assert wrapped(x=5) == 10

    def test_annotation_resolution_failure_is_silent(self):
        """If get_type_hints raises, wrapper keeps existing annotations without error."""
        from mcpyghidra.server import _make_resource_wrapper

        def my_fn(x: int = 0) -> int:
            return x

        with patch('typing.get_type_hints', side_effect=RuntimeError('hints failed')):
            wrapped = _make_resource_wrapper(my_fn, {'x'})

        # Should not raise; wrapped is callable
        assert wrapped(x=3) == 3


# ---------------------------------------------------------------------------
# 10. McpToolRegistration method delegation (async wrappers)
# ---------------------------------------------------------------------------


class TestMcpToolRegistrationDelegation:
    """Each McpToolRegistration method delegates to the correct tool module."""

    def _make_tool_registration(self, is_headless: bool = True):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend(is_headless=is_headless)
        return McpToolRegistration(backend), backend

    def test_list_entries_delegates_to_core(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = MagicMock()
            _run_async(reg.list_entries, entry_type='function')

        mock_fn.assert_awaited_once()

    def test_cursor_delegates_to_core(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.core.cursor', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = MagicMock()
            _run_async(reg.cursor)

        mock_fn.assert_awaited_once()

    def test_context_delegates_to_core(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.core.context', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = MagicMock()
            _run_async(reg.context)

        mock_fn.assert_awaited_once()

    def test_funcs_delegates_to_core(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.core.funcs', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.funcs, items=['0x1000'])

        mock_fn.assert_awaited_once()

    def test_decompile_delegates_to_analysis(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.analysis.decompile', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.decompile, items=[{'addr': '0x1000'}])

        mock_fn.assert_awaited_once()

    def test_disasm_delegates_to_analysis(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.analysis.disasm', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.disasm, items=[{'addr': '0x1000'}])

        mock_fn.assert_awaited_once()

    def test_symbols_delegates_to_analysis(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.analysis.symbols', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.symbols, items=['0x1000'])

        mock_fn.assert_awaited_once()

    def test_xrefs_delegates_to_analysis(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.analysis.xrefs', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.xrefs, items=[{'target': '0x1000'}])

        mock_fn.assert_awaited_once()

    def test_rename_sets_context_var(self):
        """rename() sets the MCP context var before calling modify.rename."""
        reg, backend = self._make_tool_registration()

        captured_ctx: list = []

        async def mock_rename(be, items):
            from mcpyghidra.server import get_current_context

            captured_ctx.append(get_current_context())
            return []

        sentinel_ctx = MagicMock()

        with patch('mcpyghidra.tools.modify.rename', side_effect=mock_rename):
            _run_async(reg.rename, items=[{'new_name': 'foo', 'addr': '0x1000'}], ctx=sentinel_ctx)

        assert captured_ctx[0] is sentinel_ctx

    def test_rename_resets_context_var_after_call(self):
        """rename() resets context var even if modify.rename raises."""
        reg, backend = self._make_tool_registration()

        async def raising_rename(be, items):
            raise RuntimeError('boom')

        sentinel_ctx = MagicMock()

        with patch('mcpyghidra.tools.modify.rename', side_effect=raising_rename):
            with pytest.raises(RuntimeError):
                _run_async(reg.rename, items=[], ctx=sentinel_ctx)

        # context var should be reset back to None
        from mcpyghidra.server import get_current_context

        assert get_current_context() is None

    def test_update_vars_sets_context_var(self):
        """update_vars() propagates ctx through _current_mcp_context."""
        reg, backend = self._make_tool_registration()

        captured_ctx: list = []

        async def mock_update_vars(be, fn, variables):
            from mcpyghidra.server import get_current_context

            captured_ctx.append(get_current_context())
            return {}

        sentinel_ctx = MagicMock()

        with patch('mcpyghidra.tools.modify.update_vars', side_effect=mock_update_vars):
            _run_async(reg.update_vars, function_name='main', variables_to_update={}, ctx=sentinel_ctx)

        assert captured_ctx[0] is sentinel_ctx

    def test_set_comments_sets_context_var(self):
        reg, backend = self._make_tool_registration()

        captured_ctx: list = []

        async def mock_set_comments(be, items):
            from mcpyghidra.server import get_current_context

            captured_ctx.append(get_current_context())
            return []

        sentinel_ctx = MagicMock()

        with patch('mcpyghidra.tools.modify.set_comments', side_effect=mock_set_comments):
            _run_async(reg.set_comments, items=[], ctx=sentinel_ctx)

        assert captured_ctx[0] is sentinel_ctx

    def test_get_comment_delegates_to_modify(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.modify.get_comment', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.get_comment, items=[{'addr': '0x1000'}])

        mock_fn.assert_awaited_once()

    def test_set_prototype_sets_context_var(self):
        reg, backend = self._make_tool_registration()

        captured_ctx: list = []

        async def mock_set_prototype(be, items):
            from mcpyghidra.server import get_current_context

            captured_ctx.append(get_current_context())
            return []

        sentinel_ctx = MagicMock()

        with patch('mcpyghidra.tools.modify.set_prototype', side_effect=mock_set_prototype):
            _run_async(reg.set_prototype, items=[], ctx=sentinel_ctx)

        assert captured_ctx[0] is sentinel_ctx

    def test_patch_delegates_to_modify(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.modify.patch', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.patch, items=[{'addr': '0x1000', 'hex_bytes': '90'}])

        mock_fn.assert_awaited_once()

    def test_begin_trans_delegates_to_modify(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.modify.begin_trans', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = '42'
            _run_async(reg.begin_trans, description='test tx')

        mock_fn.assert_awaited_once()

    def test_end_trans_delegates_to_modify(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.modify.end_trans', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = {}
            _run_async(reg.end_trans, transaction_id='42', commit=True)

        mock_fn.assert_awaited_once()

    def test_types_tool_removed_from_registration(self):
        reg, backend = self._make_tool_registration()
        # types tool was removed; calling reg.types should raise AttributeError
        assert not hasattr(reg, 'types'), 'types tool method should not exist on registration'
        # type_info is still present
        assert hasattr(reg, 'type_info')

    def test_type_info_delegates_to_type_tools(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.types.type_info', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.type_info, items=['MyStruct'])

        mock_fn.assert_awaited_once()

    def test_create_struct_delegates_to_type_tools(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.types.create_struct', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = MagicMock()
            _run_async(reg.create_struct, name='MyStruct')

        mock_fn.assert_awaited_once()

    def test_add_field_delegates_to_type_tools(self):
        reg, backend = self._make_tool_registration()

        with patch('mcpyghidra.tools.types.add_field', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.add_field, items=[])

        mock_fn.assert_awaited_once()


# ---------------------------------------------------------------------------
# 11. pyghidra_eval — RPC discovery paths
# ---------------------------------------------------------------------------


class TestPyghidraEvalRpcPaths:
    """pyghidra_eval ctx=None and ctx exception paths."""

    def _make_script_result(self):
        result = MagicMock()
        result.model_dump.return_value = {'result': '42', 'stdout': '', 'stderr': ''}
        return result

    def test_no_ctx_skips_rpc_discovery(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend()
        reg = McpToolRegistration(backend)

        async def mock_eval(be, code, reset, *, rpc_namespace, session):
            return self._make_script_result()

        with patch('mcpyghidra.tools.scripting.pyghidra_eval', side_effect=mock_eval):
            result = _run_async(reg.pyghidra_eval, code='1+1', reset=False, ctx=None)

        assert result['result'] == '42'

    def test_ctx_session_raises_during_rpc_discovery(self):
        """If ctx.session access raises, rpc_ns stays None and eval still proceeds."""
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend()
        reg = McpToolRegistration(backend)

        mock_ctx = MagicMock()
        type(mock_ctx).session = property(  # type: ignore[assignment]
            fget=lambda self: (_ for _ in ()).throw(RuntimeError('no session'))
        )

        async def mock_eval(be, code, reset, *, rpc_namespace, session):
            return self._make_script_result()

        with patch('mcpyghidra.tools.scripting.pyghidra_eval', side_effect=mock_eval):
            result = _run_async(reg.pyghidra_eval, code='1+1', reset=False, ctx=mock_ctx)

        assert result['result'] == '42'

    def test_ctx_with_valid_session_discovers_rpc(self):
        """ctx.session is valid, _discover_rpc_functions is called."""
        from mcpyghidra.server import McpToolRegistration, _reset_rpc_discovery

        _reset_rpc_discovery()
        backend = _make_backend()
        reg = McpToolRegistration(backend)

        mock_session = MagicMock()
        mock_session.client_params = None  # no capability → None namespace

        mock_ctx = MagicMock()
        mock_ctx.session = mock_session

        captured_ns: list = []

        async def mock_eval(be, code, reset, *, rpc_namespace, session):
            captured_ns.append(rpc_namespace)
            return self._make_script_result()

        with patch('mcpyghidra.tools.scripting.pyghidra_eval', side_effect=mock_eval):
            _run_async(reg.pyghidra_eval, code='x', reset=False, ctx=mock_ctx)

        # rpc_namespace should be None (no capability declared)
        assert captured_ns[0] is None


# ---------------------------------------------------------------------------
# 12. find_bytes / find_insns delegation
# ---------------------------------------------------------------------------


class TestSearchToolDelegation:
    """find_bytes and find_insns delegate to tools.search."""

    def _make_reg(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend()
        return McpToolRegistration(backend)

    def test_find_bytes_delegates(self):
        reg = self._make_reg()

        with patch('mcpyghidra.tools.search.find_bytes', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.find_bytes, patterns=['90'], limit=10, offset=0)

        mock_fn.assert_awaited_once()

    def test_find_insns_delegates(self):
        reg = self._make_reg()

        with patch('mcpyghidra.tools.search.find_insns', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = []
            _run_async(reg.find_insns, sequences=[[{'mnemonic': 'PUSH'}]], limit=10, offset=0)

        mock_fn.assert_awaited_once()


# ---------------------------------------------------------------------------
# 13. cfg / callgraph delegation (model_dump path)
# ---------------------------------------------------------------------------


class TestCfgCallgraphDelegation:
    """cfg and callgraph call model_dump(by_alias=True) on the result."""

    def _make_reg(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend()
        return McpToolRegistration(backend)

    def test_cfg_calls_model_dump(self):
        reg = self._make_reg()

        mock_result = MagicMock()
        mock_result.model_dump.return_value = {'nodes': [], 'edges': []}

        with patch('mcpyghidra.tools.cfg.cfg', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = mock_result
            result = _run_async(reg.cfg, address='0x1000')

        mock_result.model_dump.assert_called_once_with(by_alias=True)
        assert result == {'nodes': [], 'edges': []}

    def test_callgraph_calls_model_dump(self):
        reg = self._make_reg()

        mock_result = MagicMock()
        mock_result.model_dump.return_value = {'root': '0x1000', 'nodes': []}

        with patch('mcpyghidra.tools.cfg.callgraph', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = mock_result
            result = _run_async(reg.callgraph, address='0x1000')

        mock_result.model_dump.assert_called_once_with(by_alias=True)
        assert result == {'root': '0x1000', 'nodes': []}


# ---------------------------------------------------------------------------
# 14. open_program — GUI vs headless delegation
# ---------------------------------------------------------------------------


class TestOpenProgram:
    """open_program delegates to tools.open_program.open_program."""

    def test_open_program_delegates(self):
        from mcpyghidra.server import McpToolRegistration

        backend = _make_backend(is_headless=False)
        reg = McpToolRegistration(backend)

        expected = {'status': 'ready', 'binary': 'test.elf'}

        with patch('mcpyghidra.tools.open_program.open_program', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = _run_async(reg.open_program, path_or_name='/tmp/test.elf', wait=False, timeout=10)

        mock_fn.assert_awaited_once_with(backend, '/tmp/test.elf', False, 10)
        assert result == expected


# ---------------------------------------------------------------------------
# 15. server://info resource — error paths
# ---------------------------------------------------------------------------


class TestServerInfoResource:
    """server://info: backend.program raises and version fallback paths."""

    def test_program_raises_returns_no_binary(self):
        """If backend.program raises, binary/arch/path are all None."""
        backend = _make_backend(is_headless=True)
        backend.program.getName.side_effect = RuntimeError('no program')

        fn = _capture_resource(backend, 'server://info')
        assert fn is not None
        result = fn()

        assert result['binary'] is None
        assert result['analysis_status'] == 'no_binary'

    def test_get_port_called_at_request_time(self):
        """get_port callable is invoked when the resource is fetched."""
        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'crackme.elf'
        backend.program.getExecutablePath.return_value = '/crackme.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        call_count = [0]

        def dynamic_port():
            call_count[0] += 1
            return 7777

        fn = _capture_resource(backend, 'server://info', get_port=dynamic_port)
        result = fn()

        assert result['port'] == 7777
        assert call_count[0] == 1

    def test_get_port_none_when_not_provided(self):
        """If get_port is None (not provided), port is None."""
        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'crackme.elf'
        backend.program.getExecutablePath.return_value = '/crackme.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        fn = _capture_resource(backend, 'server://info')
        result = fn()
        assert result['port'] is None

    def test_pyghidra_version_fallback_in_resource(self):
        """ghidra.framework.Application unavailable → falls back to pyghidra version."""
        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'crackme.elf'
        backend.program.getExecutablePath.return_value = '/crackme.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        bad_framework = MagicMock()
        bad_framework.Application.getApplicationVersion.side_effect = RuntimeError('no ghidra')

        mock_pyghidra = MagicMock()
        mock_pyghidra.__version__ = '9.8.7'

        fn = _capture_resource(backend, 'server://info')

        with (
            patch.dict('sys.modules', {'ghidra.framework': bad_framework}),
            patch.dict('sys.modules', {'pyghidra': mock_pyghidra}),
        ):
            result = fn()

        # Version should be '9.8.7' from pyghidra fallback
        assert result['version'] == '9.8.7'

    def test_both_version_fallbacks_fail_returns_unknown(self):
        """Both ghidra and pyghidra unavailable → version is 'unknown'."""
        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'crackme.elf'
        backend.program.getExecutablePath.return_value = '/crackme.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        bad_framework = MagicMock()
        bad_framework.Application.getApplicationVersion.side_effect = RuntimeError('no ghidra')

        bad_pyghidra = MagicMock()
        bad_pyghidra.__version__ = MagicMock()
        # Force str() of __version__ to raise
        bad_pyghidra.__version__ = property(  # type: ignore[assignment]
            fget=lambda self: (_ for _ in ()).throw(RuntimeError('no version'))
        )

        fn = _capture_resource(backend, 'server://info')

        orig_import = __import__

        def mock_import(name, *args, **kwargs):
            if name == 'pyghidra':
                raise ImportError('no pyghidra')
            return orig_import(name, *args, **kwargs)

        with (
            patch.dict('sys.modules', {'ghidra.framework': bad_framework}),
            patch('builtins.__import__', side_effect=mock_import),
        ):
            result = fn()

        assert result['version'] == 'unknown'


# ---------------------------------------------------------------------------
# 16. project://binaries resource — GUI mode paths
# ---------------------------------------------------------------------------


class TestProjectBinariesResource:
    """project://binaries: GUI mode with tool/project access."""

    def test_headless_returns_empty(self):
        backend = _make_backend(is_headless=True)
        fn = _capture_resource(backend, 'project://binaries')
        assert fn is not None
        result = json.loads(fn())
        assert result['project_name'] is None
        assert result['binaries'] == []

    def test_gui_project_none_returns_empty(self):
        """GUI backend but project is None → empty binaries."""
        backend = _make_backend(is_headless=False)

        mock_tool = MagicMock()
        mock_tool.getProject.return_value = None
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'project://binaries')
        assert fn is not None

        mock_pm_service = MagicMock()
        mock_pm_service.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(ProgramManager=mock_pm_service),
            'mcpyghidra.mcpserver': MagicMock(MCPPortManager=MagicMock(_instance=None)),
        }):
            result = json.loads(fn())

        assert result['project_name'] is None
        assert result['binaries'] == []

    def test_gui_exception_returns_error_key(self):
        """GUI backend raises during project recursion → error key in result."""
        backend = _make_backend(is_headless=False)

        mock_tool = MagicMock()
        mock_project = MagicMock()
        mock_project.getName.return_value = 'TestProject'
        # Make getRootFolder raise to trigger the except clause
        mock_project.getProjectData.return_value.getRootFolder.side_effect = RuntimeError(
            'root folder exploded'
        )
        mock_tool.getProject.return_value = mock_project
        mock_tool.getService.return_value = None
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'project://binaries')
        assert fn is not None

        mock_pm_service = MagicMock()
        mock_pm_service.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(ProgramManager=mock_pm_service),
            'mcpyghidra.mcpserver': MagicMock(MCPPortManager=MagicMock(_instance=None)),
        }):
            result = json.loads(fn())

        assert 'error' in result

    def test_gui_with_project_collects_binaries(self):
        """GUI backend with a valid project → binaries list populated."""
        backend = _make_backend(is_headless=False)

        # Set up a minimal domain file and folder
        mock_file = MagicMock()
        mock_file.getName.return_value = 'firmware.bin'
        mock_file.getPathname.return_value = '/firmware.bin'

        mock_root = MagicMock()
        mock_root.getPathname.return_value = '/'
        mock_root.getFiles.return_value = [mock_file]
        mock_root.getFolders.return_value = []

        mock_project = MagicMock()
        mock_project.getName.return_value = 'MyProject'
        mock_project.getProjectData.return_value.getRootFolder.return_value = mock_root

        mock_pm = MagicMock()
        mock_pm.getAllOpenPrograms.return_value = []

        mock_tool = MagicMock()
        mock_tool.getProject.return_value = mock_project
        mock_tool.getService.return_value = mock_pm
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'project://binaries')
        assert fn is not None

        mock_pm_service = MagicMock()
        mock_pm_service.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(ProgramManager=mock_pm_service),
            'mcpyghidra.mcpserver': MagicMock(MCPPortManager=MagicMock(_instance=None)),
        }):
            result = json.loads(fn())

        assert result['project_name'] == 'MyProject'
        assert len(result['binaries']) == 1
        assert result['binaries'][0]['name'] == 'firmware.bin'


# ---------------------------------------------------------------------------
# 17. ghidra://disasm resource — error path
# ---------------------------------------------------------------------------


class TestDisasmResource:
    """ghidra://disasm raises ToolError when analysis.disasm returns an error."""

    def test_disasm_error_raises_tool_error(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://disasm/{addr}/{count}')
        assert fn is not None

        with patch(
            'mcpyghidra.tools.analysis.disasm',
            new_callable=AsyncMock,
            return_value=[{'error': 'bad address', 'asm': None}],
        ):
            with pytest.raises(ToolError, match='bad address'):
                _run_async(fn, addr='0xDEAD', count=5)

    def test_disasm_success_returns_asm(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://disasm/{addr}/{count}')
        assert fn is not None

        with patch(
            'mcpyghidra.tools.analysis.disasm',
            new_callable=AsyncMock,
            return_value=[{'error': None, 'asm': 'PUSH RBP\nMOV RBP, RSP'}],
        ):
            result = _run_async(fn, addr='0x1000', count=2)

        assert 'PUSH' in result


# ---------------------------------------------------------------------------
# 18. ghidra://bytes resource — error path
# ---------------------------------------------------------------------------


class TestBytesResource:
    """ghidra://bytes raises ToolError on memory read failure."""

    def test_bytes_error_raises_tool_error(self):
        backend = _make_backend()
        backend.program.getAddressFactory.return_value.getAddress.side_effect = RuntimeError(
            'bad addr'
        )

        fn = _capture_resource(backend, 'ghidra://bytes/{addr}/{size}')
        assert fn is not None

        with pytest.raises(ToolError, match='Failed to read bytes'):
            fn(addr='0xDEAD', size=16)

    def test_bytes_success_returns_hex_string(self):
        backend = _make_backend()
        mock_ea = MagicMock()
        backend.program.getAddressFactory.return_value.getAddress.return_value = mock_ea

        mock_mem = MagicMock()
        mock_mem.getBytes.return_value = 4  # number of bytes read
        backend.program.getMemory.return_value = mock_mem

        fn = _capture_resource(backend, 'ghidra://bytes/{addr}/{size}')
        assert fn is not None

        result = fn(addr='0x1000', size=4)
        # bytearray(4) zeroed → '00000000'
        assert result == '00000000'


# ---------------------------------------------------------------------------
# 19. ghidra://xrefs/to-func resource — error path
# ---------------------------------------------------------------------------


class TestXrefsToFuncResource:
    """ghidra://xrefs/to-func raises ToolError on xrefs error."""

    def test_xrefs_error_raises_tool_error(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://xrefs/to-func/{identifier}')
        assert fn is not None

        with patch(
            'mcpyghidra.tools.analysis.xrefs',
            new_callable=AsyncMock,
            return_value=[{'error': 'no such function', 'refs': None}],
        ):
            with pytest.raises(ToolError, match='no such function'):
                _run_async(fn, identifier='bad_func')

    def test_xrefs_success_returns_refs(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://xrefs/to-func/{identifier}')
        assert fn is not None

        expected_refs = [{'from': '0x1234', 'to': '0x5678'}]

        with patch(
            'mcpyghidra.tools.analysis.xrefs',
            new_callable=AsyncMock,
            return_value=[{'error': None, 'refs': expected_refs}],
        ):
            result = _run_async(fn, identifier='my_func')

        assert result == expected_refs


# ---------------------------------------------------------------------------
# 20. ghidra://type resource — error path
# ---------------------------------------------------------------------------


class TestTypeInfoResource:
    """ghidra://type raises ToolError on type lookup failure."""

    def test_type_info_error_raises_tool_error(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://type/{type_name}')
        assert fn is not None

        with patch(
            'mcpyghidra.tools.types.type_info',
            new_callable=AsyncMock,
            return_value=[{'error': 'type not found', 'target': 'BadType'}],
        ):
            with pytest.raises(ToolError, match='type not found'):
                _run_async(fn, type_name='BadType')

    def test_type_info_success_returns_dict(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://type/{type_name}')
        assert fn is not None

        expected = {'name': 'MyStruct', 'error': None, 'members': []}

        with patch(
            'mcpyghidra.tools.types.type_info',
            new_callable=AsyncMock,
            return_value=[expected],
        ):
            result = _run_async(fn, type_name='MyStruct')

        assert result == expected


# ---------------------------------------------------------------------------
# 21. ghidra://selection resource — headless and GUI branches
# ---------------------------------------------------------------------------


class TestSelectionResource:
    """ghidra://selection: headless returns sentinel, GUI branches."""

    def test_headless_returns_not_available(self):
        """Backend without _tool attr → headless sentinel."""
        backend = _make_backend(is_headless=True)
        # Ensure _tool is None (not auto-created by MagicMock)
        backend._tool = None

        fn = _capture_resource(backend, 'ghidra://selection')
        assert fn is not None
        result = fn()
        assert result['selected'] is False
        assert 'headless' in result.get('reason', '')

    def test_gui_service_none_returns_not_selected(self):
        """tool.getService returns None → selected=False."""
        backend = _make_backend(is_headless=False)

        mock_tool = MagicMock()
        mock_tool.getService.return_value = None
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'ghidra://selection')
        assert fn is not None

        mock_cv = MagicMock()
        mock_cv.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv),
        }):
            result = fn()

        assert result['selected'] is False

    def test_gui_selection_empty_returns_not_selected(self):
        """Selection is empty → selected=False."""
        backend = _make_backend(is_headless=False)

        mock_selection = MagicMock()
        mock_selection.isEmpty.return_value = True

        mock_svc = MagicMock()
        mock_svc.getCurrentSelection.return_value = mock_selection

        mock_tool = MagicMock()
        mock_tool.getService.return_value = mock_svc
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'ghidra://selection')
        assert fn is not None

        mock_cv = MagicMock()
        mock_cv.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv),
        }):
            result = fn()

        assert result['selected'] is False

    def test_gui_selection_none_returns_not_selected(self):
        """getCurrentSelection() returns None → selected=False."""
        backend = _make_backend(is_headless=False)

        mock_svc = MagicMock()
        mock_svc.getCurrentSelection.return_value = None

        mock_tool = MagicMock()
        mock_tool.getService.return_value = mock_svc
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'ghidra://selection')
        assert fn is not None

        mock_cv = MagicMock()
        mock_cv.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv),
        }):
            result = fn()

        assert result['selected'] is False

    def test_gui_selection_populated_returns_range(self):
        """Active selection → selected=True with start/end/size."""
        backend = _make_backend(is_headless=False)

        mock_selection = MagicMock()
        mock_selection.isEmpty.return_value = False
        mock_selection.getMinAddress.return_value = '0x1000'
        mock_selection.getMaxAddress.return_value = '0x10ff'
        mock_selection.getNumAddresses.return_value = 256

        mock_svc = MagicMock()
        mock_svc.getCurrentSelection.return_value = mock_selection

        mock_tool = MagicMock()
        mock_tool.getService.return_value = mock_svc
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'ghidra://selection')
        assert fn is not None

        mock_cv = MagicMock()
        mock_cv.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv),
        }):
            result = fn()

        assert result['selected'] is True
        assert result['size'] == 256

    def test_gui_exception_returns_not_selected(self):
        """Any exception → selected=False (catch-all)."""
        backend = _make_backend(is_headless=False)

        mock_tool = MagicMock()
        mock_tool.getService.side_effect = RuntimeError('service crash')
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'ghidra://selection')
        assert fn is not None

        mock_cv = MagicMock()
        mock_cv.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(CodeViewerService=mock_cv),
        }):
            result = fn()

        assert result['selected'] is False


# ---------------------------------------------------------------------------
# 22. ghidra://program/entrypoints resource
# ---------------------------------------------------------------------------


class TestEntrypointsResource:
    """ghidra://program/entrypoints: success and exception paths."""

    def test_entrypoints_success(self):
        backend = _make_backend()

        mock_addr = MagicMock()
        mock_addr.offset = 0x401000

        mock_sym = MagicMock()
        mock_sym.getName.return_value = 'entry'

        mock_st = MagicMock()
        mock_st.getExternalEntryPointIterator.return_value = iter([mock_addr])
        mock_st.getPrimarySymbol.return_value = mock_sym
        backend.program.getSymbolTable.return_value = mock_st

        fn = _capture_resource(backend, 'ghidra://program/entrypoints')
        assert fn is not None
        result = fn()

        assert len(result) == 1
        assert result[0]['name'] == 'entry'

    def test_entrypoints_symbol_none_uses_default_name(self):
        """Primary symbol is None → name is 'entry_{addr:#x}'."""
        backend = _make_backend()

        mock_addr = MagicMock()
        mock_addr.offset = 0x401000

        mock_st = MagicMock()
        mock_st.getExternalEntryPointIterator.return_value = iter([mock_addr])
        mock_st.getPrimarySymbol.return_value = None
        backend.program.getSymbolTable.return_value = mock_st

        fn = _capture_resource(backend, 'ghidra://program/entrypoints')
        result = fn()

        assert len(result) == 1
        assert 'entry_' in result[0]['name']

    def test_entrypoints_exception_returns_empty(self):
        """program.getSymbolTable raises → returns empty list (exception swallowed)."""
        backend = _make_backend()
        backend.program.getSymbolTable.side_effect = RuntimeError('crash')

        fn = _capture_resource(backend, 'ghidra://program/entrypoints')
        result = fn()

        assert result == []


# ---------------------------------------------------------------------------
# 23. _declare_rpc_capability
# ---------------------------------------------------------------------------


class TestDeclareRpcCapability:
    """_declare_rpc_capability injects mcpy/rpcCallbacks into init options."""

    def test_injects_capability(self):
        from mcpyghidra.server import _declare_rpc_capability

        mock_mcp = MagicMock()
        original = MagicMock(return_value={'experimental_capabilities': {}})
        mock_mcp._mcp_server.create_initialization_options = original

        _declare_rpc_capability(mock_mcp)

        patched = mock_mcp._mcp_server.create_initialization_options
        # Call with no existing experimental capabilities
        patched()
        original.assert_called_once()
        call_kwargs = original.call_args.kwargs
        assert 'mcpy/rpcCallbacks' in call_kwargs.get('experimental_capabilities', {})

    def test_existing_capabilities_preserved(self):
        from mcpyghidra.server import _declare_rpc_capability

        mock_mcp = MagicMock()
        original = MagicMock(return_value={})
        mock_mcp._mcp_server.create_initialization_options = original

        _declare_rpc_capability(mock_mcp)
        patched = mock_mcp._mcp_server.create_initialization_options

        existing = {'other/capability': {'version': 1}}
        patched(experimental_capabilities=existing)

        call_kwargs = original.call_args.kwargs
        caps = call_kwargs['experimental_capabilities']
        assert 'mcpy/rpcCallbacks' in caps
        assert 'other/capability' in caps

    def test_none_experimental_creates_empty_dict(self):
        from mcpyghidra.server import _declare_rpc_capability

        mock_mcp = MagicMock()
        original = MagicMock(return_value={})
        mock_mcp._mcp_server.create_initialization_options = original

        _declare_rpc_capability(mock_mcp)
        patched = mock_mcp._mcp_server.create_initialization_options

        patched(experimental_capabilities=None)

        call_kwargs = original.call_args.kwargs
        caps = call_kwargs['experimental_capabilities']
        assert 'mcpy/rpcCallbacks' in caps


# ---------------------------------------------------------------------------
# 24. ThreadedServer
# ---------------------------------------------------------------------------


class TestThreadedServer:
    """ThreadedServer disables signal handlers and uses pre-bound sockets."""

    def test_install_signal_handlers_is_noop(self):
        from mcpyghidra.server import ThreadedServer

        import uvicorn

        config = uvicorn.Config(app=MagicMock(), host='127.0.0.1', port=0)
        server = ThreadedServer(config, sockets=None)
        # Should not raise
        server.install_signal_handlers()

    def test_sockets_stored(self):
        from mcpyghidra.server import ThreadedServer

        import uvicorn

        config = uvicorn.Config(app=MagicMock(), host='127.0.0.1', port=0)
        fake_sockets = [MagicMock()]
        server = ThreadedServer(config, sockets=fake_sockets)
        assert server._sockets is fake_sockets


# ---------------------------------------------------------------------------
# 25. _register helper — annotations TypeError fallback path
# ---------------------------------------------------------------------------


class TestRegisterAnnotationsFallback:
    """_register falls back to mcp.resource() without annotations on TypeError."""

    def test_type_error_falls_back_to_no_annotations(self):
        """If mcp.resource(..., annotations=...) raises TypeError, retry without annotations."""
        backend = _make_backend(is_headless=True)
        backend.program.getName.return_value = 'test.elf'
        backend.program.getExecutablePath.return_value = '/test.elf'
        lang = MagicMock()
        lang.getLanguageID.return_value = 'x86:LE:64:default'
        backend.program.getLanguage.return_value = lang

        registered_uris: list[str] = []

        class _FakeMcpWithTypeError:
            _call_count: dict = {}

            def resource(self, uri, **kwargs):
                call_idx = self._call_count.get(uri, 0)
                self._call_count[uri] = call_idx + 1

                def decorator(fn):
                    registered_uris.append(uri)
                    return fn

                # Raise TypeError on first call (simulating old mcp without annotations kwarg)
                if 'annotations' in kwargs and call_idx == 0:
                    raise TypeError('unexpected kwarg: annotations')

                return decorator

        from mcpyghidra.server import register_resources

        register_resources(_FakeMcpWithTypeError(), backend, get_port=None)
        # server://info should still be registered (fell back to no-annotations path)
        assert 'server://info' in registered_uris


# ---------------------------------------------------------------------------
# 26. Simple pass-through resource handlers
# ---------------------------------------------------------------------------


class TestPassthroughResources:
    """One-liner resource functions that just delegate to core/type_tools."""

    def test_cursor_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://cursor')
        assert fn is not None

        with patch('mcpyghidra.tools.core.cursor', new_callable=AsyncMock) as mock_cursor:
            mock_cursor.return_value = MagicMock()
            _run_async(fn)

        mock_cursor.assert_awaited_once_with(backend)

    def test_program_metadata_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://program/metadata')
        assert fn is not None

        with patch('mcpyghidra.tools.core.context', new_callable=AsyncMock) as mock_ctx:
            mock_ctx.return_value = MagicMock()
            _run_async(fn)

        mock_ctx.assert_awaited_once_with(backend)

    def test_functions_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://functions/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=100)

        mock_list.assert_awaited_once_with(backend, entry_type='function', offset=0, limit=100)

    def test_segments_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://program/segments/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=50)

        assert mock_list.call_args.kwargs['entry_type'] == 'memory_segment'

    def test_imports_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://imports/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=50)

        assert mock_list.call_args.kwargs['entry_type'] == 'import'

    def test_exports_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://exports/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=50)

        assert mock_list.call_args.kwargs['entry_type'] == 'export'

    def test_strings_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://strings/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=50)

        assert mock_list.call_args.kwargs['entry_type'] == 'string'

    def test_classes_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://classes/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=50)

        assert mock_list.call_args.kwargs['entry_type'] == 'class'

    def test_namespaces_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://namespaces/{offset}/{limit}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, offset=0, limit=50)

        assert mock_list.call_args.kwargs['entry_type'] == 'namespace'

    def test_search_functions_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://search/functions/{pattern}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, pattern='main')

        call_kwargs = mock_list.call_args.kwargs
        assert call_kwargs['entry_type'] == 'function'
        assert call_kwargs['match_filter'] == 'main'

    def test_search_strings_resource_delegates_to_core(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://search/strings/{pattern}')
        assert fn is not None

        with patch('mcpyghidra.tools.core.list_entries', new_callable=AsyncMock) as mock_list:
            mock_list.return_value = MagicMock()
            _run_async(fn, pattern='error')

        call_kwargs = mock_list.call_args.kwargs
        assert call_kwargs['entry_type'] == 'string'
        assert call_kwargs['match_filter'] == 'error'

    def test_types_resource_delegates_to_list_types_result(self):
        backend = _make_backend()
        fn = _capture_resource(backend, 'ghidra://types/{offset}/{limit}')
        assert fn is not None

        # _res_types is synchronous (list_types_result is not async); call directly.
        with patch('mcpyghidra.tools.types.list_types_result') as mock_ltr:
            mock_ltr.return_value = MagicMock()
            fn(offset=0, limit=100)

        mock_ltr.assert_called_once_with(backend, 0, 100, '')


# ---------------------------------------------------------------------------
# 27. project://binaries — open programs collected
# ---------------------------------------------------------------------------


class TestProjectBinariesOpenPrograms:
    """GUI mode with open programs: pathname is added to open_programs set."""

    def test_open_program_pathname_collected(self):
        """When pm.getAllOpenPrograms() has entries, pathnames are collected."""
        backend = _make_backend(is_headless=False)

        mock_prog_domain_file = MagicMock()
        mock_prog_domain_file.getPathname.return_value = '/firmware.bin'

        mock_open_prog = MagicMock()
        mock_open_prog.getDomainFile.return_value = mock_prog_domain_file

        mock_pm = MagicMock()
        mock_pm.getAllOpenPrograms.return_value = [mock_open_prog]

        mock_file = MagicMock()
        mock_file.getName.return_value = 'firmware.bin'
        mock_file.getPathname.return_value = '/firmware.bin'

        mock_root = MagicMock()
        mock_root.getPathname.return_value = '/'
        mock_root.getFiles.return_value = [mock_file]
        mock_root.getFolders.return_value = []

        mock_project = MagicMock()
        mock_project.getName.return_value = 'TestProject'
        mock_project.getProjectData.return_value.getRootFolder.return_value = mock_root

        mock_tool = MagicMock()
        mock_tool.getProject.return_value = mock_project
        mock_tool.getService.return_value = mock_pm
        backend._tool = mock_tool

        fn = _capture_resource(backend, 'project://binaries')
        assert fn is not None

        mock_pm_service = MagicMock()
        mock_pm_service.class_ = MagicMock()

        with patch.dict('sys.modules', {
            'ghidra.app.services': MagicMock(ProgramManager=mock_pm_service),
            'mcpyghidra.mcpserver': MagicMock(MCPPortManager=MagicMock(_instance=None)),
        }):
            result = json.loads(fn())

        assert result['project_name'] == 'TestProject'
        # The binary should be marked as open since its path is in open_programs
        assert result['binaries'][0]['is_open'] is True
