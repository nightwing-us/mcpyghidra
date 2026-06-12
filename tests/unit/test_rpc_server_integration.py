"""Unit tests for RPC callback integration in server.py and tools/scripting.py.

These tests do NOT require Ghidra, Java, or a live MCP server.  All session
and transport interactions are mocked at the Python level.

Test classes:
- TestSendCustomRequest    — low-level JSON-RPC helper constructs valid request
- TestDiscoverRpcFunctions — caching, no-capability path, listFunctions parsing
- TestBuildRpcGlobals      — nested namespace projection, escaping, conflicts, no rpc global
- TestInstallRpcPath       — pure nested-tree insertion + conflict handling
- TestScriptingIntegration — scope created/invalidated, globals injected per exec
- TestDeclareRpcCapability — experimental capabilities patched on low-level server
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import pytest

# Restrict async tests to asyncio — trio is not installed in this environment.
pytestmark = pytest.mark.anyio(backends=['asyncio'])


@pytest.fixture
def anyio_backend():
    """Override anyio backend — restrict to asyncio only."""
    return 'asyncio'

from mcpyghidra.rpc_callbacks import (  # noqa: E402  # must follow pytestmark / anyio_backend fixture
    CallbackScope,
    RPCDisconnectedError,
    RPCError,
    RPCNamespace,
    RPCTimeoutError,
    ToolNamespace,
    generate_callback_function,
)
from mcpyghidra.rpc_types import (  # noqa: E402  # must follow pytestmark / anyio_backend fixture
    FunctionDefinition,
)
from mcpyghidra.server import (  # noqa: E402  # must follow pytestmark / anyio_backend fixture
    _build_rpc_globals,
    _declare_rpc_capability,
    _discover_rpc_functions,
    _install_rpc_path,
    _make_sync_caller,
    _on_functions_changed,
    _reset_rpc_discovery,
    _send_custom_request,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_defn(
    name: str = 'search_web',
    param_order: list[str] | None = None,
    required: list[str] | None = None,
) -> FunctionDefinition:
    if param_order is None:
        param_order = ['query']
    if required is None:
        required = ['query']
    return FunctionDefinition(
        name=name,
        description=f'Description of {name}',
        parameterOrder=param_order,
        inputSchema={
            'type': 'object',
            'properties': {p: {'type': 'string'} for p in param_order},
            'required': required,
        },
    )


def _make_session(
    *,
    has_capability: bool = True,
    list_functions_result: dict | None = None,
) -> MagicMock:
    """Build a minimal mock ServerSession."""
    session = MagicMock()
    session._request_id = 0
    session._response_streams = {}
    session._write_stream = AsyncMock()

    # Build client_params with or without the experimental capability.
    client_params = MagicMock()
    caps = MagicMock()
    if has_capability:
        caps.experimental = {'mcpy/rpcCallbacks': {}}
    else:
        caps.experimental = {}
    client_params.capabilities = caps
    session.client_params = client_params

    if list_functions_result is not None:
        # Patch _send_custom_request at the test level via mock; not needed here
        # because tests that need it will patch it directly.
        pass

    return session


def _noop_rpc_caller(name: str, arguments: dict[str, Any], timeout: float) -> Any:
    """No-op rpc_caller used in tests that only check structure, not RPC behaviour."""
    return None


def _get_async_call(sync_call: Any) -> Any:
    """Extract the _async_call coroutine function from a sync_call closure.

    _make_sync_caller produces:
        def sync_call(...):   # closes over _async_call and scope
            ...
            return anyio.from_thread.run(_async_call, ...)

    We extract _async_call from the closure cells by matching co_freevars.
    """
    freevars = sync_call.__code__.co_freevars
    cells = sync_call.__closure__ or ()
    cell_map = dict(zip(freevars, cells))
    if '_async_call' not in cell_map:
        raise RuntimeError(
            '_get_async_call: closure variable _async_call not found. '
            f'Available: {list(cell_map.keys())}'
        )
    return cell_map['_async_call'].cell_contents


def _make_populated_namespace(
    names: list[str] | None = None,
) -> RPCNamespace:
    """Build an RPCNamespace with generated callback functions."""
    if names is None:
        names = ['search_web', 'ask_llm']
    ns = RPCNamespace()
    scope = CallbackScope()
    functions: dict[str, Any] = {}
    definitions: dict[str, FunctionDefinition] = {}
    for name in names:
        defn = _make_defn(name)
        fn = generate_callback_function(defn, _noop_rpc_caller, scope, ns)
        functions[name] = fn
        definitions[name] = defn
    ns.update_functions(functions, definitions)
    return ns


# ---------------------------------------------------------------------------
# TestSendCustomRequest
# ---------------------------------------------------------------------------

class TestSendCustomRequest:
    """Tests for the low-level _send_custom_request helper."""

    @pytest.mark.anyio
    async def test_constructs_jsonrpc_request_with_correct_method(self):
        """Helper sends a JSONRPCRequest with the specified method."""
        from mcp.types import JSONRPCResponse

        session = _make_session()

        # Simulate the session responding immediately via the response stream.
        async def _fake_send(msg):
            # Deliver a fake JSONRPCResponse to the waiting reader.
            req_id = session._request_id - 1  # ID was incremented before send
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={'functions': []})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        result = await _send_custom_request(session, 'mcpy/listFunctions', {})
        assert result == {'functions': []}

    @pytest.mark.anyio
    async def test_request_id_incremented(self):
        """Each call increments the session request ID."""
        from mcp.types import JSONRPCResponse

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        assert session._request_id == 0
        await _send_custom_request(session, 'mcpy/testMethod', {})
        assert session._request_id == 1
        await _send_custom_request(session, 'mcpy/testMethod', {})
        assert session._request_id == 2

    @pytest.mark.anyio
    async def test_raises_on_jsonrpc_error(self):
        """Helper raises McpError when the peer returns a JSON-RPC error."""
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData, JSONRPCError

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            err_data = ErrorData(code=-32601, message='Method not found')
            error = JSONRPCError(jsonrpc='2.0', id=req_id, error=err_data)
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(error)

        session._write_stream.send.side_effect = _fake_send

        with pytest.raises(McpError):
            await _send_custom_request(session, 'mcpy/unknown', {})

    @pytest.mark.anyio
    async def test_timeout_raises(self):
        """Helper raises TimeoutError when no response arrives within timeout."""
        session = _make_session()
        # _write_stream.send does nothing — no response will arrive.
        session._write_stream.send = AsyncMock()

        request_id = session._request_id
        with pytest.raises(TimeoutError):
            await _send_custom_request(session, 'mcpy/slow', {}, timeout=0.05)

        # Response stream must be cleaned up even on timeout.
        assert request_id not in session._response_streams

    @pytest.mark.anyio
    async def test_response_stream_cleaned_up_on_success(self):
        """_response_streams entry is removed after successful response."""
        from mcp.types import JSONRPCResponse

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        await _send_custom_request(session, 'mcpy/listFunctions', {})
        assert 0 not in session._response_streams

    @pytest.mark.anyio
    async def test_response_stream_cleaned_up_on_error(self):
        """_response_streams entry is removed even when an error response arrives."""
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData, JSONRPCError

        session = _make_session()

        async def _fake_send(msg):
            req_id = session._request_id - 1
            err = JSONRPCError(
                jsonrpc='2.0', id=req_id,
                error=ErrorData(code=-32600, message='Invalid request'),
            )
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(err)

        session._write_stream.send.side_effect = _fake_send

        with pytest.raises(McpError):
            await _send_custom_request(session, 'mcpy/fail', {})
        assert 0 not in session._response_streams

    @pytest.mark.anyio
    async def test_params_embedded_in_request(self):
        """Params dict is sent as-is in the JSON-RPC request."""
        from mcp.types import JSONRPCResponse, JSONRPCRequest

        session = _make_session()
        sent_messages: list = []

        async def _fake_send(msg):
            sent_messages.append(msg)
            req_id = session._request_id - 1
            response = JSONRPCResponse(jsonrpc='2.0', id=req_id, result={})
            stream = session._response_streams.get(req_id)
            if stream is not None:
                await stream.send(response)

        session._write_stream.send.side_effect = _fake_send

        params = {'cursor': 'abc123'}
        await _send_custom_request(session, 'mcpy/listFunctions', params)

        assert len(sent_messages) == 1
        # The message wraps a JSONRPCRequest
        msg = sent_messages[0]
        jsonrpc_req = msg.message.root
        assert isinstance(jsonrpc_req, JSONRPCRequest)
        assert jsonrpc_req.method == 'mcpy/listFunctions'
        assert jsonrpc_req.params == params


# ---------------------------------------------------------------------------
# TestDiscoverRpcFunctions
# ---------------------------------------------------------------------------

class TestDiscoverRpcFunctions:
    """Tests for _discover_rpc_functions caching and capability detection."""

    def setup_method(self):
        """Reset module-level discovery state before each test."""
        _reset_rpc_discovery()

    @pytest.mark.anyio
    async def test_returns_none_when_client_has_no_experimental(self):
        """Returns None if client capabilities.experimental is None."""
        session = _make_session(has_capability=False)
        session.client_params.capabilities.experimental = None

        result = await _discover_rpc_functions(session)
        assert result is None

    @pytest.mark.anyio
    async def test_returns_none_when_capability_absent(self):
        """Returns None if mcpy/rpcCallbacks is not in experimental dict."""
        session = _make_session(has_capability=False)

        result = await _discover_rpc_functions(session)
        assert result is None

    @pytest.mark.anyio
    async def test_returns_none_caches_false_result(self):
        """Second call with no-capability client uses cache (no extra requests)."""
        session = _make_session(has_capability=False)

        result1 = await _discover_rpc_functions(session)
        result2 = await _discover_rpc_functions(session)

        assert result1 is None
        assert result2 is None
        # _write_stream was never touched
        session._write_stream.send.assert_not_called()

    @pytest.mark.anyio
    async def test_discovers_functions_from_list_functions_response(self):
        """Builds RPCNamespace from mcpy/listFunctions response."""
        session = _make_session(has_capability=True)

        defn_data = {
            'functions': [
                {
                    'name': 'search_web',
                    'description': 'Search the web',
                    'parameterOrder': ['query'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': {'query': {'type': 'string'}},
                        'required': ['query'],
                    },
                }
            ]
        }

        with patch('mcpyghidra.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = defn_data
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert isinstance(result, RPCNamespace)
        assert 'search_web' in result._definitions

    @pytest.mark.anyio
    async def test_second_call_returns_cached_namespace(self):
        """_discover_rpc_functions returns cached result on second call."""
        session = _make_session(has_capability=True)

        defn_data = {
            'functions': [
                {
                    'name': 'fn_one',
                    'parameterOrder': ['x'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': {'x': {'type': 'string'}},
                        'required': ['x'],
                    },
                }
            ]
        }

        with patch('mcpyghidra.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = defn_data
            result1 = await _discover_rpc_functions(session)
            result2 = await _discover_rpc_functions(session)

        # Only one RPC call made
        assert mock_send.call_count == 1
        assert result1 is result2

    @pytest.mark.anyio
    async def test_returns_none_when_list_functions_raises(self):
        """Returns None gracefully when mcpy/listFunctions fails."""
        import mcpyghidra.server as srv

        session = _make_session(has_capability=True)

        with patch('mcpyghidra.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = RuntimeError('connection error')
            result = await _discover_rpc_functions(session)

        assert result is None
        # Transient failure must not be cached — allow retry on next call.
        assert srv._rpc_functions_discovered is False

    @pytest.mark.anyio
    async def test_skips_unsafe_function_names(self):
        """Functions whose names collide with Python builtins are skipped."""
        session = _make_session(has_capability=True)

        defn_data = {
            'functions': [
                {
                    'name': 'print',  # builtin — must be skipped
                    'parameterOrder': [],
                    'inputSchema': {'type': 'object', 'properties': {}},
                },
                {
                    'name': 'safe_fn',
                    'parameterOrder': ['x'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': {'x': {'type': 'string'}},
                        'required': ['x'],
                    },
                },
            ]
        }

        with patch('mcpyghidra.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = defn_data
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert 'print' not in result._definitions
        assert 'safe_fn' in result._definitions

    @pytest.mark.anyio
    async def test_returns_none_when_client_params_none(self):
        """Returns None gracefully when session.client_params is None."""
        session = _make_session(has_capability=False)
        session.client_params = None

        result = await _discover_rpc_functions(session)
        assert result is None

    @pytest.mark.anyio
    async def test_empty_functions_list_returns_namespace(self):
        """Handles empty functions list without error; namespace.is_available() True."""
        session = _make_session(has_capability=True)

        with patch('mcpyghidra.server._send_custom_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {'functions': []}
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert isinstance(result, RPCNamespace)
        assert result.is_available() is True
        assert result.available() == []

    @pytest.mark.anyio
    async def test_discover_functions_handles_pagination(self):
        """Discovery follows nextCursor for paginated function lists."""
        session = _make_session(has_capability=True)

        def _make_fn_entry(name: str) -> dict:
            return {
                'name': name,
                'parameterOrder': ['x'],
                'inputSchema': {
                    'type': 'object',
                    'properties': {'x': {'type': 'string'}},
                    'required': ['x'],
                },
            }

        # Two pages: page 1 returns function_a with nextCursor, page 2 returns function_b.
        page1 = {'functions': [_make_fn_entry('function_a')], 'nextCursor': 'page2'}
        page2 = {'functions': [_make_fn_entry('function_b')]}

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = [page1, page2]
            result = await _discover_rpc_functions(session)

        assert result is not None
        assert 'function_a' in result._definitions
        assert 'function_b' in result._definitions
        # Two calls were made — one per page.
        assert mock_send.call_count == 2
        # Second call included the cursor.
        assert mock_send.call_args_list[1].args[2] == {'cursor': 'page2'}

    @pytest.mark.anyio
    async def test_discover_functions_retries_after_failure(self):
        """Transient failure allows retry on next call."""
        import mcpyghidra.server as srv

        session = _make_session(has_capability=True)

        fn_entry = {
            'name': 'my_fn',
            'parameterOrder': ['x'],
            'inputSchema': {
                'type': 'object',
                'properties': {'x': {'type': 'string'}},
                'required': ['x'],
            },
        }

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            # First call: transient failure.
            mock_send.side_effect = RuntimeError('transient error')
            result1 = await _discover_rpc_functions(session)

        assert result1 is None
        # Cache must NOT be set after transient failure.
        assert srv._rpc_functions_discovered is False

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            # Second call: succeeds.
            mock_send.side_effect = None
            mock_send.return_value = {'functions': [fn_entry]}
            result2 = await _discover_rpc_functions(session)

        assert result2 is not None
        assert 'my_fn' in result2._definitions

    @pytest.mark.anyio
    async def test_session_identity_change_resets_cache(self):
        """When a new session connects, the cached namespace is invalidated."""
        session_a = _make_session(has_capability=True)
        session_b = _make_session(has_capability=True)

        fn_a = {
            'name': 'fn_a',
            'parameterOrder': ['x'],
            'inputSchema': {
                'type': 'object',
                'properties': {'x': {'type': 'string'}},
                'required': ['x'],
            },
        }
        fn_b = {
            'name': 'fn_b',
            'parameterOrder': ['y'],
            'inputSchema': {
                'type': 'object',
                'properties': {'y': {'type': 'string'}},
                'required': ['y'],
            },
        }

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'functions': [fn_a]}
            result_a = await _discover_rpc_functions(session_a)

        assert result_a is not None
        assert 'fn_a' in result_a._definitions

        # Second session — different identity — should trigger fresh discovery.
        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'functions': [fn_b]}
            result_b = await _discover_rpc_functions(session_b)

        assert result_b is not None
        assert 'fn_b' in result_b._definitions
        # fn_a should not be in the new session's namespace.
        assert 'fn_a' not in result_b._definitions


# ---------------------------------------------------------------------------
# TestBuildRpcGlobals
# ---------------------------------------------------------------------------

class TestBuildRpcGlobals:
    """Tests for _build_rpc_globals — per-execution nested namespace projection."""

    def _make_ns(self, names: list[str] | None = None) -> RPCNamespace:
        return _make_populated_namespace(names)

    def test_no_rpc_global_injected(self):
        """The script-facing 'rpc' object is no longer injected (Decision 2)."""
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert 'rpc' not in injected

    def test_flat_name_stays_top_level_callable(self):
        """A name with no '__' separator stays a flat top-level global."""
        ns = self._make_ns(['search_web', 'ask_llm'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert callable(injected['search_web'])
        assert callable(injected['ask_llm'])

    def test_namespaced_name_projects_to_nested(self):
        """mcp__ghidra1__list -> injected['mcp'].ghidra1.list (callable)."""
        ns = self._make_ns(['mcp__ghidra1__list'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert set(injected.keys()) == {'mcp'}
        assert isinstance(injected['mcp'], ToolNamespace)
        assert isinstance(injected['mcp'].ghidra1, ToolNamespace)
        assert callable(injected['mcp'].ghidra1.list)

    def test_projected_leaf_shows_dotted_name_in_help(self):
        """help()/repr show the dotted path (mcp.ghidra1.list), not mcp__ghidra1__list."""
        ns = self._make_ns(['mcp__ghidra1__list'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        leaf = injected['mcp'].ghidra1.list
        assert leaf.__name__ == 'mcp.ghidra1.list'
        assert leaf.__qualname__ == 'mcp.ghidra1.list'

    def test_sibling_functions_share_namespace_root(self):
        """mcp__a__x and mcp__b__y both extend the same 'mcp' root."""
        ns = self._make_ns(['mcp__a__x', 'mcp__b__y'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert set(injected.keys()) == {'mcp'}
        assert callable(injected['mcp'].a.x)
        assert callable(injected['mcp'].b.y)

    def test_hard_keyword_segment_escaped_in_tree(self):
        """mcp__import__x -> injected['mcp']._import.x (import is escaped)."""
        ns = self._make_ns(['mcp__import__x'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert callable(injected['mcp']._import.x)

    def test_top_level_builtin_shadow_escaped(self):
        """list__foo -> top 'list' is a builtin, escaped to '_list.foo'."""
        ns = self._make_ns(['list__foo'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert 'list' not in injected
        assert callable(injected['_list'].foo)

    def test_importable_module_root_escaped(self):
        """Any importable-module root (stdlib OR installed) is escaped."""
        # stdlib module
        ns = self._make_ns(['os__path__tool'])
        injected = _build_rpc_globals(ns, None, CallbackScope(), {})
        assert 'os' not in injected  # real `os` must not be shadowable
        assert callable(injected['_os'].path.tool)
        # installed (non-stdlib) package — caught by find_spec, not stdlib lists
        ns2 = self._make_ns(['anyio__x__tool'])
        injected2 = _build_rpc_globals(ns2, None, CallbackScope(), {})
        assert 'anyio' not in injected2
        assert callable(injected2['_anyio'].x.tool)

    def test_mcp_root_is_blessed_not_escaped(self):
        """`mcp` is importable (the SDK) but is the blessed faux root, not escaped."""
        ns = self._make_ns(['mcp__svc__x'])
        injected = _build_rpc_globals(ns, None, CallbackScope(), {})
        assert 'mcp' in injected and '_mcp' not in injected
        assert callable(injected['mcp'].svc.x)

    def test_top_level_existing_global_shadow_escaped(self):
        """A namespace root colliding with an existing global is escaped."""
        ns = self._make_ns(['mcp__a__x'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {'mcp': 'already_here'})
        assert callable(injected['_mcp'].a.x)

    def test_flat_name_collision_with_existing_global_escaped(self):
        """Flat name colliding with an existing global is escaped to _name."""
        ns = self._make_ns(['search_web', 'ask_llm'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {'search_web': 'already_here'})
        # escaped form is injected; the original name is left untouched
        assert 'search_web' not in injected
        assert callable(injected['_search_web'])
        assert callable(injected['ask_llm'])

    def test_top_level_shadow_escape_also_collides_skipped(self):
        """If both the name and its escaped form already exist, the function is skipped."""
        ns = self._make_ns(['search_web', 'ask_llm'])
        scope = CallbackScope()
        existing = {'search_web': 'x', '_search_web': 'y'}
        injected = _build_rpc_globals(ns, None, scope, existing)
        assert 'search_web' not in injected
        assert '_search_web' not in injected
        # ask_llm is unaffected
        assert callable(injected['ask_llm'])

    def test_leaf_vs_namespace_conflict_first_wins(self):
        """mcp__ghidra1 (leaf) wins over mcp__ghidra1__list (namespace); latter skipped."""
        ns = self._make_ns(['mcp__ghidra1', 'mcp__ghidra1__list'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        # sorted order: 'mcp__ghidra1' claims the leaf first
        assert callable(injected['mcp'].ghidra1)
        assert 'list' not in dir(injected['mcp'].ghidra1)

    def test_all_underscore_name_skipped(self):
        """A name that yields no segments (all underscores) is skipped."""
        ns = self._make_ns(['____', 'search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert set(injected.keys()) == {'search_web'}

    def test_scope_invalidation_expires_injected_functions(self):
        """Injected callback functions raise RuntimeError after scope invalidation."""
        ns = self._make_ns(['search_web'])
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        fn = injected['search_web']
        scope.invalidate()
        with pytest.raises(RuntimeError, match='Callback expired'):
            fn('hello')

    def test_empty_namespace_returns_empty_dict(self):
        """Empty RPCNamespace yields no globals (no 'rpc' key)."""
        ns = RPCNamespace()
        ns.update_functions({}, {})
        scope = CallbackScope()
        injected = _build_rpc_globals(ns, None, scope, {})
        assert injected == {}


# ---------------------------------------------------------------------------
# TestScriptingIntegration
# ---------------------------------------------------------------------------

class TestScriptingIntegration:
    """Tests for the scripting.py changes — scope lifecycle and globals injection.

    We test _pyghidra_eval_sync directly (sync, no thread pool) since we can
    supply a mock rpc_namespace without needing Ghidra.
    """

    def _make_ns(self, names: list[str] | None = None) -> RPCNamespace:
        return _make_populated_namespace(names)

    def _make_backend(self) -> MagicMock:
        """Create a minimal mock GhidraBackend."""
        backend = MagicMock()
        return backend

    def test_callback_scope_invalidated_after_execution(self):
        """CallbackScope is invalidated once _pyghidra_eval_sync returns."""
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        # We need _persistent_globals to be set; patch _build_pyghidra_script.
        with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
            mock_build.return_value = {}
            with patch('mcpyghidra.tools.scripting._persistent_globals', None):
                captured_scopes: list[CallbackScope] = []

                def _capture_scope(*args, **kwargs):
                    # Intercept _build_rpc_globals to capture the scope.
                    scope = kwargs.get('scope') or args[2]
                    captured_scopes.append(scope)
                    return {'rpc': RPCNamespace()}

                ns = self._make_ns(['search_web'])
                backend = self._make_backend()

                with patch('mcpyghidra.server._build_rpc_globals', side_effect=_capture_scope):
                    _pyghidra_eval_sync(backend, 'x = 1', rpc_namespace=ns)

                assert len(captured_scopes) == 1
                assert not captured_scopes[0].is_valid

    def test_callback_scope_invalidated_even_on_error(self):
        """Scope is invalidated even when script execution raises an exception."""
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        captured_scopes: list[CallbackScope] = []

        def _capture_scope(*args, **kwargs):
            scope = kwargs.get('scope') or args[2]
            captured_scopes.append(scope)
            return {'rpc': RPCNamespace()}

        ns = self._make_ns(['search_web'])
        backend = self._make_backend()

        with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
            mock_build.return_value = {}
            with patch('mcpyghidra.tools.scripting._persistent_globals', None):
                with patch('mcpyghidra.server._build_rpc_globals', side_effect=_capture_scope):
                    result = _pyghidra_eval_sync(
                        backend,
                        'raise ValueError("intentional")',
                        rpc_namespace=ns,
                    )

        # Script errored but scope is still invalidated.
        assert result.success is False
        assert len(captured_scopes) == 1
        assert not captured_scopes[0].is_valid

    def test_no_rpc_namespace_no_scope_created(self):
        """When rpc_namespace is None no CallbackScope is created."""
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = self._make_backend()

        with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
            mock_build.return_value = {}
            with patch('mcpyghidra.tools.scripting._persistent_globals', None):
                with patch('mcpyghidra.server._build_rpc_globals') as mock_build_globals:
                    _pyghidra_eval_sync(backend, '1 + 1', rpc_namespace=None)
                    mock_build_globals.assert_not_called()

    def test_unavailable_namespace_no_scope_created(self):
        """When rpc_namespace.is_available() is False, no CallbackScope is created."""
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        ns = RPCNamespace()  # freshly created — not available yet

        backend = self._make_backend()

        with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
            mock_build.return_value = {}
            with patch('mcpyghidra.tools.scripting._persistent_globals', None):
                with patch('mcpyghidra.server._build_rpc_globals') as mock_build_globals:
                    _pyghidra_eval_sync(backend, '1 + 1', rpc_namespace=ns)
                    mock_build_globals.assert_not_called()

    def test_rpc_globals_injected_into_persistent_globals(self):
        """_build_rpc_globals result is merged into _persistent_globals during exec."""
        import mcpyghidra.tools.scripting as scripting_mod
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        ns = self._make_ns(['my_callback'])
        backend = self._make_backend()

        def _fake_build_globals(namespace, session, scope, existing):
            return {'mcp': RPCNamespace(), 'my_callback': lambda: 'ok'}

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.server._build_rpc_globals', side_effect=_fake_build_globals):
                result = _pyghidra_eval_sync(backend, '1', rpc_namespace=ns)
        finally:
            scripting_mod._persistent_globals = saved

        assert result.success is True

    def test_rpc_globals_cleaned_up_after_execution(self):
        """RPC globals injected for an execution are popped from _persistent_globals."""
        import mcpyghidra.tools.scripting as scripting_mod
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        ns = self._make_ns(['my_callback'])
        backend = self._make_backend()

        def _fake_build_globals(namespace, session, scope, existing):
            return {'mcp': RPCNamespace(), 'my_callback': lambda: 'ok'}

        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.server._build_rpc_globals', side_effect=_fake_build_globals):
                _pyghidra_eval_sync(backend, '1', rpc_namespace=ns)
            pg = scripting_mod._persistent_globals
        finally:
            scripting_mod._persistent_globals = saved

        # After execution, the injected top-level keys must be gone.
        assert pg is not None
        assert 'my_callback' not in pg
        assert 'mcp' not in pg


# ---------------------------------------------------------------------------
# TestDeclareRpcCapability
# ---------------------------------------------------------------------------

class TestDeclareRpcCapability:
    """Tests for _declare_rpc_capability — experimental capability injection."""

    def _make_mcp(self) -> MagicMock:
        """Build a minimal FastMCP mock."""
        from mcp.server.models import InitializationOptions
        from mcp.types import ServerCapabilities

        mcp = MagicMock()
        low_level = MagicMock()

        # Real create_initialization_options behaviour: returns InitializationOptions.
        def _real_create(notification_options=None, experimental_capabilities=None):
            caps = experimental_capabilities or {}
            return InitializationOptions(
                server_name='test',
                server_version='0.0.0',
                capabilities=ServerCapabilities(experimental=caps),
            )

        low_level.create_initialization_options = _real_create
        mcp._mcp_server = low_level
        return mcp

    def test_experimental_capability_added(self):
        """After patching, create_initialization_options includes mcpy/rpcCallbacks."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options()
        assert opts.capabilities.experimental is not None
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental

    def test_existing_capabilities_preserved(self):
        """Existing experimental capabilities are not removed by the patch."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options(
            experimental_capabilities={'some/other': {'value': 1}}
        )
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental
        assert 'some/other' in opts.capabilities.experimental

    def test_setdefault_semantics_when_already_present(self):
        """If mcpy/rpcCallbacks is already declared, the existing value is kept."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)

        existing_value = {'version': 1}
        opts = mcp._mcp_server.create_initialization_options(
            experimental_capabilities={'mcpy/rpcCallbacks': existing_value}
        )
        assert opts.capabilities.experimental['mcpy/rpcCallbacks'] == existing_value

    def test_patch_is_idempotent(self):
        """Calling _declare_rpc_capability twice does not corrupt capabilities."""
        mcp = self._make_mcp()
        _declare_rpc_capability(mcp)
        _declare_rpc_capability(mcp)

        opts = mcp._mcp_server.create_initialization_options()
        assert opts.capabilities.experimental is not None
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental

    def test_original_called_with_correct_args(self):
        """The patched function delegates to the original with merged caps."""
        mcp = self._make_mcp()

        _declare_rpc_capability(mcp)

        # Call with additional caps — original should receive merged dict.
        opts = mcp._mcp_server.create_initialization_options(
            experimental_capabilities={'extra/cap': {}}
        )
        assert 'mcpy/rpcCallbacks' in opts.capabilities.experimental
        assert 'extra/cap' in opts.capabilities.experimental


# ---------------------------------------------------------------------------
# TestMakeSyncCaller
# ---------------------------------------------------------------------------

class TestMakeSyncCaller:
    """Tests for _make_sync_caller — sync→async bridge for mcpy/callFunction."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_scope(self) -> CallbackScope:
        return CallbackScope()

    def _make_session(self) -> MagicMock:
        return _make_session()

    # ------------------------------------------------------------------
    # sync_call scope check
    # ------------------------------------------------------------------

    def test_sync_caller_checks_scope_before_bridge(self):
        """Expired scope raises RuntimeError before anyio.from_thread.run is called."""
        session = self._make_session()
        scope = self._make_scope()
        scope.invalidate()

        sync_call = _make_sync_caller(session, scope)

        with patch('anyio.from_thread.run') as mock_run:
            with pytest.raises(RuntimeError, match='Callback expired'):
                sync_call('my_fn', {}, 30.0)
            mock_run.assert_not_called()

    def test_sync_caller_bridges_to_async(self):
        """sync_call invokes anyio.from_thread.run with _async_call coroutine."""
        session = self._make_session()
        scope = self._make_scope()

        sync_call = _make_sync_caller(session, scope)

        with patch('anyio.from_thread.run', return_value='result_value') as mock_run:
            result = sync_call('my_fn', {'x': 1}, 30.0)

        assert result == 'result_value'
        assert mock_run.call_count == 1
        # First positional arg should be an awaitable (_async_call coroutine function)
        call_args = mock_run.call_args
        assert callable(call_args.args[0]), 'First arg to anyio.from_thread.run must be callable'
        # Remaining args are forwarded correctly
        assert call_args.args[1] == 'my_fn'
        assert call_args.args[2] == {'x': 1}
        assert call_args.args[3] == 30.0

    # ------------------------------------------------------------------
    # _async_call behaviour (tested via anyio event loop)
    # ------------------------------------------------------------------

    @pytest.mark.anyio
    async def test_async_call_sends_callfunction_request(self):
        """_async_call sends mcpy/callFunction with correct method and params."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'content': 'answer'}

            result = await anyio.to_thread.run_sync(
                lambda: anyio.from_thread.run(
                    _get_async_call(sync_call),
                    'search_web', {'q': 'test'}, 30.0,
                ),
                abandon_on_cancel=True,
            )

        assert result == 'answer'
        mock_send.assert_called_once_with(
            session, 'mcpy/callFunction',
            {'name': 'search_web', 'arguments': {'q': 'test'}},
            timeout=30.0,
        )

    @pytest.mark.anyio
    async def test_async_call_returns_content(self):
        """_async_call extracts content from CallFunctionResult."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {'content': 42}
            result = await anyio.to_thread.run_sync(
                lambda: anyio.from_thread.run(
                    _get_async_call(sync_call), 'fn', {}, 30.0
                ),
                abandon_on_cancel=True,
            )

        assert result == 42

    @pytest.mark.anyio
    async def test_async_call_timeout_raises_rpc_timeout(self):
        """TimeoutError from _send_custom_request becomes RPCTimeoutError."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = TimeoutError('timed out')
            with pytest.raises(RPCTimeoutError, match='timed out after'):
                await anyio.to_thread.run_sync(
                    lambda: anyio.from_thread.run(
                        _get_async_call(sync_call), 'slow_fn', {}, 5.0
                    ),
                    abandon_on_cancel=True,
                )

    @pytest.mark.anyio
    async def test_async_call_mcp_error_raises_rpc_error(self):
        """McpError from _send_custom_request becomes RPCError."""
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData

        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = McpError(ErrorData(code=-32600, message='bad request'))
            with pytest.raises(RPCError, match='MCP error calling'):
                await anyio.to_thread.run_sync(
                    lambda: anyio.from_thread.run(
                        _get_async_call(sync_call), 'bad_fn', {}, 30.0
                    ),
                    abandon_on_cancel=True,
                )

    @pytest.mark.anyio
    async def test_async_call_disconnect_raises_rpc_disconnected(self):
        """Unexpected Exception from _send_custom_request becomes RPCDisconnectedError."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.side_effect = ConnectionResetError('connection lost')
            with pytest.raises(RPCDisconnectedError, match='Lost connection'):
                await anyio.to_thread.run_sync(
                    lambda: anyio.from_thread.run(
                        _get_async_call(sync_call), 'fn', {}, 30.0
                    ),
                    abandon_on_cancel=True,
                )

    @pytest.mark.anyio
    async def test_async_call_exception_response_mapped(self):
        """CallFunctionException in response dict raises the mapped Python exception."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {
                'exception': {
                    'type': 'ValueError',
                    'message': 'bad value',
                    'traceback': 'File "x.py", line 1',
                }
            }
            with pytest.raises(ValueError, match='bad value'):
                await anyio.to_thread.run_sync(
                    lambda: anyio.from_thread.run(
                        _get_async_call(sync_call), 'fn', {}, 30.0
                    ),
                    abandon_on_cancel=True,
                )

    @pytest.mark.anyio
    async def test_async_call_exception_response_unknown_type_uses_runtime_error(self):
        """Unknown exception type in response falls back to RuntimeError."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            mock_send.return_value = {
                'exception': {
                    'type': 'SomeCustomError',
                    'message': 'custom error message',
                }
            }
            with pytest.raises(RuntimeError, match='custom error message'):
                await anyio.to_thread.run_sync(
                    lambda: anyio.from_thread.run(
                        _get_async_call(sync_call), 'fn', {}, 30.0
                    ),
                    abandon_on_cancel=True,
                )

    @pytest.mark.anyio
    async def test_async_call_scope_checked_before_send(self):
        """Expired scope raises RuntimeError inside _async_call before sending."""
        session = self._make_session()
        scope = self._make_scope()
        sync_call = _make_sync_caller(session, scope)
        scope.invalidate()

        with patch(
            'mcpyghidra.server._send_custom_request', new_callable=AsyncMock
        ) as mock_send:
            with pytest.raises(RuntimeError, match='Callback expired'):
                await anyio.to_thread.run_sync(
                    lambda: anyio.from_thread.run(
                        _get_async_call(sync_call), 'fn', {}, 30.0
                    ),
                    abandon_on_cancel=True,
                )
            mock_send.assert_not_called()


# ---------------------------------------------------------------------------
# TestBuildRpcGlobalsUsesRealCaller
# ---------------------------------------------------------------------------

class TestBuildRpcGlobalsUsesRealCaller:
    """Verify _build_rpc_globals uses the real _make_sync_caller, not _stub_rpc_caller."""

    def test_build_rpc_globals_uses_real_caller(self):
        """_build_rpc_globals creates a sync caller via _make_sync_caller, not a stub."""
        import mcpyghidra.server as srv

        # Verify _stub_rpc_caller no longer exists in server module
        assert not hasattr(srv, '_stub_rpc_caller'), (
            '_stub_rpc_caller should have been removed; '
            '_make_sync_caller is the real implementation'
        )
        # Verify _make_sync_caller exists
        assert hasattr(srv, '_make_sync_caller')

    def test_build_rpc_globals_make_sync_caller_called(self):
        """_build_rpc_globals calls _make_sync_caller with session and scope."""
        import mcpyghidra.server as srv

        session = _make_session()
        scope = CallbackScope()
        ns = RPCNamespace()
        ns.update_functions({}, {})  # empty namespace

        with patch.object(srv, '_make_sync_caller', wraps=srv._make_sync_caller) as mock_maker:
            _build_rpc_globals(ns, session, scope, {})

        mock_maker.assert_called_once_with(session, scope)


# ---------------------------------------------------------------------------
# TestSnapshotIsolation
# ---------------------------------------------------------------------------

class TestSnapshotIsolation:
    """Tests for snapshot isolation — function list updates deferred during execution.

    The invariant: once a script begins executing, _on_functions_changed() must
    not mutate the function-list cache.  Instead it sets _rpc_update_deferred so
    that the next tool call sees fresh functions.
    """

    def setup_method(self):
        """Reset all module-level RPC state before each test."""
        _reset_rpc_discovery()

    # ------------------------------------------------------------------
    # _on_functions_changed — idle path
    # ------------------------------------------------------------------

    def test_functions_changed_when_idle_invalidates_immediately(self):
        """functionsChanged when no script is running sets _rpc_functions_discovered=False."""
        import mcpyghidra.server as srv

        # Simulate a previously discovered cache.
        srv._rpc_functions_discovered = True
        srv._script_executing = False

        _on_functions_changed()

        assert srv._rpc_functions_discovered is False
        assert srv._rpc_update_deferred is False

    def test_functions_changed_when_idle_does_not_set_deferred(self):
        """When idle, _on_functions_changed sets no deferred flag."""
        import mcpyghidra.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = False

        _on_functions_changed()

        assert srv._rpc_update_deferred is False

    # ------------------------------------------------------------------
    # _on_functions_changed — executing path
    # ------------------------------------------------------------------

    def test_functions_changed_during_execution_sets_deferred_flag(self):
        """functionsChanged during script execution sets deferred flag, not cache."""
        import mcpyghidra.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = True

        _on_functions_changed()

        # Cache must NOT be invalidated mid-execution.
        assert srv._rpc_functions_discovered is True
        # Deferred flag must be set.
        assert srv._rpc_update_deferred is True

    def test_functions_changed_during_execution_preserves_discovery_flag(self):
        """Cache invalidation is deferred, not applied immediately."""
        import mcpyghidra.server as srv

        srv._rpc_functions_discovered = True
        srv._script_executing = True

        _on_functions_changed()

        assert srv._rpc_functions_discovered is True

    # ------------------------------------------------------------------
    # Script execution lifecycle — _script_executing flag management
    # ------------------------------------------------------------------

    def test_script_executing_flag_set_during_execution(self):
        """_script_executing is True while _pyghidra_eval_sync runs the script body."""
        import mcpyghidra.server as srv
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        executing_during: list[bool] = []

        def _spy_eval_ast(tree, code, exec_globals):
            executing_during.append(srv._script_executing)
            return None

        import mcpyghidra.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.tools.scripting._eval_ast', side_effect=_spy_eval_ast):
                with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
                    mock_build.return_value = {}
                    _pyghidra_eval_sync(MagicMock(), 'x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        assert len(executing_during) == 1
        assert executing_during[0] is True

    def test_script_executing_flag_cleared_after_execution(self):
        """_script_executing is False after _pyghidra_eval_sync returns."""
        import mcpyghidra.server as srv
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        import mcpyghidra.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
                mock_build.return_value = {}
                _pyghidra_eval_sync(MagicMock(), 'x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        assert srv._script_executing is False

    def test_script_executing_flag_cleared_even_on_error(self):
        """_script_executing is False after a script that raises an exception."""
        import mcpyghidra.server as srv
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        import mcpyghidra.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
                mock_build.return_value = {}
                result = _pyghidra_eval_sync(
                    MagicMock(), 'raise RuntimeError("boom")'
                )
        finally:
            scripting_mod._persistent_globals = saved

        assert result.success is False
        assert srv._script_executing is False

    # ------------------------------------------------------------------
    # Deferred update applied after execution
    # ------------------------------------------------------------------

    def test_deferred_update_applied_after_execution(self):
        """After script completes with a pending deferred flag, cache is invalidated."""
        import mcpyghidra.server as srv
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        # Pre-seed state: cache is valid, deferred update pending mid-execution.
        srv._rpc_functions_discovered = True
        srv._rpc_update_deferred = False  # will be set by _on_functions_changed below

        executing_started: list[bool] = []

        def _spy_and_notify(tree, code, exec_globals):
            # Simulate the notification arriving during execution.
            executing_started.append(srv._script_executing)
            _on_functions_changed()
            return None

        import mcpyghidra.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.tools.scripting._eval_ast', side_effect=_spy_and_notify):
                with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
                    mock_build.return_value = {}
                    _pyghidra_eval_sync(MagicMock(), 'x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        # Execution flag was True when notification arrived.
        assert executing_started[0] is True
        # After completion, discovery is invalidated and deferred flag is cleared.
        assert srv._rpc_functions_discovered is False
        assert srv._rpc_update_deferred is False
        assert srv._script_executing is False

    def test_no_deferred_update_leaves_cache_intact(self):
        """If no deferred flag was set, the cache remains valid after execution."""
        import mcpyghidra.server as srv
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        srv._rpc_functions_discovered = True
        srv._rpc_update_deferred = False

        import mcpyghidra.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
                mock_build.return_value = {}
                _pyghidra_eval_sync(MagicMock(), 'x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        # No notification arrived — cache should still be valid.
        assert srv._rpc_functions_discovered is True
        assert srv._rpc_update_deferred is False

    def test_deferred_flag_cleared_after_apply(self):
        """_rpc_update_deferred is reset to False after being applied on execution end."""
        import mcpyghidra.server as srv
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        srv._rpc_functions_discovered = True

        def _set_deferred(tree, code, exec_globals):
            _on_functions_changed()  # sets deferred while executing
            return None

        import mcpyghidra.tools.scripting as scripting_mod
        saved = scripting_mod._persistent_globals
        scripting_mod._persistent_globals = {'__builtins__': __builtins__}
        try:
            with patch('mcpyghidra.tools.scripting._eval_ast', side_effect=_set_deferred):
                with patch('mcpyghidra.tools.scripting._build_pyghidra_script') as mock_build:
                    mock_build.return_value = {}
                    _pyghidra_eval_sync(MagicMock(), 'x = 1')
        finally:
            scripting_mod._persistent_globals = saved

        assert srv._rpc_update_deferred is False

    # ------------------------------------------------------------------
    # _reset_rpc_discovery also resets snapshot state
    # ------------------------------------------------------------------

    def test_reset_rpc_discovery_clears_snapshot_state(self):
        """_reset_rpc_discovery resets both _rpc_update_deferred and _script_executing."""
        import mcpyghidra.server as srv

        srv._rpc_update_deferred = True
        srv._script_executing = True

        _reset_rpc_discovery()

        assert srv._rpc_update_deferred is False
        assert srv._script_executing is False


# ---------------------------------------------------------------------------
# TestInstallRpcPath
# ---------------------------------------------------------------------------

class TestInstallRpcPath:
    """Tests for _install_rpc_path — pure nested-tree insertion."""

    def _fn(self, tag: str):
        return lambda: tag

    def test_single_segment_is_flat_root(self):
        roots: dict = {}
        assert _install_rpc_path(roots, ['search_web'], self._fn('a')) is True
        assert callable(roots['search_web'])

    def test_nested_path_builds_namespaces(self):
        roots: dict = {}
        assert _install_rpc_path(roots, ['mcp', 'ghidra1', 'list'], self._fn('a')) is True
        assert isinstance(roots['mcp'], ToolNamespace)
        assert isinstance(roots['mcp'].ghidra1, ToolNamespace)
        assert roots['mcp'].ghidra1.list() == 'a'

    def test_multiple_paths_share_root(self):
        roots: dict = {}
        _install_rpc_path(roots, ['mcp', 'a', 'x'], self._fn('x'))
        _install_rpc_path(roots, ['mcp', 'b', 'y'], self._fn('y'))
        assert set(roots.keys()) == {'mcp'}
        assert roots['mcp'].a.x() == 'x'
        assert roots['mcp'].b.y() == 'y'

    def test_leaf_then_namespace_conflict_returns_false(self):
        roots: dict = {}
        assert _install_rpc_path(roots, ['mcp', 'ghidra1'], self._fn('leaf')) is True
        # 'mcp.ghidra1' is now a callable — nesting under it must fail
        assert _install_rpc_path(roots, ['mcp', 'ghidra1', 'list'], self._fn('x')) is False
        assert callable(roots['mcp'].ghidra1)

    def test_namespace_then_leaf_conflict_returns_false(self):
        roots: dict = {}
        assert _install_rpc_path(roots, ['mcp', 'ghidra1', 'list'], self._fn('x')) is True
        # 'mcp.ghidra1' is now a namespace — binding it as a leaf must fail
        assert _install_rpc_path(roots, ['mcp', 'ghidra1'], self._fn('leaf')) is False
        assert isinstance(roots['mcp'].ghidra1, ToolNamespace)

    def test_duplicate_leaf_returns_false(self):
        roots: dict = {}
        assert _install_rpc_path(roots, ['mcp', 'x'], self._fn('first')) is True
        assert _install_rpc_path(roots, ['mcp', 'x'], self._fn('second')) is False
        assert roots['mcp'].x() == 'first'
