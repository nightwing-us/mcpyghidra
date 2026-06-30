"""MCP server lifecycle and tool/resource registration.

This module is the registration layer that connects the extracted tool functions
in tools/ to FastMCP. It uses a McpToolRegistration class to preserve type
annotations for FastMCP schema generation (bare closures lose annotations).

Usage::

    from mcpyghidra.server import create_mcp_app

    app, mcp = create_mcp_app(backend)
"""

from __future__ import annotations

import contextvars
import functools
import importlib.util
import inspect
import json
import logging
import os
import sys
import typing
from contextlib import asynccontextmanager
from typing import (
    Annotated,
    Any,
    TYPE_CHECKING,
)

import anyio
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCError, JSONRPCMessage, JSONRPCRequest
from pydantic import Field
from starlette.middleware.cors import CORSMiddleware
import uvicorn

from mcpyghidra.rpc_callbacks import (
    CallbackScope,
    RPCDisconnectedError,
    RPCError,
    RPCNamespace,
    RPCTimeoutError,
    ToolNamespace,
    generate_callback_function,
    is_name_safe,
    map_exception,
    project_name,
)
from mcpyghidra.rpc_types import (
    CallFunctionException,
    CallFunctionResult,
    FunctionDefinition,
    ListFunctionsResult,
)
from mcpyghidra.dispatch import single_or_batch, unwrap
from mcpyghidra.tools import analysis, core, modify
from mcpyghidra.tools import types as type_tools

if TYPE_CHECKING:
    from mcpyghidra.backend import GhidraBackend


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Context threading via contextvars
# ---------------------------------------------------------------------------

_current_mcp_context: contextvars.ContextVar = contextvars.ContextVar(
    '_current_mcp_context', default=None
)


def get_current_context():
    """Return the MCP Context for the current request, or None."""
    return _current_mcp_context.get()


async def elicit_confirmation(description: str, batch_state: dict) -> bool:
    """Ask the MCP client for user confirmation via elicitation.

    Returns True to proceed, False to skip.
    Handles batch 'apply_to_all' state and falls back to auto-allow when
    elicitation is unsupported by the client or SDK.
    """
    # Check batch cache — if a previous item's 'apply_to_all' was set, use it.
    if batch_state.get('apply_to_all_decision') is not None:
        return batch_state['apply_to_all_decision']

    ctx = get_current_context()
    if ctx is None:
        return True  # No context — auto-allow

    from mcpyghidra.models import ConfirmAction

    try:
        result = await ctx.elicit(
            message=description,
            schema=ConfirmAction,
        )
    except Exception:
        # Client doesn't support elicitation or SDK version too old — auto-allow
        return True

    if result.action == 'accept':
        data = result.data
        if data is not None and data.apply_to_all:
            batch_state['apply_to_all_decision'] = data.confirm
        return data.confirm if data is not None else True

    # 'decline' or 'cancel' — skip this item
    return False


# ---------------------------------------------------------------------------
# RPC Callbacks — state, low-level helpers, function discovery
# ---------------------------------------------------------------------------

# Module-level cache: set once per server process after the first successful
# mcpy/listFunctions round-trip.  None = not yet discovered; a populated
# RPCNamespace = discovery succeeded; empty RPCNamespace with is_available()==False
# but _rpc_functions_discovered==True = client does not support the capability.
#
# _rpc_session_id tracks the id() of the session that populated the cache.
# If a new session connects (different id), the cache is invalidated.
_rpc_namespace: RPCNamespace | None = None
_rpc_functions_discovered: bool = False
_rpc_session_id: int | None = None

# Snapshot isolation state: a script execution holds the function list snapshot.
# If the client sends notifications/mcpy/functions/list_changed mid-execution,
# the update is deferred until the script completes.
_rpc_update_deferred: bool = False
_script_executing: bool = False


def _reset_rpc_discovery() -> None:
    """Reset module-level discovery cache (used by tests and server restart)."""
    global _rpc_namespace, _rpc_functions_discovered, _rpc_session_id
    global _rpc_update_deferred, _script_executing
    _rpc_namespace = None
    _rpc_functions_discovered = False
    _rpc_session_id = None
    _rpc_update_deferred = False
    _script_executing = False


def _on_functions_changed() -> None:
    """Called when the client notifies that the function list has changed.

    If a script is currently executing, the update is deferred until the script
    completes (snapshot isolation — we do not mutate the function list mid-execution).
    If no script is running, the cache is invalidated immediately so that the next
    tool call re-discovers functions.
    """
    global _rpc_update_deferred, _rpc_functions_discovered
    if _script_executing:
        _rpc_update_deferred = True  # defer until script ends
    else:
        _rpc_functions_discovered = False  # invalidate cache immediately


async def _send_custom_request(
    session: Any,
    method: str,
    params: dict[str, Any],
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Send an arbitrary JSON-RPC request through the MCP session transport.

    The MCP SDK's session.send_request() only accepts typed ServerRequest
    objects (PingRequest, CreateMessageRequest, …).  Our custom methods
    (mcpy/listFunctions, mcpy/callFunction) are not in that union, so we
    bypass the typed path and construct a JSONRPCRequest directly, then
    register a response stream exactly as the SDK does internally.

    Args:
        session: A ServerSession (or any BaseSession with _write_stream /
                 _response_streams / _request_id attributes).
        method:  The JSON-RPC method name, e.g. 'mcpy/listFunctions'.
        params:  The params dict (will be embedded verbatim).
        timeout: How long to wait for the response, in seconds.

    Returns:
        The result dict from the JSON-RPC response.

    Raises:
        McpError:    If the peer returns a JSON-RPC error.
        TimeoutError: If the response is not received within *timeout* seconds.
    """
    # NOTE: Safe under single-threaded asyncio — no await between read and write.
    # Mirrors the SDK's own send_request() pattern.
    request_id: int = session._request_id
    session._request_id = request_id + 1

    response_stream, response_stream_reader = anyio.create_memory_object_stream(1)
    session._response_streams[request_id] = response_stream

    try:
        jsonrpc_request = JSONRPCRequest(
            jsonrpc='2.0',
            id=request_id,
            method=method,
            params=params,
        )
        await session._write_stream.send(
            SessionMessage(message=JSONRPCMessage(jsonrpc_request))
        )

        with anyio.fail_after(timeout):
            response_or_error = await response_stream_reader.receive()

        if isinstance(response_or_error, JSONRPCError):
            raise McpError(response_or_error.error)

        # response_or_error is a JSONRPCResponse; .result is the payload dict
        result = response_or_error.result
        if result is None:
            return {}
        if isinstance(result, dict):
            return result
        # Pydantic model or other — convert to dict
        return dict(result)

    finally:
        session._response_streams.pop(request_id, None)
        await response_stream.aclose()
        await response_stream_reader.aclose()


def _make_sync_caller(session: Any, scope: CallbackScope) -> Any:
    """Create a sync rpc_caller that bridges to the async MCP session.

    Generated callback functions run in a thread pool (via anyio.to_thread.run_sync).
    They need to call back into the async event loop to send mcpy/callFunction.
    We use anyio.from_thread.run() for this bridge.

    Args:
        session: The live ServerSession for this tool call.
        scope:   The CallbackScope for this execution.

    Returns:
        A synchronous callable(name, arguments, timeout) -> Any that sends
        mcpy/callFunction and returns the result.content value.
    """

    async def _async_call(name: str, arguments: dict[str, Any], timeout: float) -> Any:
        scope.check()  # raises RuntimeError if expired
        try:
            raw = await _send_custom_request(
                session,
                'mcpy/callFunction',
                {'name': name, 'arguments': arguments or {}},
                timeout=timeout,
            )
        except TimeoutError:
            raise RPCTimeoutError(f'Callback {name!r} timed out after {timeout}s')
        except McpError as exc:
            raise RPCError(f'MCP error calling {name!r}: {exc}') from exc
        except (ConnectionError, OSError, EOFError) as exc:
            raise RPCDisconnectedError(
                f'Lost connection calling {name!r}: {exc}'
            ) from exc

        # Check for a server-side exception embedded in the response.
        if isinstance(raw, dict) and raw.get('exception'):
            exc_data = CallFunctionException.model_validate(raw['exception'])
            raise map_exception(exc_data.type, exc_data.message, exc_data.traceback)

        result = CallFunctionResult.model_validate(raw)
        return result.content

    def sync_call(name: str, arguments: dict[str, Any], timeout: float) -> Any:
        scope.check()  # fail fast before bridging to the event loop
        import anyio.from_thread

        return anyio.from_thread.run(_async_call, name, arguments, timeout)

    return sync_call


async def _discover_rpc_functions(session: Any) -> RPCNamespace | None:
    """Check client capability and discover callback functions.

    Sends mcpy/listFunctions on the first call and caches the result.
    Subsequent calls return the cached namespace immediately (unless the
    session identity has changed, in which case the cache is invalidated).

    Args:
        session: A live ServerSession obtained from the MCP Context.

    Returns:
        Populated RPCNamespace if the client supports mcpy/rpcCallbacks,
        otherwise None.
    """
    global _rpc_namespace, _rpc_functions_discovered, _rpc_session_id

    # Invalidate cache if a different session connected.
    current_id = id(session)
    if _rpc_session_id != current_id:
        _rpc_functions_discovered = False
        _rpc_namespace = None
        _rpc_session_id = current_id

    if _rpc_functions_discovered:
        return _rpc_namespace

    # Check whether the client declared mcpy/rpcCallbacks experimental capability.
    try:
        client_params = session.client_params
        caps = client_params.capabilities if client_params else None
        experimental = caps.experimental if caps else None
        if not experimental or 'mcpy/rpcCallbacks' not in experimental:
            _rpc_functions_discovered = True
            _rpc_namespace = None
            return None
    except Exception:
        _rpc_functions_discovered = True
        _rpc_namespace = None
        return None

    # Fetch the function list from the client, following pagination cursors.
    try:
        all_functions: list[FunctionDefinition] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {}
            if cursor:
                params['cursor'] = cursor
            raw = await _send_custom_request(session, 'mcpy/listFunctions', params)
            result = ListFunctionsResult.model_validate(raw)
            all_functions.extend(result.functions)
            if not result.nextCursor:
                break
            cursor = result.nextCursor
    except Exception as exc:
        logger.warning('mcpy/listFunctions failed: %s', exc)
        # Don't cache failure — allow retry on next tool call.
        return None

    namespace = RPCNamespace()
    functions: dict[str, Any] = {}
    definitions: dict[str, FunctionDefinition] = {}

    # Build generated callback wrappers.  We use a temporary scope; the real
    # per-execution scope will be created in pyghidra_eval and injected into
    # the script globals at that point.  The wrappers stored in the namespace
    # are regenerated per-execution — this discovery step only records which
    # functions exist so we know their definitions.
    for defn in all_functions:
        if not is_name_safe(defn.name):
            logger.warning('Skipping unsafe callback function name: %r', defn.name)
            continue
        definitions[defn.name] = defn

    namespace.update_functions(functions, definitions)
    _rpc_namespace = namespace
    _rpc_functions_discovered = True
    return namespace


def _install_rpc_path(
    roots: dict[str, Any],
    path: list[str],
    fn: Any,
) -> bool:
    """Insert callable *fn* into the nested namespace tree at *path*.

    All but the last segment are namespace levels (auto-created as
    ToolNamespace); the last segment is the callable leaf. Returns ``False``
    and installs nothing on a conflict:

    - a namespace segment is already bound to a callable (cannot nest under it)
    - the leaf slot is already occupied (by a namespace or another callable)

    Args:
        roots: Top-level mapping (name -> ToolNamespace | callable).
        path: Attribute path segments (length >= 1).
        fn: The callback wrapper to bind at the leaf.

    Returns:
        True if installed, False on conflict.
    """
    *ns_segs, leaf = path
    children = roots
    prefix: list[str] = []
    for seg in ns_segs:
        prefix.append(seg)
        node = children.get(seg)
        if node is None:
            node = ToolNamespace('.'.join(prefix))
            children[seg] = node
        elif not isinstance(node, ToolNamespace):
            return False  # a callable occupies this path — cannot nest under it
        children = node._children
    if leaf in children:
        return False  # leaf slot already taken (namespace or duplicate callable)
    children[leaf] = fn
    return True


def _shadows_real_module(name: str) -> bool:
    """True if *name* names an importable module/package.

    A projected faux top-level with such a name would shadow the real module in
    the script's import machinery (see the REPL ``__import__`` support in
    tools/scripting.py), so it must be escaped. ``mcp`` is the one blessed
    exception: the real MCP SDK is never used inside the pyghidra REPL, so
    ``mcp.*`` is the intended faux import root.
    """
    if name == 'mcp':
        return False
    if name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _top_level_collides(name: str, existing_globals: dict[str, Any]) -> bool:
    """A projected top-level *name* is unsafe if it would shadow a Python
    builtin/keyword, an existing scripting global, or an importable module."""
    return not is_name_safe(name, existing_globals) or _shadows_real_module(name)


def _build_rpc_globals(
    namespace: RPCNamespace,
    session: Any,
    scope: CallbackScope,
    existing_globals: dict[str, Any],
) -> dict[str, Any]:
    """Generate per-execution callback globals from a discovered RPCNamespace.

    Projects ``__``-separated function names into nested ``ToolNamespace``
    objects: ``mcp__ghidra1__list`` becomes ``mcp.ghidra1.list(...)``. Names
    with no ``__`` separator stay flat globals (``search_web``). The script-
    facing ``rpc`` object is no longer injected — native ``help()``/``dir()``
    cover discovery.

    Processing is in sorted raw-name order (deterministic). For each function:

    1. ``project_name`` parses the path (per-segment hard-keyword escaping);
       a name yielding no segments is skipped with a warning.
    2. The top-level segment — the only real global — is checked against
       *existing_globals* and the builtin/keyword denylist via ``is_name_safe``;
       on collision it is escaped with a leading underscore, and skipped if it
       still collides.
    3. ``_install_rpc_path`` walks/creates the namespace tree and binds the
       wrapper at the leaf; a leaf-vs-namespace or duplicate-path conflict is
       skipped with a warning ("first claim wins").

    Args:
        namespace:       The cached RPCNamespace populated by _discover_rpc_functions.
        session:         The ServerSession for this tool call (used by rpc_caller).
        scope:           The CallbackScope for this execution.
        existing_globals: The current script globals (used for collision detection).

    Returns:
        A dict of top-level name -> (ToolNamespace | callable) to merge into
        script globals, e.g. ``{'mcp': <ns>, 'search_web': <fn>}``. The keys
        are the only globals added (and later popped) by the scripting layer.
    """
    roots: dict[str, Any] = {}

    rpc_caller = _make_sync_caller(session, scope)

    for raw in sorted(namespace._definitions):
        defn = namespace._definitions[raw]
        path = project_name(raw)
        if path is None:
            logger.warning(
                'Skipping callback %r: name yields no namespace segments', raw
            )
            continue

        # The first segment is the only actual global / importable root — guard
        # it against builtins/keywords, existing script globals, AND real
        # importable modules, escaping then skipping.
        top = path[0]
        if _top_level_collides(top, existing_globals):
            escaped = '_' + top
            if _top_level_collides(escaped, existing_globals):
                logger.warning(
                    'Skipping callback %r: top-level name %r collides (builtin, '
                    'global, or importable module) even after escaping',
                    raw,
                    top,
                )
                continue
            top = escaped
        path = [top, *path[1:]]

        # mcp.self.* is reserved for this server's own in-process tools — never
        # let a reverse-RPC projection land there.
        if path[:2] == ['mcp', 'self']:
            logger.warning(
                'Skipping callback %r: mcp.self.* is reserved for in-process tools',
                raw,
            )
            continue

        fn = generate_callback_function(defn, rpc_caller, scope, namespace)
        # Display the projected dotted path in help()/repr (and tracebacks)
        # instead of the raw __-separated wire name: mcp__svc__list is reached
        # as mcp.svc.list, so help(mcp.svc.list) should read "mcp.svc.list".
        dotted = '.'.join(path)
        fn.__name__ = dotted
        fn.__qualname__ = dotted
        if not _install_rpc_path(roots, path, fn):
            logger.warning(
                'Skipping callback %r: namespace/leaf conflict at %r',
                raw,
                dotted,
            )

    return roots


# ---------------------------------------------------------------------------
# ThreadedServer
# ---------------------------------------------------------------------------


class ThreadedServer(uvicorn.Server):
    """uvicorn Server subclass that supports pre-bound sockets and disables signal handlers.

    Used by both the headless launcher (headless.py) and the Ghidra plugin server
    (mcpserver.py) so that a single socket is bound before starting the thread
    and the actual port can be read back (critical for port=0 auto-assign).
    """

    def __init__(self, config: uvicorn.Config, sockets: list | None = None):
        super().__init__(config)
        self._sockets = sockets

    def install_signal_handlers(self) -> None:
        # Disable signal handlers — we manage shutdown externally via should_exit
        ...

    def run(self, sockets: list | None = None) -> None:
        return super().run(sockets=self._sockets or sockets)


# ---------------------------------------------------------------------------
# Resource wrapper helper
# ---------------------------------------------------------------------------


def _make_resource_wrapper(fn: Any, uri_params: set[str]) -> Any:
    """Create a wrapper that exposes only URI template parameters for resource registration.

    FastMCP >= 1.25.0 validates that resource function parameters match URI
    template parameters exactly. This wrapper strips extra params not in the URI
    and eagerly resolves string annotations so pydantic TypeAdapter can build the
    JSON schema without needing access to this module's namespace.
    """
    sig = inspect.signature(fn)
    new_params = [p for name, p in sig.parameters.items() if name in uri_params]
    new_sig = sig.replace(parameters=new_params)

    @functools.wraps(fn)
    def wrapper(**kwargs: Any) -> Any:
        return fn(**kwargs)

    wrapper.__signature__ = new_sig  # type: ignore[attr-defined]

    # Resolve string annotations to concrete types using the function's own
    # module globals. Without this, pydantic resolves them from the FastMCP
    # templates.py frame which knows nothing about our types.
    try:
        underlying = inspect.unwrap(fn)
        globalns = getattr(underlying, '__globals__', {})
        resolved = typing.get_type_hints(underlying, globalns=globalns)
        wrapper.__annotations__ = resolved
    except Exception:
        pass  # keep whatever annotations were there as a fallback

    return wrapper


# ---------------------------------------------------------------------------
# McpToolRegistration class
# ---------------------------------------------------------------------------


class McpToolRegistration:
    """Registration class that preserves type annotations for FastMCP.

    Using a class instead of bare closures ensures that FastMCP can introspect
    method signatures to generate correct tool schemas. Bare closures lose their
    annotations, resulting in untyped schema parameters.

    The standalone tool functions in tools/ remain independently testable.
    This class is purely the wiring layer — it delegates all logic.
    """

    def __init__(self, backend: 'GhidraBackend') -> None:
        self._backend = backend

    def iter_tools(self) -> list[tuple[str, str, dict[str, Any], bool]]:
        """Return (method_name, tool_name, annotations, is_readonly) tuples.

        is_readonly=True means the tool will be skipped when
        MCPY_DISABLE_READONLY_TOOLS=1 is set.

        GUI-only tools (e.g. open_program) are appended only when the backend
        is not headless.
        """
        tools: list[tuple[str, str, dict[str, Any], bool]] = [
            # Core read-only tools
            ('list_entries', 'list', {'readOnlyHint': True}, True),
            ('cursor', 'cursor', {'readOnlyHint': True}, True),
            ('context', 'context', {'readOnlyHint': True}, True),
            ('funcs', 'funcs', {'readOnlyHint': True}, True),
            # Analysis read-only tools
            ('decompile', 'decompile', {'readOnlyHint': True}, True),
            ('disasm', 'disasm', {'readOnlyHint': True}, True),
            ('symbols', 'symbols', {'readOnlyHint': True}, True),
            ('xrefs', 'xrefs', {'readOnlyHint': True}, True),
            # Modify tools (write)
            ('rename', 'rename', {}, False),
            ('update_vars', 'update_vars', {}, False),
            ('set_comments', 'set_comments', {}, False),
            ('get_comment', 'get_comment', {'readOnlyHint': True}, True),
            ('set_prototype', 'set_prototype', {}, False),
            ('patch', 'patch', {'destructiveHint': True}, False),
            ('begin_trans', 'begin_trans', {}, False),
            ('end_trans', 'end_trans', {}, False),
            # Type tools
            ('type_info', 'type_info', {'readOnlyHint': True}, True),
            ('create_struct', 'create_struct', {}, False),
            ('add_field', 'add_field', {}, False),
            # Scripting
            ('pyghidra_eval', 'pyghidra', {'executesCode': True}, False),
            # Search tools
            ('find_bytes', 'find_bytes', {'readOnlyHint': True}, True),
            ('find_insns', 'find_insns', {'readOnlyHint': True}, True),
            # CFG tools
            ('cfg', 'cfg', {'readOnlyHint': True}, True),
            ('callgraph', 'callgraph', {'readOnlyHint': True}, True),
        ]
        # GUI-only tools — only registered when a Ghidra GUI is available
        if not self._backend.is_headless:
            tools.append(('open_program', 'open_program', {}, False))
        return tools

    # --- Core tools ---

    async def list_entries(
        self,
        entry_type: Annotated[
            str,
            Field(
                description=(
                    'Type of entry to list. '
                    'Valid values: function, memory_segment, import, export, string, class, namespace'
                )
            ),
        ],
        offset: Annotated[
            int, Field(description='Pagination offset (default 0)', ge=0)
        ] = 0,
        limit: Annotated[
            int, Field(description='Max items to return (default 500)', ge=1, le=10000)
        ] = 500,
        match_filter: Annotated[
            str,
            Field(
                description=(
                    'Optional substring filter on the name (functions and strings only)'
                )
            ),
        ] = '',
    ) -> Any:
        """Get a paginated list of binary entries by type.

        RETURNS: ListResult with items[], page_info (has_more, next_offset), total_count

        VALID entry_type VALUES: function, memory_segment, import, export, string, class, namespace

        EXAMPLES:
        - list(entry_type='function') -> first 500 functions
        - list(entry_type='function', limit=50) -> first 50 functions
        - list(entry_type='function', offset=100, limit=50) -> functions 100-149
        - list(entry_type='string', match_filter='error', limit=20) -> strings containing 'error'"""
        # entry_type is validated by FastMCP's enum schema at request time;
        # cast here to match core.list_entries' Literal type.
        return await core.list_entries(
            self._backend,
            entry_type=entry_type,  # type: ignore[arg-type]
            offset=offset,
            limit=limit,
            match_filter=match_filter,
        )

    async def cursor(self) -> Any:
        """Get the address and function info at the user's current cursor position in Ghidra.

        RETURNS: CurrentLocation with:
        - addr: Current hex address (e.g., "0x401000")
        - function: FunctionInfo if cursor is inside a function (name, entrypoint, signature), or null

        USE CASE: Find where the user is looking before taking contextual actions."""
        return await core.cursor(self._backend)

    async def context(self) -> Any:
        """Get comprehensive context about the currently open binary.

        RETURNS: BinaryContext with complete information about:
        - current_location: Cursor position and current function
        - program: Binary file details (path, format, size, hash)
        - architecture: Processor, bitness, endianness
        - memory: Address space layout (base, entry point, min/max)
        - analysis: Database path, function count, symbols, analysis state
        - application: RE application name and version"""
        return await core.context(self._backend)

    async def funcs(
        self,
        items: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of addresses or function names. For one, omit items and pass target.'
                ),
            ),
        ] = None,
        *,
        target: Annotated[
            str | None,
            Field(default=None, description='Single: hex address or function name.'),
        ] = None,
    ) -> Any:
        """Function info by address or name.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - name: function name
        - entrypoint: function entry point address
        - signature: function signature (on success)
        - error: null on success, error message on failure

        Single: pass target (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {'target': target},
            kind='scalar',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await core.funcs(self._backend, items), single)

    # --- Analysis tools ---

    async def decompile(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {addr?, name?}. For one function, omit items and pass addr/name.'
                ),
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None,
            Field(default=None, description='Single: function address (hex).'),
        ] = None,
        name: Annotated[
            str | None, Field(default=None, description='Single: function name.')
        ] = None,
    ) -> Any:
        """Decompile function(s). Returns C pseudocode with function comment prepended.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - code: decompiled C pseudocode (on success)
        - name: resolved function name
        - entrypoint: function entry point (hex)
        - error: null on success, error message on failure

        Single: pass addr/name (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {'addr': addr, 'name': name},
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.decompile(self._backend, items), single)

    async def disasm(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {addr?, name?, count?}. For one target, omit items and pass addr/name/count.'
                ),
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(default=None, description='Single: address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(default=None, description='Single: function name.')
        ] = None,
        count: Annotated[
            int | None,
            Field(
                default=None, description='Single: instruction count (address mode).'
            ),
        ] = None,
    ) -> Any:
        """Disassemble function(s) or address ranges. MERGED from disassemble_function + disassemble_addr.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - asm: disassembly text (on success)
        - addr: resolved address
        - name: function name (if function mode)
        - mode: 'function' or 'address'
        - error: null on success, error message on failure

        Single: pass addr/name/count (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {'addr': addr, 'name': name, 'count': count},
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.disasm(self._backend, items), single)

    async def symbols(
        self,
        items: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of hex addresses. For one address, omit items and pass addr.'
                ),
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(default=None, description='Single: hex address.')
        ] = None,
    ) -> Any:
        """Symbol info for address(es).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: input address
        - name: symbol name (on success)
        - symbol_type: one of function, code_label, global_variable, data_label, unknown
        - error: null on success, error message on failure

        Single: pass addr (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {'addr': addr},
            kind='scalar',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.symbols(self._backend, items), single)

    async def xrefs(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {addr?, name?, direction?, offset?, limit?}. '
                    'Aliases accepted: target/ea/function (0x-prefixed → address, else name). '
                    'For one target, omit items and pass addr/name.'
                ),
            ),
        ] = None,
        *,
        target: Annotated[
            str | None,
            Field(
                default=None,
                description='Single: hex address or function name (alias for addr/name).',
            ),
        ] = None,
        direction: Annotated[
            str | None, Field(default=None, description='Single: "to" or "from".')
        ] = None,
        offset: Annotated[
            int | None, Field(default=None, description='Single: pagination offset.')
        ] = None,
        limit: Annotated[
            int | None, Field(default=None, description='Single: max results.')
        ] = None,
    ) -> Any:
        """Cross-references to/from an address or function. MERGED from xrefs_to + xrefs_from.

        Input accepts addr (hex) or name (function name); aliases target/ea/function also accepted.

        RETURNS: a flat dict (single call) or list of flat dicts (batch), each with:
        - addr: resolved entry address (hex)
        - name: echoed when a function name was provided
        - direction: 'to' or 'from'
        - items: cross-reference rows
        - summary, page_info, entry_type, schema_version: lifted from ListResult
        - error: null on success, error message on failure

        Single: pass target (hex address or function name), direction, offset, limit (returns one dict).
        Batch: pass items=[…] where each item may use addr/name or aliases target/ea/function (returns a list)."""
        items, single = single_or_batch(
            items,
            {
                'target': target,
                'direction': direction,
                'offset': offset,
                'limit': limit,
            },
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await analysis.xrefs(self._backend, items), single)

    # --- Modify tools ---

    async def rename(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {new_name, addr?, name?}. For one, omit items and pass new_name + addr/name.'
                ),
            ),
        ] = None,
        *,
        new_name: Annotated[
            str | None, Field(default=None, description='Single: new symbol name.')
        ] = None,
        addr: Annotated[
            str | None, Field(default=None, description='Single: symbol address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(default=None, description='Single: current symbol name.')
        ] = None,
        ctx: Context = None,  # type: ignore[assignment]
    ) -> Any:
        """Rename symbol(s). THIS MODIFIES THE GHIDRA DATABASE.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: resolved hex address
        - old_name: previous symbol name
        - new_name: new name applied
        - error: null on success, error message on failure

        Single: pass new_name + addr/name (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items, {'new_name': new_name, 'addr': addr, 'name': name}, kind='dict'
        )
        token = _current_mcp_context.set(ctx)
        try:
            return unwrap(await modify.rename(self._backend, items), single)
        finally:
            _current_mcp_context.reset(token)

    async def update_vars(
        self,
        function_name: Annotated[
            str, Field(description='Name of the function containing the variables')
        ],
        variables_to_update: Annotated[
            dict[str, dict[str, str]],
            Field(
                description=(
                    'Mapping from current variable name to {new_name?, new_type?}'
                )
            ),
        ],
        ctx: Context = None,  # type: ignore[assignment]
    ) -> Any:
        """Rename and/or retype multiple variables in a function at once.

        THIS MODIFIES THE GHIDRA DATABASE.

        EXAMPLE:
          update_vars(
            function_name="main",
            variables_to_update={
              "local_8": {"new_name": "buffer", "new_type": "char *"},
              "param_1": {"new_name": "argc"}
            }
          )

        RETURNS: Structured dict with function/addr/results[]/error.
        results[] items: {var, new_name, new_type, error} — error null on success.
        Top-level error is null unless function-not-found or no-variables provided."""
        token = _current_mcp_context.set(ctx)
        try:
            return await modify.update_vars(
                self._backend, function_name, variables_to_update
            )
        finally:
            _current_mcp_context.reset(token)

    async def set_comments(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {comment, kind?, addr?, name?, line?}. For one, omit items.'
                ),
            ),
        ] = None,
        *,
        comment: Annotated[
            str | None, Field(default=None, description='Single: comment text.')
        ] = None,
        kind: Annotated[
            str | None,
            Field(default=None, description='Single: disasm|decompiler|function|both.'),
        ] = None,
        addr: Annotated[
            str | None, Field(default=None, description='Single: address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(default=None, description='Single: function name.')
        ] = None,
        line: Annotated[
            int | None,
            Field(default=None, description='Single: decompiler line number.'),
        ] = None,
        ctx: Context = None,  # type: ignore[assignment]
    ) -> Any:
        """Set comment(s). THIS MODIFIES THE GHIDRA DATABASE.

        kind values:
        - 'disasm'     → EOL comment at addr (requires addr)
        - 'decompiler' → pre-comment at line in function (requires line and addr or name)
        - 'function'   → plate comment on function (requires addr or name)
        - 'both'       (default) → disasm comment at addr; ALSO decompiler comment if line provided

        addr selects by address (hex string); name selects by function name. line is the
        decompiler line number within the function body (required for decompiler/both kinds).

        RETURNS: a dict (single call) or list of dicts (batch), each with kind, addr,
        message (on success) or error (on failure).

        Single: pass comment + addr/name (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {
                'comment': comment,
                'kind': kind,
                'addr': addr,
                'name': name,
                'line': line,
            },
            kind='dict',
        )
        token = _current_mcp_context.set(ctx)
        try:
            return unwrap(await modify.set_comments(self._backend, items), single)
        finally:
            _current_mcp_context.reset(token)

    async def get_comment(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {addr?, name?}. For one, omit items and pass addr/name.'
                ),
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(default=None, description='Single: address (hex).')
        ] = None,
        name: Annotated[
            str | None, Field(default=None, description='Single: function name.')
        ] = None,
    ) -> Any:
        """Get function plate comment(s).

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - name: function name
        - addr: function entry point address
        - comment: plate comment text (may be empty string)
        - error: null on success, error message on failure

        Single: pass addr/name (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {'addr': addr, 'name': name},
            kind='dict',
            empty_hint='list(entry_type="function")',
        )
        return unwrap(await modify.get_comment(self._backend, items), single)

    async def set_prototype(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {addr, prototype}. For one, omit items and pass addr + prototype.'
                ),
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None,
            Field(default=None, description='Single: function address (hex).'),
        ] = None,
        prototype: Annotated[
            str | None,
            Field(
                default=None, description='Single: C signature, e.g. "int f(int a)".'
            ),
        ] = None,
        ctx: Context = None,  # type: ignore[assignment]
    ) -> Any:
        """Set function prototype(s). THIS MODIFIES THE GHIDRA DATABASE.

        The old signature is saved in the function comment for reference.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: function address
        - name: function name
        - error: null on success, error message on failure

        Single: pass addr + prototype (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items, {'addr': addr, 'prototype': prototype}, kind='dict'
        )
        token = _current_mcp_context.set(ctx)
        try:
            return unwrap(await modify.set_prototype(self._backend, items), single)
        finally:
            _current_mcp_context.reset(token)

    async def patch(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {addr, hex_bytes}. For one, omit items and pass addr + hex_bytes.'
                ),
            ),
        ] = None,
        *,
        addr: Annotated[
            str | None, Field(default=None, description='Single: address (hex).')
        ] = None,
        hex_bytes: Annotated[
            str | None,
            Field(default=None, description='Single: new bytes as hex, e.g. "90".'),
        ] = None,
    ) -> Any:
        """Overwrite bytes at address(es). THIS MODIFIES THE GHIDRA DATABASE.

        BEHAVIOR: Clears existing code unit, writes bytes, re-disassembles.

        RETURNS: a dict (single call) or list of dicts (batch), each with:
        - addr: patched address
        - error: null on success, error message on failure

        Single: pass addr + hex_bytes (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items, {'addr': addr, 'hex_bytes': hex_bytes}, kind='dict'
        )
        return unwrap(await modify.patch(self._backend, items), single)

    async def begin_trans(
        self,
        description: Annotated[
            str, Field(description='Human-readable transaction description')
        ],
    ) -> Any:
        """Start a manual transaction for multiple modifications.

        RETURNS: Dict with keys: transaction_id (int), message (str), error (null or str).
        Use transaction_id with end_trans to commit or rollback.

        WHEN TO USE:
        - Most modification tools handle transactions internally
        - Only use manual transactions when making MULTIPLE modifications that should be atomic

        EXAMPLE:
          tx = begin_trans("Rename related functions")
          rename(...)
          end_trans(tx['transaction_id'], commit=True)"""
        return await modify.begin_trans(self._backend, description)

    async def end_trans(
        self,
        transaction_id: Annotated[
            str, Field(description='Transaction ID returned by begin_trans')
        ],
        commit: Annotated[
            bool, Field(description='True to commit changes, False to rollback')
        ] = True,
    ) -> Any:
        """End a manual transaction started with begin_trans.

        PARAMETERS:
        - transaction_id: ID returned in begin_trans result dict
        - commit: True to save changes, False to discard/rollback

        RETURNS: Dict with keys: transaction_id (int), committed (bool),
        message (str), error (null on success, str on failure)."""
        return await modify.end_trans(self._backend, int(transaction_id), commit)

    # --- Type tools ---

    async def type_info(
        self,
        items: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of type names. For one, omit items and pass type_name.'
                ),
            ),
        ] = None,
        *,
        type_name: Annotated[
            str | None,
            Field(default=None, description='Single: type name or full path.'),
        ] = None,
    ) -> Any:
        """Detailed type info.

        RETURNS: a dict (single call) or list of dicts (batch), each with TypeDetails fields
        (on success) or {target, error} on failure.

        Single: pass type_name (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {'type_name': type_name},
            kind='scalar',
            empty_hint='list(entry_type="type")',
        )
        return unwrap(await type_tools.type_info(self._backend, items), single)

    async def create_struct(
        self,
        name: Annotated[str, Field(description="Structure name (e.g., 'request_t')")],
        size: Annotated[
            int,
            Field(description='Total size in bytes. 0 = auto-size from fields', ge=0),
        ] = 0,
        fields: Annotated[
            list[dict] | None,
            Field(
                description=(
                    'Optional initial fields: [{name, type, offset, comment?}]'
                )
            ),
        ] = None,
        packed: Annotated[
            bool, Field(description='If True, no padding between fields')
        ] = False,
    ) -> Any:
        """Create a new structure type in the Ghidra type database.

        RETURNS: StructureCreationResult with name, size, created flag, and message.

        EXAMPLE:
          create_struct(
              name="NetworkPacket",
              fields=[
                  {"name": "header_ptr", "type": "void *", "offset": 0},
                  {"name": "length", "type": "int", "offset": 8},
              ]
          )"""
        return await type_tools.create_struct(
            self._backend,
            name=name,
            size=size,
            fields=fields,
            packed=packed,
        )

    async def add_field(
        self,
        items: Annotated[
            list[dict] | None,
            Field(
                default=None,
                description=(
                    'Batch: list of {struct_name, field_name, field_type, offset, comment?}. For one, omit items.'
                ),
            ),
        ] = None,
        *,
        struct_name: Annotated[
            str | None, Field(default=None, description='Single: structure name.')
        ] = None,
        field_name: Annotated[
            str | None, Field(default=None, description='Single: field name.')
        ] = None,
        field_type: Annotated[
            str | None, Field(default=None, description='Single: field type.')
        ] = None,
        offset: Annotated[
            int | None, Field(default=None, description='Single: field offset.')
        ] = None,
        comment: Annotated[
            str | None, Field(default=None, description='Single: optional comment.')
        ] = None,
    ) -> Any:
        """Add field(s) to struct(s). THIS MODIFIES THE GHIDRA DATABASE.

        If a field already exists at the specified offset, it will be replaced.
        If the structure is not large enough, it will be expanded automatically.

        RETURNS: a dict (single call) or list of dicts (batch) with FieldAdditionResult fields.

        Single: pass struct_name/field_name/field_type/offset (returns one dict). Batch: pass items=[…] (returns a list)."""
        items, single = single_or_batch(
            items,
            {
                'struct_name': struct_name,
                'field_name': field_name,
                'field_type': field_type,
                'offset': offset,
                'comment': comment,
            },
            kind='dict',
        )
        return unwrap(await type_tools.add_field(self._backend, items), single)

    # --- Scripting tools ---

    async def pyghidra_eval(
        self,
        code: Annotated[
            str,
            Field(
                description=(
                    'Python code to execute in Ghidra context. '
                    'Has access to: currentProgram, flat_api, backend, ghidra.*, java.* '
                    'Jupyter-style: last expression is returned as result. '
                    'Variables persist between calls for the MCP server lifetime.'
                )
            ),
        ],
        reset: Annotated[
            bool,
            Field(
                description=(
                    'If True, clear the persistent session state before executing code. '
                    'Recreates the PyGhidraScript from the backend. '
                    'Use to start a clean session. Default: False.'
                )
            ),
        ] = False,
        # NOTE: must be plain `Context`, NOT `Context | None`. FastMCP's
        # context-param detection skips any parameter whose annotation has a
        # typing origin (Union/Optional), so `Context | None` is never injected
        # and arrives as None — silently disabling RPC callback discovery (and,
        # in the write handlers, elicitation). Plain `Context` is detected and
        # injected; the `= None` default only covers direct/test calls.
        ctx: Context = None,  # type: ignore[assignment]
    ) -> dict:
        """Execute Python code in Ghidra context with full API access.

        Returns ScriptResult with result, stdout, stderr, and interleaved output.
        Jupyter-style evaluation: the last expression value is returned as 'result'.
        Variables persist between calls for the MCP server lifetime.

        EXAMPLES:
          "currentProgram.getFunctionManager().getFunctionCount()"  -> returns count
          "for f in currentProgram.getFunctionManager().getFunctions(True): print(f.getName())"  -> stdout
          "x = 1 + 1\\nx"  -> result = "2"
          pyghidra(code='x = 42') then pyghidra(code='x') -> result='42' (persists)
          pyghidra(code='', reset=True) -> clears session state
        """
        from .tools.scripting import pyghidra_eval

        # Discover RPC callback functions on first call (cached thereafter).
        session = None
        rpc_ns: RPCNamespace | None = None
        if ctx is not None:
            try:
                session = ctx.session
                rpc_ns = await _discover_rpc_functions(session)
            except Exception as exc:
                logger.debug('RPC discovery skipped: %s', exc)

        return (
            await pyghidra_eval(
                self._backend,
                code,
                reset,
                rpc_namespace=rpc_ns,
                session=session,
            )
        ).model_dump()

    # --- Search tools ---

    async def find_bytes(
        self,
        patterns: Annotated[
            list[str],
            Field(
                description=(
                    'Byte patterns to search for. Space-separated hex tokens, ?? for wildcard. '
                    'Example: ["48 8B ?? ??", "55 48 89 E5"]'
                )
            ),
        ],
        limit: Annotated[
            int, Field(description='Max results per pattern', ge=1, le=10000)
        ] = 1000,
        offset: Annotated[int, Field(description='Skip first N results', ge=0)] = 0,
    ) -> list[dict]:
        """Search binary for byte patterns with wildcard support.

        RETURNS: list of dicts, each with:
        - pattern: the input pattern string
        - matches: list of {addr, bytes} dicts
        - has_more: True if more results exist beyond the limit
        - error: null on success, error message on failure

        EXAMPLES:
        - find_bytes(patterns=["90"]) -> find all NOP bytes
        - find_bytes(patterns=["48 8B ?? ??"]) -> find MOV r64,r/m64 variants
        - find_bytes(patterns=["55 48 89 E5"], limit=10) -> first 10 matches of function prologue"""
        from .tools.search import find_bytes

        return await find_bytes(self._backend, patterns, limit, offset)

    async def find_insns(
        self,
        sequences: Annotated[
            list[list[dict]],
            Field(
                description=(
                    'Instruction sequences to search for. Each sequence is a list of '
                    '{mnemonic, operands} patterns. Operands use glob by default, /regex/ for regex. '
                    'Example: [[{"mnemonic": "PUSH", "operands": ["RBP"]}, '
                    '{"mnemonic": "MOV", "operands": ["RBP", "RSP"]}]]'
                )
            ),
        ],
        limit: Annotated[
            int, Field(description='Max results per sequence', ge=1, le=10000)
        ] = 1000,
        offset: Annotated[int, Field(description='Skip first N results', ge=0)] = 0,
    ) -> list[dict]:
        """Search for consecutive instruction sequences matching patterns.

        RETURNS: list of dicts, each with:
        - sequence: the input sequence patterns
        - matches: list of {addr, instructions} dicts
        - has_more: True if more results exist beyond the limit
        - error: null on success, error message on failure

        EXAMPLES:
        - find_insns(sequences=[[{"mnemonic": "PUSH", "operands": ["RBP"]}]]) -> find all PUSH RBP
        - find_insns(sequences=[[{"mnemonic": "PUSH"}, {"mnemonic": "MOV"}]]) -> PUSH followed by MOV
        - find_insns(sequences=[[{"mnemonic": "CALL", "operands": ["/*malloc*/"]}}]]) -> CALL with regex operand"""
        from .tools.search import find_insns

        return await find_insns(self._backend, sequences, limit, offset)

    # --- CFG tools ---

    async def cfg(
        self,
        address: Annotated[str, Field(description='Function address (hex) or name')],
        normalize: Annotated[
            bool, Field(description='Apply cross-tool normalization')
        ] = True,
        include_bytes: Annotated[
            bool, Field(description='Include base64 raw bytes per block')
        ] = False,
        include_disassembly: Annotated[
            bool, Field(description='Include instruction list per block')
        ] = False,
    ) -> dict:
        """Extract control flow graph for a function. Returns basic blocks with successors, called functions, and strings."""
        from mcpyghidra.tools.cfg import cfg as cfg_impl

        result = await cfg_impl(
            self._backend, address, normalize, include_bytes, include_disassembly
        )
        return result.model_dump(by_alias=True)

    async def callgraph(
        self,
        address: Annotated[
            str, Field(description='Root function address (hex) or name')
        ],
        direction: Annotated[
            str, Field(description="'callees', 'callers', or 'both'")
        ] = 'callees',
        max_depth: Annotated[int, Field(description='Maximum traversal depth')] = 5,
        max_nodes: Annotated[int, Field(description='Maximum function nodes')] = 1000,
        max_edges: Annotated[int, Field(description='Maximum call edges')] = 5000,
    ) -> dict:
        """Build call graph from a root function. Traverses call relationships with configurable depth and limits."""
        from mcpyghidra.tools.cfg import callgraph as callgraph_impl

        result = await callgraph_impl(
            self._backend, address, direction, max_depth, max_nodes, max_edges
        )
        return result.model_dump(by_alias=True)

    # --- GUI-only tools ---

    async def open_program(
        self,
        path_or_name: Annotated[
            str,
            Field(
                description=(
                    'File path on disk (imports into project then opens) or name of an '
                    'existing project binary (opens in a new CodeBrowser window).'
                )
            ),
        ],
        wait: Annotated[
            bool,
            Field(
                description=(
                    'If True (default), block until the new MCP server port is registered '
                    'or until *timeout* seconds elapse. '
                    'If False, return immediately after opening.'
                )
            ),
        ] = True,
        timeout: Annotated[
            int,
            Field(
                description=(
                    'Maximum seconds to wait for the new MCP server to start '
                    '(only used when wait=True). Default: 300.'
                ),
                ge=1,
            ),
        ] = 300,
    ) -> dict:
        """Open a binary in Ghidra. Imports from disk if needed, opens in a new CodeBrowser with its own MCP server.

        Only available in GUI mode. Returns new server connection info so the client can connect to the dedicated server for that binary.

        RETURNS: dict with:
        - status: "ready" | "analyzing" | "timeout"
        - binary: name of the opened binary
        - architecture: processor/endian/bitness string, or null
        - new_server: {host, port} for the new MCP server, or null
        - analysis_status: "complete" | "analyzing" | "unknown"
        - message: human-readable summary

        EXAMPLES:
        - open_program(path_or_name="/tmp/firmware.bin") -> imports and opens, waits for analysis
        - open_program(path_or_name="crackme.elf") -> opens existing project binary
        - open_program(path_or_name="/tmp/large.bin", wait=False) -> returns immediately"""
        from mcpyghidra.tools.open_program import open_program as open_program_impl

        return await open_program_impl(self._backend, path_or_name, wait, timeout)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_tools(mcp: FastMCP, backend: 'GhidraBackend') -> None:
    """Register all MCP tools by instantiating McpToolRegistration.

    Checks MCPY_DISABLE_READONLY_TOOLS environment variable: if set to '1' or
    'true', read-only (readOnlyHint) tools are not registered. Useful for
    write-only sessions.
    """
    disable_readonly = os.environ.get('MCPY_DISABLE_READONLY_TOOLS', '').lower() in (
        '1',
        'true',
    )

    registration = McpToolRegistration(backend)

    for (
        method_name,
        tool_name,
        annotations_dict,
        is_readonly,
    ) in registration.iter_tools():
        if is_readonly and disable_readonly:
            continue
        method = getattr(registration, method_name)
        # FastMCP accepts a dict for `annotations` at runtime even though
        # the type is ToolAnnotations | None; the dict is normalized
        # internally. Suppress the strict-type mismatch here.
        mcp.tool(tool_name, annotations=annotations_dict)(method)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# MCP instructions builder
# ---------------------------------------------------------------------------


def build_instructions(backend: 'GhidraBackend | None') -> str:
    """Build the MCP instructions string injected into the LLM system prompt.

    Called at server startup from create_mcp_app(). Kept under 2 KB
    (Claude Code limit).

    Args:
        backend: Active backend (PluginBackend or HeadlessBackend), or None
                 if called before a backend exists (rare, defensive only).
    """
    tool_line = 'MCPyGhidra MCP Server'
    try:
        from ghidra.framework import Application

        version = str(Application.getApplicationVersion())
        tool_line = f'MCPyGhidra (Ghidra {version})'
    except Exception:
        try:
            import pyghidra

            version = str(getattr(pyghidra, '__version__', 'unknown'))
            tool_line = f'MCPyGhidra (pyghidra {version})'
        except Exception:
            pass

    if backend is None:
        mode = 'unknown'
        binary_line = 'Binary: none'
        arch_line = 'Architecture: N/A'
    else:
        mode = 'headless' if backend.is_headless else 'gui'
        try:
            prog = backend.program
            binary_name = prog.getName()
            binary_path = str(prog.getExecutablePath())
            binary_line = f'Binary: {binary_name} ({binary_path})'
            lang = prog.getLanguage()
            arch_line = f'Architecture: {lang.getLanguageID()}'
        except Exception:
            binary_line = 'Binary: unknown'
            arch_line = 'Architecture: unknown'

    tools = (
        'list, cursor, context, funcs, decompile, disasm, symbols, xrefs, '
        'rename, update_vars, set_comments, get_comment, set_prototype, patch, '
        'begin_trans, end_trans, type_info, create_struct, add_field, '
        'pyghidra, find_bytes, find_insns, cfg, callgraph'
    )
    if backend is not None and not backend.is_headless:
        tools += ', open_program'

    lines = [
        tool_line,
        f'Mode: {mode}',
        binary_line,
        arch_line,
        'Port: see server://info',
        '',
        f'Available tools: {tools}',
        '',
        'Workflow: Use cfg/callgraph for control flow. Use decompile for C pseudocode.',
        'Check server://info for live server state including port.',
    ]
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Project binaries helper
# ---------------------------------------------------------------------------


def _collect_binaries(
    folder: Any,
    binaries: list[dict[str, Any]],
    open_programs: set[str],
    port_manager: Any,
) -> None:
    """Recursively collect domain files from a Ghidra project folder.

    Appends one dict per binary to *binaries*.  Detects whether a program is
    currently open and whether it has an active MCP server port.

    Args:
        folder: A Ghidra ``DomainFolder`` instance.
        binaries: Accumulator list — entries are appended in place.
        open_programs: Set of domain-file pathnames that are currently open.
        port_manager: ``MCPPortManager`` instance or ``None``.
    """
    folder_path = str(folder.getPathname())

    for file in folder.getFiles():
        file_path = str(file.getPathname())
        file_name = str(file.getName())
        is_open = file_path in open_programs

        mcp_port = None
        has_mcp = False
        if port_manager is not None and hasattr(port_manager, '_program_path_to_port'):
            port = port_manager._program_path_to_port.get(file_path)
            if port is not None:
                has_mcp = True
                mcp_port = port

        binaries.append({
            'name': file_name,
            'path': file_path,
            'folder': folder_path,
            'is_open': is_open,
            'has_mcp_server': has_mcp,
            'mcp_port': mcp_port,
        })

    for subfolder in folder.getFolders():
        _collect_binaries(subfolder, binaries, open_programs, port_manager)


# ---------------------------------------------------------------------------
# Resource registration
# ---------------------------------------------------------------------------


def register_resources(
    mcp: FastMCP,
    backend: 'GhidraBackend',
    get_port: 'typing.Callable[[], int | None] | None' = None,
) -> None:
    """Register all MCP resources.

    Resources expose the same data as tools but are accessible via URI.
    They call the same tool functions in tools/. Resources are always
    registered regardless of MCPY_DISABLE_READONLY_TOOLS.

    Args:
        mcp: The FastMCP instance to register resources on.
        backend: Active GhidraBackend (PluginBackend or HeadlessBackend).
        get_port: Optional callable that returns the current server port.
                  Called at request time so the port is always up-to-date.
                  Supports both headless (port_container[0]) and GUI
                  (lambda: self.port) patterns.
    """

    # Helper: register a resource, handling older mcp versions that don't
    # support the 'annotations' kwarg.
    def _register(
        uri: str,
        fn: Any,
        *,
        name: str,
        description: str,
        mime_type: str = 'application/json',
        ann: dict[str, Any] | None = None,
    ) -> None:
        uri_params = set(__import__('re').findall(r'\{(\w+)\}', uri))
        wrapped = _make_resource_wrapper(fn, uri_params)
        resource_kwargs: dict[str, Any] = {
            'name': name,
            'description': description,
            'mime_type': mime_type,
        }
        if ann is not None:
            from mcp.types import Annotations

            mcp_ann = Annotations(**ann)
            try:
                mcp.resource(uri, **resource_kwargs, annotations=mcp_ann)(wrapped)
                return
            except TypeError:
                pass  # older mcp version — fall through without annotations
        mcp.resource(uri, **resource_kwargs)(wrapped)

    # --- Server info ---

    def _res_server_info() -> Any:
        try:
            prog = backend.program
            binary_name = str(prog.getName())
            binary_path = str(prog.getExecutablePath())
            lang = prog.getLanguage()
            arch = str(lang.getLanguageID())
            analysis_status = 'complete'
        except Exception:
            binary_name = None
            binary_path = None
            arch = None
            analysis_status = 'no_binary'

        try:
            from ghidra.framework import Application

            version = str(Application.getApplicationVersion())
        except Exception:
            try:
                import pyghidra as _pyghidra

                version = str(getattr(_pyghidra, '__version__', 'unknown'))
            except Exception:
                version = 'unknown'

        mode = 'headless' if backend.is_headless else 'gui'
        port = get_port() if get_port is not None else None

        return {
            'tool': 'ghidra',
            'version': version,
            'mode': mode,
            'binary': binary_name,
            'binary_path': binary_path,
            'architecture': arch,
            'analysis_status': analysis_status,
            'port': port,
        }

    _register(
        'server://info',
        _res_server_info,
        name='server_info',
        description='Live server metadata: tool, version, mode, binary, architecture, port',
        ann={'audience': ['assistant'], 'priority': 1.0},
    )

    # --- Project binaries (GUI mode only) ---

    def _res_project_binaries() -> Any:
        if backend is None or backend.is_headless:
            return json.dumps({'project_name': None, 'binaries': []})

        try:
            from ghidra.app.services import ProgramManager
            from mcpyghidra.mcpserver import MCPPortManager

            tool = backend._tool  # type: ignore[attr-defined]  # PluginBackend
            project = tool.getProject()
            if project is None:
                return json.dumps({'project_name': None, 'binaries': []})
            project_name = str(project.getName())

            # Collect open program paths from ProgramManager
            open_programs: set[str] = set()
            pm = tool.getService(ProgramManager.class_)
            if pm is not None:
                for prog in pm.getAllOpenPrograms():
                    open_programs.add(str(prog.getDomainFile().getPathname()))

            # Access port manager singleton
            port_manager = MCPPortManager._instance

            # Recurse through project folders
            binaries: list[dict[str, Any]] = []
            root_folder = project.getProjectData().getRootFolder()
            _collect_binaries(root_folder, binaries, open_programs, port_manager)

            return json.dumps(
                {
                    'project_name': project_name,
                    'binaries': binaries,
                },
                indent=2,
            )
        except Exception as e:
            return json.dumps({'project_name': None, 'binaries': [], 'error': str(e)})

    _register(
        'project://binaries',
        _res_project_binaries,
        name='project_binaries',
        description='Binaries imported into the Ghidra project (GUI mode only)',
        ann={'audience': ['assistant'], 'priority': 0.8},
    )

    # --- Cursor (dual: tool + resource) ---

    def _res_cursor() -> Any:
        return core.cursor(backend)

    _register(
        'ghidra://cursor',
        _res_cursor,
        name='cursor',
        description='Current cursor position and function info',
        ann={'audience': ['assistant'], 'priority': 1.0},
    )

    # --- Program metadata (dual: tool + resource) ---

    def _res_program_metadata() -> Any:
        return core.context(backend)

    _register(
        'ghidra://program/metadata',
        _res_program_metadata,
        name='program_metadata',
        description='Binary file info, architecture, base address, hashes',
        ann={'audience': ['assistant'], 'priority': 1.0},
    )

    # --- Paginated list resources ---

    def _res_functions(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='function', offset=offset, limit=limit
        )

    _register(
        'ghidra://functions/{offset}/{limit}',
        _res_functions,
        name='functions',
        description='Paginated list of functions',
    )

    def _res_segments(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='memory_segment', offset=offset, limit=limit
        )

    _register(
        'ghidra://program/segments/{offset}/{limit}',
        _res_segments,
        name='segments',
        description='Memory segments with permissions',
    )

    def _res_imports(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='import', offset=offset, limit=limit
        )

    _register(
        'ghidra://imports/{offset}/{limit}',
        _res_imports,
        name='imports',
        description='Imported functions and data',
    )

    def _res_exports(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='export', offset=offset, limit=limit
        )

    _register(
        'ghidra://exports/{offset}/{limit}',
        _res_exports,
        name='exports',
        description='Exported symbols',
    )

    def _res_strings(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='string', offset=offset, limit=limit
        )

    _register(
        'ghidra://strings/{offset}/{limit}',
        _res_strings,
        name='strings',
        description='String literals found in binary',
    )

    def _res_classes(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='class', offset=offset, limit=limit
        )

    _register(
        'ghidra://classes/{offset}/{limit}',
        _res_classes,
        name='classes',
        description='C++ classes',
    )

    def _res_namespaces(offset: int = 0, limit: int = 500) -> Any:
        return core.list_entries(
            backend, entry_type='namespace', offset=offset, limit=limit
        )

    _register(
        'ghidra://namespaces/{offset}/{limit}',
        _res_namespaces,
        name='namespaces',
        description='C++ namespaces',
    )

    # --- Search resources ---

    def _res_search_functions(pattern: str) -> Any:
        return core.list_entries(
            backend, entry_type='function', offset=0, limit=500, match_filter=pattern
        )

    _register(
        'ghidra://search/functions/{pattern}',
        _res_search_functions,
        name='search_functions',
        description='Search functions by name substring',
    )

    def _res_search_strings(pattern: str) -> Any:
        return core.list_entries(
            backend, entry_type='string', offset=0, limit=500, match_filter=pattern
        )

    _register(
        'ghidra://search/strings/{pattern}',
        _res_search_strings,
        name='search_strings',
        description='Search strings by content substring',
    )

    # --- Program entry points ---

    def _res_entrypoints() -> Any:
        entries: list[dict[str, Any]] = []
        try:
            program = backend.program
            sym_table = program.getSymbolTable()
            for addr in sym_table.getExternalEntryPointIterator():
                sym = sym_table.getPrimarySymbol(addr)
                entries.append({
                    'addr': f'{addr.offset:#x}',
                    'name': sym.getName() if sym else f'entry_{addr.offset:#x}',
                })
        except Exception:
            pass
        return entries

    _register(
        'ghidra://program/entrypoints',
        _res_entrypoints,
        name='entrypoints',
        description='Program entry points',
    )

    # --- Current selection ---

    def _res_selection() -> Any:
        try:
            # Selection is only available via CodeViewerService (GUI mode).
            # In headless mode return a not-available sentinel.
            tool = getattr(backend, '_tool', None)
            if tool is None:
                return {'selected': False, 'reason': 'headless mode'}
            from ghidra.app.services import CodeViewerService

            svc = tool.getService(CodeViewerService.class_)
            if svc is None:
                return {'selected': False}
            selection = svc.getCurrentSelection()
            if selection is None or selection.isEmpty():
                return {'selected': False}
            return {
                'selected': True,
                'start': str(selection.getMinAddress()),
                'end': str(selection.getMaxAddress()),
                'size': selection.getNumAddresses(),
            }
        except Exception:
            return {'selected': False}

    _register(
        'ghidra://selection',
        _res_selection,
        name='selection',
        description='Current selection range in Ghidra',
    )

    # --- Disasm at address (N instructions) ---

    async def _res_disasm(addr: str, count: int = 10) -> Any:
        # analysis.disasm is async — must await; the previous sync version
        # silently returned a coroutine and raised TypeError on subscript.
        results = await analysis.disasm(backend, [{'addr': addr, 'count': count}])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r.get('asm', '')

    _register(
        'ghidra://disasm/{addr}/{count}',
        _res_disasm,
        name='disasm',
        description='Disassembly starting at address for count instructions',
        mime_type='text/plain',
    )

    # --- Bytes at address ---

    def _res_bytes(addr: str, size: int = 16) -> Any:
        """Read raw bytes from memory at addr, return as hex string."""
        try:
            ea = backend.program.getAddressFactory().getAddress(addr)
            mem = backend.program.getMemory()
            buf = bytearray(size)
            n_read = mem.getBytes(ea, buf)
            return buf[:n_read].hex()
        except Exception as e:
            raise ToolError(f'Failed to read bytes at {addr}: {e}')

    _register(
        'ghidra://bytes/{addr}/{size}',
        _res_bytes,
        name='bytes',
        description='Raw bytes at address as hex string',
        mime_type='text/plain',
    )

    # --- Xrefs to function by name or address ---

    async def _res_xrefs_to_func(identifier: str) -> Any:
        results = await analysis.xrefs(
            backend,
            [{'target': identifier, 'direction': 'to', 'offset': 0, 'limit': 500}],
        )
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r.get('refs')

    _register(
        'ghidra://xrefs/to-func/{identifier}',
        _res_xrefs_to_func,
        name='xrefs_to_func',
        description='Cross-references to function by name or address',
    )

    # --- Types (paginated) ---

    def _res_types(offset: int = 0, limit: int = 500) -> Any:
        from mcpyghidra.tools.types import list_types_result

        return list_types_result(backend, offset, limit, '')

    _register(
        'ghidra://types/{offset}/{limit}',
        _res_types,
        name='types',
        description='Paginated list of all types (structs, enums, typedefs)',
    )

    # --- Type info by name ---

    async def _res_type_info(type_name: str) -> Any:
        results = await type_tools.type_info(backend, [type_name])
        r = results[0]
        if r.get('error') is not None:
            raise ToolError(r['error'])
        return r

    _register(
        'ghidra://type/{type_name}',
        _res_type_info,
        name='type_info',
        description='Detailed type info (members, values, etc.)',
    )


# ---------------------------------------------------------------------------
# Capability declaration
# ---------------------------------------------------------------------------


def _declare_rpc_capability(mcp: FastMCP) -> None:
    """Patch the low-level MCP server to advertise mcpy/rpcCallbacks capability.

    FastMCP calls ``_mcp_server.create_initialization_options()`` internally
    each time it starts a new transport session.  We wrap that method to inject
    ``mcpy/rpcCallbacks: {}`` into the ``experimental_capabilities`` dict so
    that every client handshake includes the capability declaration.

    Args:
        mcp: The FastMCP instance created in create_mcp_app().
    """
    low_level = mcp._mcp_server
    original = low_level.create_initialization_options

    @functools.wraps(original)
    def _patched(notification_options=None, experimental_capabilities=None):
        caps = dict(experimental_capabilities) if experimental_capabilities else {}
        caps.setdefault('mcpy/rpcCallbacks', {})
        return original(
            notification_options=notification_options,
            experimental_capabilities=caps,
        )

    low_level.create_initialization_options = _patched  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_mcp_app(
    backend: 'GhidraBackend',
    name: str = 'ghidra-mcp',
    get_port: 'typing.Callable[[], int | None] | None' = None,
) -> tuple[FastAPI, FastMCP]:
    """Create FastAPI + FastMCP app with all tools and resources registered.

    Args:
        backend: The GhidraBackend instance (PluginBackend or HeadlessBackend).
        name: MCP server name exposed to clients (default 'ghidra-mcp').
        get_port: Optional callable that returns the current server port at
                  request time.  Passed through to register_resources() so
                  that the server://info resource can report the live port.
                  Callers provide this after binding the socket, e.g.:
                    - headless: ``lambda: port_container[0]``
                    - GUI: ``lambda: self.port``

    Returns:
        (app, mcp) tuple where app is the FastAPI ASGI app and mcp is the
        FastMCP instance.  The caller is responsible for serving app with
        uvicorn or similar.
    """
    instructions = build_instructions(backend)
    mcp = FastMCP(name, instructions=instructions)
    _declare_rpc_capability(mcp)

    @asynccontextmanager
    async def parent_lifespan(app: FastAPI) -> Any:  # type: ignore[misc]
        mcp_app = mcp.streamable_http_app()
        async with LifespanManager(mcp_app):
            yield

    app = FastAPI(title='Ghidra MCP', lifespan=parent_lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=['GET', 'POST', 'OPTIONS'],
        allow_headers=['*'],
        expose_headers=['*'],
        max_age=600,
    )

    # Resources are always registered (not affected by MCPY_DISABLE_READONLY_TOOLS)
    register_resources(mcp, backend, get_port=get_port)

    # Tools are conditionally registered
    register_tools(mcp, backend)

    mcp_app = mcp.streamable_http_app()
    app.mount('/', mcp_app)

    return app, mcp
