"""Script execution tool — pyghidra.

Executes Python code using the same environment as the pyghidra
interactive console. The execution context is a PyGhidraScript
instance — a dict-like object that wraps a Java GhidraScript,
providing access to currentProgram, currentAddress, monitor,
toAddr(), getFunction(), and all ~200 GhidraScript methods.

Variables persist between calls for the lifetime of the MCP server.
Use reset=True to clear state and start fresh from a new PyGhidraScript.
"""

from __future__ import annotations

import ast
import builtins
import functools
import io
import logging
import sys
import threading
import traceback
from typing import TYPE_CHECKING, Any

import anyio
from mcpyghidra.models import ScriptResult
from mcpyghidra.rpc_callbacks import ToolNamespace

if TYPE_CHECKING:
    from mcpyghidra.backend import GhidraBackend
    from mcpyghidra.rpc_callbacks import RPCNamespace


logger = logging.getLogger(__name__)

_script_lock = threading.Lock()
_persistent_globals: dict | None = None

# Real builtins __import__, captured so the script-scoped importer can defer to
# it. _active_import_roots holds the current execution's top-level namespace
# roots (set under the single-flight lock); it is None between executions, when
# the scoped importer is a transparent pass-through.
_real_import = builtins.__import__
_active_import_roots: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Script execution thread pool (isolated from the default to_thread pool)
# ---------------------------------------------------------------------------
# Scripts run on a DEDICATED CapacityLimiter so that a script which blocks
# mid-execution waiting on an in-process `mcp.self.*` tool call (see below)
# never competes for tokens with that tool's own `to_thread.run_sync` offload.
# Sharing the default 40-token pool would risk a circular wait — N blocked
# scripts each holding a token while their tool's sync core waits for one —
# under high concurrency. Separate pools make in-process self-dispatch
# deadlock-free at any concurrency.
_SCRIPT_LIMITER_TOKENS = 40
_script_limiter: anyio.CapacityLimiter | None = None


def _get_script_limiter() -> anyio.CapacityLimiter:
    global _script_limiter
    if _script_limiter is None:
        _script_limiter = anyio.CapacityLimiter(_SCRIPT_LIMITER_TOKENS)
    return _script_limiter


# ---------------------------------------------------------------------------
# mcp.self — project THIS server's own tools into the script env (in-process)
# ---------------------------------------------------------------------------
# A script can call sibling tools as `mcp.self.decompile([...])` and have them
# run IN-PROCESS rather than reverse-RPC'd back to the orchestrating client
# (which would re-enter this server mid-request and deadlock). Always injected,
# independent of any mcpy/rpcCallbacks client.

# Tools that must NOT be exposed under mcp.self:
#   pyghidra      — calling the script tool from within a script is nonsensical
#   open_program  — GUI/async-native, side-effectful program lifecycle op
_SELF_EXCLUDED_TOOLS = frozenset({'pyghidra', 'open_program'})


def _make_self_dispatch(handler: Any, display_name: str) -> Any:
    """Wrap an async tool handler as a sync, in-process callable for scripts.

    The script runs on a worker thread (gated by `_script_limiter`); the wrapper
    bridges back to the server's event loop via `anyio.from_thread.run` to run
    the handler coroutine there. The handler's own `to_thread.run_sync` offload
    draws from the DEFAULT limiter — which scripts never hold — so this cannot
    deadlock. *display_name* is the projected dotted path (e.g. ``mcp.self.list``)
    so help()/repr show that rather than a bare leaf, and the handler docstring
    is copied through so help() renders it.
    """

    def _dispatch(*args: Any, **kwargs: Any) -> Any:
        return anyio.from_thread.run(functools.partial(handler, *args, **kwargs))

    _dispatch.__name__ = display_name
    _dispatch.__qualname__ = display_name
    _dispatch.__doc__ = getattr(handler, '__doc__', None)
    return _dispatch


def _build_self_namespace(backend: 'GhidraBackend', root_label: str) -> Any:
    """Build a ToolNamespace of this server's own tools (in-process dispatch)."""
    from mcpyghidra.rpc_callbacks import ToolNamespace
    from mcpyghidra.server import McpToolRegistration

    registration = McpToolRegistration(backend)
    ns = ToolNamespace(f'{root_label}.self')
    for method_name, tool_name, _annotations, _is_readonly in registration.iter_tools():
        if tool_name in _SELF_EXCLUDED_TOOLS:
            continue
        handler = getattr(registration, method_name)
        ns._children[tool_name] = _make_self_dispatch(
            handler, f'{root_label}.self.{tool_name}'
        )
    return ns


def _install_self_namespace(
    roots: dict[str, Any],
    backend: 'GhidraBackend',
    existing_globals: dict[str, Any],
) -> None:
    """Attach `mcp.self.*` into *roots*, merging with any reverse-RPC `mcp` root.

    The top-level `mcp` global is escaped to `_mcp` if it would shadow an
    existing script global (mirrors _build_rpc_globals' shadow handling, so a
    reverse-RPC `mcp` root and this self namespace land under the same key).
    """
    from mcpyghidra.rpc_callbacks import ToolNamespace, is_name_safe

    top = 'mcp'
    if not is_name_safe(top, existing_globals):
        top = '_mcp'
        if not is_name_safe(top, existing_globals):
            logger.warning(
                "Cannot inject mcp.self: both 'mcp' and '_mcp' shadow existing globals"
            )
            return

    mcp_root = roots.get(top)
    if mcp_root is None:
        mcp_root = ToolNamespace(top)
        roots[top] = mcp_root
    elif not isinstance(mcp_root, ToolNamespace):
        logger.warning('Cannot inject mcp.self: %r is bound to a callable', top)
        return

    # `self` is ours — it wins over any reverse-RPC projection onto mcp.self.
    mcp_root._children['self'] = _build_self_namespace(backend, top)


def _rpc_import(
    name: str,
    globals: Any = None,
    locals: Any = None,
    fromlist: Any = (),
    level: int = 0,
) -> Any:
    """``__import__`` replacement for the script env: make the projected
    groupings importable like real packages.

    Resolves imports against the current execution's namespace tree — for ANY
    top-level root produced by the projection, not just ``mcp``. Whatever the
    client's ``mcpy/listFunctions`` yields drives the roots: ``foo__bar__tool``
    makes ``import foo``, ``import foo.bar``, ``from foo.bar import tool``, and
    ``from foo import bar`` all work, exactly like ``mcp.*``. Anything whose top
    segment is NOT a projected root (``json``, ``ghidra.*``, …) is deferred to
    the real importer. Installed ONLY in the script's own ``__builtins__`` and
    active only while a script runs (gated on ``_active_import_roots``), so the
    server's own ``mcp`` SDK imports — and ``sys.modules`` — are never touched.
    """
    roots = _active_import_roots
    if roots is not None and level == 0:
        # `top` is the first dotted segment of the requested import; resolution
        # is purely data-driven from `roots`, with no hard-coded prefix.
        top = name.split('.', 1)[0]
        node = roots.get(top)
        if isinstance(node, ToolNamespace):
            resolved = True
            for part in name.split('.')[1:]:
                try:
                    node = getattr(node, part)
                except AttributeError:
                    resolved = False
                    break
            if resolved:
                # `import a.b` (no fromlist) returns the top package; `from a.b
                # import x` (fromlist) returns the addressed submodule/namespace.
                return node if fromlist else roots[top]
    return _real_import(name, globals, locals, fromlist, level)


def _install_scoped_importer(script_globals: dict) -> None:
    """Route the script env's imports through ``_rpc_import`` (idempotent).

    ``__builtins__`` is normalised to a per-script dict so overriding
    ``__import__`` never touches the process-wide builtins module.

    NB: ``exec()`` resolves a frame's builtins from the C-level dict storage of
    ``globals['__builtins__']``, BYPASSING any ``__getitem__``/``__setitem__``
    overrides. pyghidra's ``PyGhidraScript`` is a dict subclass whose
    ``__setitem__`` routes keys to a Java object, so a plain
    ``globals['__builtins__'] = ...`` is invisible to ``exec`` (the frame keeps
    the real builtins module). Use ``dict.{get,__setitem__}`` to read/write the
    same underlying storage that ``exec`` reads.
    """
    b = dict.get(script_globals, '__builtins__')
    if isinstance(b, dict):
        if b.get('__import__') is not _rpc_import:
            b['__import__'] = _rpc_import
    else:
        nb = dict(vars(builtins))
        nb['__import__'] = _rpc_import
        dict.__setitem__(script_globals, '__builtins__', nb)


class _TeeStream:
    """Writes to both a target buffer and a shared interleaved buffer."""

    def __init__(self, target: io.StringIO, shared: io.StringIO) -> None:
        self._target = target
        self._shared = shared

    def write(self, s: str) -> int:
        self._target.write(s)
        self._shared.write(s)
        return len(s)

    def flush(self) -> None:
        self._target.flush()
        self._shared.flush()


async def pyghidra_eval(
    backend: 'GhidraBackend',
    code: str,
    reset: bool = False,
    rpc_namespace: 'RPCNamespace | None' = None,
    session: Any = None,
) -> ScriptResult:
    """Execute Python code in the pyghidra scripting environment.

    The execution context is identical to the pyghidra interactive console:
    - currentProgram, currentAddress, currentLocation, currentHighlight
    - monitor, state
    - toAddr(), getFunction(), getDataAt(), getBytes(), etc.
    - All ~200 GhidraScript convenience methods
    - Full access to ghidra.* Java packages via JPype

    Variables persist between calls for the MCP server lifetime.
    Use reset=True to clear state before executing code.

    If rpc_namespace is provided (and the client declared mcpy/rpcCallbacks),
    callback functions are injected into the script globals for this execution
    and the callback scope is invalidated when execution completes.

    Returns ScriptResult with result, stdout, stderr, interleaved output.
    Jupyter-style: the last expression value is returned as 'result'.
    """
    return await anyio.to_thread.run_sync(
        lambda: _pyghidra_eval_sync(backend, code, reset, rpc_namespace, session),
        limiter=_get_script_limiter(),
    )


def _pyghidra_eval_sync(
    backend: 'GhidraBackend',
    code: str,
    reset: bool = False,
    rpc_namespace: 'RPCNamespace | None' = None,
    session: Any = None,
) -> ScriptResult:
    """Sync implementation — runs in thread pool."""
    global _persistent_globals, _active_import_roots

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    shared_buf = io.StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = _TeeStream(stdout_buf, shared_buf)  # type: ignore[assignment]
        sys.stderr = _TeeStream(stderr_buf, shared_buf)  # type: ignore[assignment]

        # pyghidra is single-flight: one script at a time against the shared
        # persistent namespace. Acquire WITHOUT blocking so a re-entrant
        # invocation — a script that called a client tool which called back
        # into pyghidra — fails fast with a clear error instead of blocking on
        # the lock until the reverse-RPC callback times out (~30s) and wedging
        # pyghidra for that window. An overlapping concurrent call likewise gets
        # a retryable error rather than silently racing on shared state.
        if not _script_lock.acquire(blocking=False):
            return ScriptResult(
                result=None,
                stdout=stdout_buf.getvalue(),
                stderr=stderr_buf.getvalue(),
                output=shared_buf.getvalue(),
                success=False,
                error=(
                    'pyghidra is already executing and cannot be invoked '
                    're-entrantly or concurrently: the scripting session has a '
                    'single shared persistent namespace and runs one script at a '
                    'time. This typically happens when a script calls a client '
                    'tool (mcp.<server>.*) that calls back into pyghidra. Retry '
                    'after the current execution completes.'
                ),
            )
        try:
            if reset or _persistent_globals is None:
                _persistent_globals = _build_pyghidra_script(backend)

            # Build the per-execution global injections: reverse-RPC callbacks
            # (mcp.<other>.*, when a client declares mcpy/rpcCallbacks) plus the
            # always-on mcp.self.* namespace (this server's own tools, in-process).
            scope = None
            injected_globals: dict[str, Any] = {}
            if rpc_namespace is not None and rpc_namespace.is_available():
                from mcpyghidra.server import _build_rpc_globals
                from mcpyghidra.rpc_callbacks import CallbackScope

                scope = CallbackScope()
                injected_globals = _build_rpc_globals(
                    rpc_namespace, session, scope, _persistent_globals
                )

            # mcp.self.* is always available, merged into the same mcp root.
            # Never let a self-namespace failure abort the user's script — it is
            # an enhancement, so degrade gracefully if it can't be built.
            try:
                _install_self_namespace(injected_globals, backend, _persistent_globals)
            except Exception:
                logger.warning(
                    'Failed to build mcp.self namespace; continuing without it',
                    exc_info=True,
                )
            _persistent_globals.update(injected_globals)

            # Make the projected groupings importable (import mcp.ida1 as ida) in
            # addition to attribute access, by routing the script's imports
            # through _rpc_import for the duration of this execution. Reset in the
            # finally below.
            _install_scoped_importer(_persistent_globals)
            _active_import_roots = injected_globals

            # Mark script execution active for snapshot isolation.
            import mcpyghidra.server as _srv

            _srv._script_executing = True

            try:
                if not code.strip():
                    # Reset-only or empty code — no execution needed
                    return ScriptResult(
                        success=True,
                        result='Session reset' if reset else None,
                        stdout=stdout_buf.getvalue(),
                        stderr=stderr_buf.getvalue(),
                        output=shared_buf.getvalue(),
                    )

                result_value = None

                # AST-based Jupyter-style eval using persistent globals
                try:
                    tree = ast.parse(code)
                except SyntaxError:
                    # Fallback: direct exec
                    exec(code, _persistent_globals)
                    result_value = _extract_result(_persistent_globals)
                else:
                    result_value = _eval_ast(tree, code, _persistent_globals)

                return ScriptResult(
                    result=str(result_value) if result_value is not None else None,
                    stdout=stdout_buf.getvalue(),
                    stderr=stderr_buf.getvalue(),
                    output=shared_buf.getvalue(),
                    success=True,
                )

            finally:
                # Clear execution flag and apply any deferred function-list update.
                _srv._script_executing = False
                if _srv._rpc_update_deferred:
                    _srv._rpc_update_deferred = False
                    _srv._rpc_functions_discovered = False

                # Always invalidate the callback scope after execution completes,
                # and remove all injected globals (reverse-RPC + mcp.self) to
                # prevent stale references leaking into the persistent session.
                if scope is not None:
                    scope.invalidate()
                for key in injected_globals:
                    _persistent_globals.pop(key, None)
                # Disarm the scoped importer (transparent pass-through again).
                _active_import_roots = None
        finally:
            _script_lock.release()

    except Exception as e:
        return ScriptResult(
            result=None,
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            output=shared_buf.getvalue(),
            success=False,
            error=str(e),
            error_traceback=traceback.format_exc(),
        )
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


def _build_pyghidra_script(backend: 'GhidraBackend') -> dict:
    """Create a PyGhidraScript environment identical to the pyghidra console.

    PyGhidraScript is a dict subclass wrapping a Java GhidraScript object.
    Attribute access falls through to the Java object, providing:
    - currentProgram, currentAddress, currentLocation, currentHighlight
    - monitor, state
    - toAddr(), getFunction(), getDataAt(), etc.
    - All GhidraScript methods
    """
    from pyghidra.script import PyGhidraScript
    from ghidra.app.script import GhidraState
    from ghidra.program.util import ProgramLocation
    from ghidra.util.task import TaskMonitor
    from java.io import PrintWriter
    from java.lang import System

    program = backend.program

    # Create GhidraState with current program
    location = None
    if program is not None:
        mem = program.getMemory().getLoadedAndInitializedAddressSet()
        if not mem.isEmpty():
            location = ProgramLocation(program, mem.getMinAddress())

    state = GhidraState(None, None, program, location, None, None)

    # Create the script — this is the same globals dict the pyghidra console uses
    script = PyGhidraScript()
    script.set(
        state, TaskMonitor.DUMMY, PrintWriter(System.out), PrintWriter(System.err)
    )

    # Add our backend for convenience (not in standard pyghidra, but useful)
    script['backend'] = backend
    script['flat_api'] = backend.flat_api

    return script


def _eval_ast(tree: ast.Module, code: str, exec_globals: dict) -> object:
    """Jupyter-style AST evaluation.

    Uses exec_globals as both globals AND locals so that variables
    assigned by exec'd code are visible to subsequent statements
    and to the PyGhidraScript's __missing__ fallback.
    """
    if not tree.body:
        return None

    if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
        # Single expression — eval it
        return eval(code, exec_globals)

    if isinstance(tree.body[-1], ast.Expr):
        # Multiple statements, last is expression — exec all but last, eval last
        # len > 1 is always True here: the len==1 + Expr case is handled above at line 236.
        if len(tree.body) > 1:  # pragma: no branch
            exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
            exec(compile(exec_tree, '<pyghidra>', 'exec'), exec_globals)
        eval_tree = ast.Expression(body=tree.body[-1].value)
        return eval(compile(eval_tree, '<pyghidra>', 'eval'), exec_globals)

    # All statements — exec, return 'result' variable or last assigned
    before_keys = set(exec_globals.keys())
    exec(code, exec_globals)
    new_keys = [k for k in exec_globals if k not in before_keys]
    if 'result' in new_keys:
        return exec_globals['result']
    if new_keys:
        return exec_globals[new_keys[-1]]
    return None


def _extract_result(exec_locals: dict) -> object:
    """Extract result from executed locals."""
    if 'result' in exec_locals:
        return exec_locals['result']
    if exec_locals:
        last_key = list(exec_locals.keys())[-1]
        return exec_locals[last_key]
    return None
