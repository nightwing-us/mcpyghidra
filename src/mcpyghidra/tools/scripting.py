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
import io
import sys
import threading
import traceback
from typing import TYPE_CHECKING, Any

import anyio
from mcpyghidra.models import ScriptResult

if TYPE_CHECKING:
    from mcpyghidra.backend import GhidraBackend
    from mcpyghidra.rpc_callbacks import RPCNamespace


_script_lock = threading.Lock()
_persistent_globals: dict | None = None


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
        lambda: _pyghidra_eval_sync(backend, code, reset, rpc_namespace, session)
    )


def _pyghidra_eval_sync(
    backend: 'GhidraBackend',
    code: str,
    reset: bool = False,
    rpc_namespace: 'RPCNamespace | None' = None,
    session: Any = None,
) -> ScriptResult:
    """Sync implementation — runs in thread pool."""
    global _persistent_globals

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    shared_buf = io.StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr

    try:
        sys.stdout = _TeeStream(stdout_buf, shared_buf)  # type: ignore[assignment]
        sys.stderr = _TeeStream(stderr_buf, shared_buf)  # type: ignore[assignment]

        with _script_lock:
            if reset or _persistent_globals is None:
                _persistent_globals = _build_pyghidra_script(backend)

            # Inject RPC callback globals for this execution.
            scope = None
            rpc_globals: dict[str, Any] = {}
            if rpc_namespace is not None and rpc_namespace.is_available():
                from mcpyghidra.server import _build_rpc_globals
                from mcpyghidra.rpc_callbacks import CallbackScope

                scope = CallbackScope()
                rpc_globals = _build_rpc_globals(
                    rpc_namespace, session, scope, _persistent_globals
                )
                _persistent_globals.update(rpc_globals)

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
                # and remove all injected RPC globals to prevent stale references.
                if scope is not None:
                    scope.invalidate()
                for key in rpc_globals:
                    _persistent_globals.pop(key, None)

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
