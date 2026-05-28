"""Unit tests for defensive / error branches in tools/scripting.py.

These tests run without Ghidra/pyghidra by mocking GhidraBackend and all
Java-type dependencies.  Each test targets exactly ONE branch.

Coverage goal: tools/scripting.py from 60% line / 3% branch → 90%+ line / ~95% branch.
"""
from __future__ import annotations

import ast
import sys
import types as _types
from unittest.mock import MagicMock, patch

import anyio

from tests.unit.conftest import patched_mcpyghidra_server


# ---------------------------------------------------------------------------
# Stub out every module imported lazily inside scripting.py
# ---------------------------------------------------------------------------

_SCRIPTING_STUBS = [
    'pyghidra',
    'pyghidra.script',
    'ghidra',
    'ghidra.app',
    'ghidra.app.script',
    'ghidra.program',
    'ghidra.program.util',
    'ghidra.util',
    'ghidra.util.task',
    'java',
    'java.io',
    'java.lang',
]
for _mod in _SCRIPTING_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# mcpyghidra.server is imported inside _pyghidra_eval_sync; stub it via
# patch.dict inside each test that calls _pyghidra_eval_sync (see usages of
# _mock_server below).  We do NOT install it at module-load time so that the
# real mcpyghidra.server is never permanently replaced in sys.modules.
_mock_server = _types.ModuleType('mcpyghidra.server')
_mock_server._script_executing = False
_mock_server._rpc_update_deferred = False
_mock_server._rpc_functions_discovered = True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_backend() -> MagicMock:
    backend = MagicMock()
    backend.program = MagicMock()
    backend.flat_api = MagicMock()
    return backend


def _run_async(async_fn, *args, **kwargs):
    """Run an async function synchronously for unit tests (same pattern as test_core_branches)."""

    async def wrapper():
        return await async_fn(*args, **kwargs)

    return anyio.run(wrapper)


# ---------------------------------------------------------------------------
# _TeeStream — write() and flush() branches
# ---------------------------------------------------------------------------


class TestTeeStream:
    """_TeeStream forwards writes to both target and shared buffers."""

    def test_write_returns_length(self):
        """write(s) returns len(s) and writes to both buffers."""
        import io
        from mcpyghidra.tools.scripting import _TeeStream

        target = io.StringIO()
        shared = io.StringIO()
        tee = _TeeStream(target, shared)

        n = tee.write('hello')
        assert n == 5
        assert target.getvalue() == 'hello'
        assert shared.getvalue() == 'hello'

    def test_write_empty_string(self):
        """write('') returns 0 and both buffers stay empty."""
        import io
        from mcpyghidra.tools.scripting import _TeeStream

        target = io.StringIO()
        shared = io.StringIO()
        tee = _TeeStream(target, shared)

        n = tee.write('')
        assert n == 0

    def test_flush_does_not_raise(self):
        """flush() is callable and propagates to both streams without error."""
        import io
        from mcpyghidra.tools.scripting import _TeeStream

        target = io.StringIO()
        shared = io.StringIO()
        tee = _TeeStream(target, shared)
        tee.write('data')
        tee.flush()  # no exception = pass


# ---------------------------------------------------------------------------
# _eval_ast — empty body branch
# ---------------------------------------------------------------------------


class TestEvalAstEmptyBody:
    """_eval_ast returns None immediately when tree.body is empty."""

    def test_empty_tree_returns_none(self):
        """An empty AST module (e.g., parsed from whitespace) → None."""
        from mcpyghidra.tools.scripting import _eval_ast

        tree = ast.parse('   ')  # whitespace only → empty body
        result = _eval_ast(tree, '   ', {})
        assert result is None

    def test_single_expression_evals_directly(self):
        """Single Expr node uses eval() path (not exec+eval split)."""
        from mcpyghidra.tools.scripting import _eval_ast

        code = '1 + 1'
        tree = ast.parse(code)
        assert len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr)
        result = _eval_ast(tree, code, {})
        assert result == 2

    def test_multi_stmt_last_is_expr_evals_last(self):
        """Multiple statements, last is Expr → exec rest, eval last."""
        from mcpyghidra.tools.scripting import _eval_ast

        code = 'x = 10\nx + 5'
        tree = ast.parse(code)
        g: dict = {}
        result = _eval_ast(tree, code, g)
        assert result == 15

    def test_multi_stmt_single_non_expr_last_uses_exec_path(self):
        """Single non-Expr statement (assignment) → exec path, returns new var."""
        from mcpyghidra.tools.scripting import _eval_ast

        code = 'y = 99'
        tree = ast.parse(code)
        g: dict = {}
        result = _eval_ast(tree, code, g)
        # 'y' is a new key; _eval_ast returns its value
        assert result == 99

    def test_all_stmts_returns_result_key_if_present(self):
        """When exec sets 'result' in globals, that value is returned."""
        from mcpyghidra.tools.scripting import _eval_ast

        code = 'a = 1\nresult = 42'
        tree = ast.parse(code)
        g: dict = {}
        value = _eval_ast(tree, code, g)
        assert value == 42

    def test_all_stmts_no_new_keys_returns_none(self):
        """exec that only modifies pre-existing keys produces no new keys → None."""
        from mcpyghidra.tools.scripting import _eval_ast

        code = 'x = 7'
        tree = ast.parse(code)
        # Pre-seed 'x' AND '__builtins__' so exec adds NO new keys at all.
        g: dict = {'x': 0, '__builtins__': __builtins__}
        value = _eval_ast(tree, code, g)
        # new_keys will be empty → returns None
        assert value is None

    def test_all_stmts_last_new_key_returned_when_no_result(self):
        """When no 'result' key, last new key's value is returned."""
        from mcpyghidra.tools.scripting import _eval_ast

        code = 'a = 1\nb = 2'
        tree = ast.parse(code)
        g: dict = {}
        value = _eval_ast(tree, code, g)
        # 'b' is the last new key
        assert value == 2


# ---------------------------------------------------------------------------
# _extract_result — all three branches
# ---------------------------------------------------------------------------


class TestExtractResult:
    """_extract_result covers 'result' key, last-key fallback, and empty dict."""

    def test_result_key_returned_first(self):
        """'result' in exec_locals → that value returned regardless of order."""
        from mcpyghidra.tools.scripting import _extract_result

        d = {'a': 1, 'result': 99}
        assert _extract_result(d) == 99

    def test_last_key_returned_when_no_result(self):
        """No 'result' key and dict is non-empty → last key's value returned."""
        from mcpyghidra.tools.scripting import _extract_result

        d = {'a': 1, 'b': 2}
        # last key is 'b' (insertion order)
        assert _extract_result(d) == 2

    def test_empty_dict_returns_none(self):
        """Empty exec_locals → None."""
        from mcpyghidra.tools.scripting import _extract_result

        assert _extract_result({}) is None


# ---------------------------------------------------------------------------
# _pyghidra_eval_sync — _persistent_globals already initialised, no reset
# ---------------------------------------------------------------------------


class TestPyghidraEvalSyncPersistentGlobals:
    """_persistent_globals is reused across calls when reset=False."""

    def _run_two_calls(self, code1: str, code2: str):
        """Helper: run two eval calls using the same patched environment."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}

        _scripting._persistent_globals = None  # force first-call initialisation

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                r1 = _pyghidra_eval_sync(backend, code1, reset=False)
                r2 = _pyghidra_eval_sync(backend, code2, reset=False)
        return r1, r2

    def test_second_call_reuses_globals_without_reset(self):
        """Second call with reset=False reuses _persistent_globals (no re-init)."""
        r1, r2 = self._run_two_calls('x = 77', 'x')
        assert r1.success is True
        assert r2.success is True
        assert r2.result == '77'

    def test_reset_true_clears_then_runs(self):
        """reset=True forces re-initialisation of _persistent_globals."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fresh2: dict = {'__builtins__': __builtins__}

        _scripting._persistent_globals = {'__builtins__': __builtins__, 'old_var': 1}

        call_count = [0]
        def fake_build(b):
            call_count[0] += 1
            return fresh2

        with patch.object(_scripting, '_build_pyghidra_script', side_effect=fake_build):
            with patched_mcpyghidra_server(_mock_server):
                r = _pyghidra_eval_sync(backend, '', reset=True)

        assert r.success is True
        assert r.result == 'Session reset'
        assert call_count[0] == 1  # _build_pyghidra_script was called

    def test_empty_code_no_reset_returns_none_result(self):
        """Empty code with reset=False returns success=True and result=None."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                r = _pyghidra_eval_sync(backend, '', reset=False)

        assert r.success is True
        assert r.result is None  # no reset, just empty


# ---------------------------------------------------------------------------
# _pyghidra_eval_sync — SyntaxError fallback path
# ---------------------------------------------------------------------------


class TestPyghidraEvalSyncSyntaxError:
    """When ast.parse raises SyntaxError, exec() is called directly."""

    def test_syntax_error_falls_back_to_exec(self):
        """Deliberately invalid syntax causes exec() fallback (still fails with SyntaxError)."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        # "def f(: pass" is a SyntaxError that ast.parse raises, then exec raises too.
        # The outer except Exception catches the exec SyntaxError → success=False.
        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                r = _pyghidra_eval_sync(backend, 'def f(: pass', reset=False)

        assert r.success is False
        assert r.error is not None

    def test_syntax_error_exec_succeeds_with_valid_result(self):
        """ast.parse raises SyntaxError, but exec() succeeds and sets 'result'."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        # Patch ast.parse to raise SyntaxError for valid code to force the fallback path.
        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                with patch('mcpyghidra.tools.scripting.ast') as mock_ast:
                    mock_ast.parse.side_effect = SyntaxError('forced')
                    # _extract_result reads from the dict; preset 'result' via exec side effect
                    r = _pyghidra_eval_sync(backend, 'result = 5', reset=False)

        # exec('result = 5', fake_globals) succeeds; _extract_result sees result=5
        assert r.success is True
        assert r.result == '5'


# ---------------------------------------------------------------------------
# _pyghidra_eval_sync — rpc_namespace branches
# ---------------------------------------------------------------------------


class TestPyghidraEvalSyncRpc:
    """rpc_namespace branches: None, not available, available."""

    def _run_with_rpc(self, rpc_namespace):
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                return _pyghidra_eval_sync(
                    backend, '1+1', reset=False, rpc_namespace=rpc_namespace
                )

    def test_rpc_namespace_none_skips_rpc_injection(self):
        """rpc_namespace=None → RPC injection block is skipped entirely."""
        r = self._run_with_rpc(None)
        assert r.success is True
        assert r.result == '2'

    def test_rpc_namespace_not_available_skips_rpc_injection(self):
        """rpc_namespace.is_available() is False → RPC injection block is skipped."""
        rpc = MagicMock()
        rpc.is_available.return_value = False
        r = self._run_with_rpc(rpc)
        assert r.success is True
        assert r.result == '2'

    def test_rpc_namespace_available_injects_and_cleans_up(self):
        """rpc_namespace.is_available() True → CallbackScope created, invalidated after exec."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        rpc = MagicMock()
        rpc.is_available.return_value = True

        mock_scope = MagicMock()
        mock_rpc_globals = {'__rpc_cb__': MagicMock()}

        mock_callback_scope_cls = MagicMock(return_value=mock_scope)
        mock_build_rpc_globals = MagicMock(return_value=mock_rpc_globals)

        # Build a patched server module that exposes _build_rpc_globals
        patched_server = _types.ModuleType('mcpyghidra.server')
        patched_server._script_executing = False
        patched_server._rpc_update_deferred = False
        patched_server._rpc_functions_discovered = True
        patched_server._build_rpc_globals = mock_build_rpc_globals

        mock_rpc_callbacks_mod = MagicMock()
        mock_rpc_callbacks_mod.CallbackScope = mock_callback_scope_cls

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(patched_server), \
                 patch.dict(sys.modules, {'mcpyghidra.rpc_callbacks': mock_rpc_callbacks_mod}):
                _pyghidra_eval_sync(
                    backend, '1+1', reset=False, rpc_namespace=rpc, session=None
                )

        # The rpc branch was entered (is_available checked) and scope was invalidated.
        rpc.is_available.assert_called()
        mock_callback_scope_cls.assert_called_once()
        mock_scope.invalidate.assert_called_once()
        # All injected RPC globals must be removed after execution.
        assert '__rpc_cb__' not in fake_globals


# ---------------------------------------------------------------------------
# _pyghidra_eval_sync — _rpc_update_deferred branch
# ---------------------------------------------------------------------------


class TestRpcUpdateDeferred:
    """_srv._rpc_update_deferred=True → reset flags in finally block."""

    def test_deferred_flag_reset_in_finally(self):
        """When _rpc_update_deferred is True, both deferred flags are cleared."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        # Build a custom server mock where _rpc_update_deferred starts as True.
        deferred_server = _types.ModuleType('mcpyghidra.server')
        deferred_server._script_executing = False
        deferred_server._rpc_update_deferred = True
        deferred_server._rpc_functions_discovered = True

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(deferred_server):
                r = _pyghidra_eval_sync(backend, '1', reset=False)

        assert r.success is True
        # Both flags should have been cleared by the finally block.
        assert deferred_server._rpc_update_deferred is False
        assert deferred_server._rpc_functions_discovered is False


# ---------------------------------------------------------------------------
# _pyghidra_eval_sync — outer except Exception branch (catastrophic failure)
# ---------------------------------------------------------------------------


class TestPyghidraEvalSyncOuterException:
    """Outer except Exception catches errors from _build_pyghidra_script."""

    def test_build_script_raises_returns_failure_result(self):
        """_build_pyghidra_script raising → success=False with error and traceback."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import _pyghidra_eval_sync

        backend = _make_backend()
        _scripting._persistent_globals = None

        with patch.object(
            _scripting, '_build_pyghidra_script', side_effect=RuntimeError('Ghidra crash')
        ):
            with patched_mcpyghidra_server(_mock_server):
                r = _pyghidra_eval_sync(backend, 'x', reset=True)

        assert r.success is False
        assert 'Ghidra crash' in (r.error or '')
        assert r.error_traceback is not None


# ---------------------------------------------------------------------------
# pyghidra_eval async wrapper — smoke test
# ---------------------------------------------------------------------------


class TestPyghidraEvalAsync:
    """pyghidra_eval delegates to _pyghidra_eval_sync via anyio thread pool."""

    def test_async_wrapper_returns_script_result(self):
        """pyghidra_eval is callable and returns a ScriptResult."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import pyghidra_eval

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                result = _run_async(pyghidra_eval, backend, '2 + 2')

        assert result.success is True
        assert result.result == '4'

    def test_async_wrapper_reset_true(self):
        """pyghidra_eval with reset=True returns 'Session reset'."""
        import mcpyghidra.tools.scripting as _scripting
        from mcpyghidra.tools.scripting import pyghidra_eval

        backend = _make_backend()
        fake_globals: dict = {'__builtins__': __builtins__}
        _scripting._persistent_globals = None

        with patch.object(_scripting, '_build_pyghidra_script', return_value=fake_globals):
            with patched_mcpyghidra_server(_mock_server):
                result = _run_async(pyghidra_eval, backend, '', reset=True)

        assert result.success is True
        assert result.result == 'Session reset'


# ---------------------------------------------------------------------------
# _build_pyghidra_script — program is None branch and empty memory branch
# ---------------------------------------------------------------------------


class TestBuildPyghidraScript:
    """_build_pyghidra_script: program=None → location=None; empty mem → location=None."""

    def _make_stubs(self):
        """Return patched sub-stubs needed for _build_pyghidra_script."""
        mock_script = MagicMock()
        mock_script_cls = MagicMock(return_value=mock_script)

        mock_state_cls = MagicMock()
        mock_task_monitor = MagicMock()
        mock_task_monitor.DUMMY = MagicMock()
        mock_print_writer_cls = MagicMock()
        mock_system = MagicMock()
        mock_program_location_cls = MagicMock()

        return {
            'PyGhidraScript': mock_script_cls,
            'GhidraState': mock_state_cls,
            'ProgramLocation': mock_program_location_cls,
            'TaskMonitor': mock_task_monitor,
            'PrintWriter': mock_print_writer_cls,
            'System': mock_system,
            'mock_script': mock_script,
        }

    def test_program_none_skips_location(self):
        """backend.program is None → location stays None, GhidraState called with None."""
        from mcpyghidra.tools.scripting import _build_pyghidra_script

        stubs = self._make_stubs()
        backend = _make_backend()
        backend.program = None

        with patch.dict(sys.modules, {
            'pyghidra.script': MagicMock(PyGhidraScript=stubs['PyGhidraScript']),
            'ghidra.app.script': MagicMock(GhidraState=stubs['GhidraState']),
            'ghidra.program.util': MagicMock(ProgramLocation=stubs['ProgramLocation']),
            'ghidra.util.task': MagicMock(TaskMonitor=stubs['TaskMonitor']),
            'java.io': MagicMock(PrintWriter=stubs['PrintWriter']),
            'java.lang': MagicMock(System=stubs['System']),
        }):
            result = _build_pyghidra_script(backend)

        # GhidraState should have been called with program=None, location=None
        stubs['GhidraState'].assert_called_once()
        call_args = stubs['GhidraState'].call_args[0]
        assert call_args[2] is None   # program arg is None
        assert call_args[3] is None   # location arg is None
        # ProgramLocation should NOT have been called (program was None)
        stubs['ProgramLocation'].assert_not_called()
        # The result is the mock script instance (dict-like)
        assert result is stubs['mock_script']

    def test_empty_memory_skips_location(self):
        """program.getMemory().isEmpty() → location stays None."""
        from mcpyghidra.tools.scripting import _build_pyghidra_script

        stubs = self._make_stubs()
        backend = _make_backend()

        mock_mem = MagicMock()
        mock_mem.isEmpty.return_value = True
        backend.program.getMemory.return_value.getLoadedAndInitializedAddressSet.return_value = mock_mem

        with patch.dict(sys.modules, {
            'pyghidra.script': MagicMock(PyGhidraScript=stubs['PyGhidraScript']),
            'ghidra.app.script': MagicMock(GhidraState=stubs['GhidraState']),
            'ghidra.program.util': MagicMock(ProgramLocation=stubs['ProgramLocation']),
            'ghidra.util.task': MagicMock(TaskMonitor=stubs['TaskMonitor']),
            'java.io': MagicMock(PrintWriter=stubs['PrintWriter']),
            'java.lang': MagicMock(System=stubs['System']),
        }):
            _build_pyghidra_script(backend)

        # ProgramLocation should NOT have been called (memory was empty)
        stubs['ProgramLocation'].assert_not_called()
        stubs['GhidraState'].assert_called_once()
        call_args = stubs['GhidraState'].call_args[0]
        assert call_args[3] is None  # location is None

    def test_non_empty_memory_creates_location(self):
        """Non-empty memory → ProgramLocation created with min address."""
        from mcpyghidra.tools.scripting import _build_pyghidra_script

        stubs = self._make_stubs()
        backend = _make_backend()

        mock_min_addr = MagicMock()
        mock_mem = MagicMock()
        mock_mem.isEmpty.return_value = False
        mock_mem.getMinAddress.return_value = mock_min_addr
        backend.program.getMemory.return_value.getLoadedAndInitializedAddressSet.return_value = mock_mem

        mock_location_instance = MagicMock()
        stubs['ProgramLocation'].return_value = mock_location_instance

        with patch.dict(sys.modules, {
            'pyghidra.script': MagicMock(PyGhidraScript=stubs['PyGhidraScript']),
            'ghidra.app.script': MagicMock(GhidraState=stubs['GhidraState']),
            'ghidra.program.util': MagicMock(ProgramLocation=stubs['ProgramLocation']),
            'ghidra.util.task': MagicMock(TaskMonitor=stubs['TaskMonitor']),
            'java.io': MagicMock(PrintWriter=stubs['PrintWriter']),
            'java.lang': MagicMock(System=stubs['System']),
        }):
            _build_pyghidra_script(backend)

        # ProgramLocation WAS called (memory was non-empty)
        stubs['ProgramLocation'].assert_called_once_with(backend.program, mock_min_addr)
        stubs['GhidraState'].assert_called_once()
        call_args = stubs['GhidraState'].call_args[0]
        assert call_args[3] is mock_location_instance  # location was passed
