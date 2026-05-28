"""Integration tests for pyghidra_eval — script execution tool.

Tests call pyghidra_eval(backend, code) directly on the HeadlessBackend.
pyghidra must be available (tests are session-scoped via conftest.py fixtures).
"""
from __future__ import annotations

import pytest

from mcpyghidra.tools.scripting import pyghidra_eval
from tests.integration.helpers import run_async


class TestPyghidraEval:
    """pyghidra_eval(backend, code) -> ScriptResult"""

    def test_simple_expression(self, backend):
        """1+1 evaluates to '2' with success=True."""
        result = run_async(pyghidra_eval, backend, '1+1')
        assert result.success is True
        assert result.result == '2'
        assert result.error is None

    def test_stdout_capture(self, backend):
        """print() output is captured in stdout and output fields."""
        result = run_async(pyghidra_eval, backend, "print('hello')")
        assert result.success is True
        assert 'hello' in result.stdout
        assert 'hello' in result.output

    def test_multiline_jupyter(self, backend):
        """Multi-line code with last expression returns that expression's value."""
        result = run_async(pyghidra_eval, backend, 'x=1\nx+1')
        assert result.success is True
        assert result.result == '2'

    def test_ghidra_api_access(self, backend):
        """currentProgram.getName() returns the loaded binary name."""
        result = run_async(pyghidra_eval, backend, 'currentProgram.getName()')
        assert result.success is True, f'Unexpected error: {result.error}'
        assert result.result is not None
        assert len(result.result) > 0

    def test_function_count(self, backend):
        """getFunctionCount() returns a number greater than 0."""
        result = run_async(pyghidra_eval,
            backend,
            'currentProgram.getFunctionManager().getFunctionCount()',
        )
        assert result.success is True, f'Unexpected error: {result.error}'
        assert result.result is not None
        count = int(result.result)
        assert count > 0, f'Expected function count > 0, got {count}'

    def test_to_addr(self, backend):
        """toAddr() GhidraScript convenience method resolves an address."""
        result = run_async(pyghidra_eval, backend, 'str(toAddr(0x401000))')
        assert result.success is True, f'Unexpected error: {result.error}'
        assert result.result is not None
        assert '401000' in result.result.lower()

    def test_error_returns_traceback(self, backend):
        """Division by zero sets success=False and error contains ZeroDivision."""
        result = run_async(pyghidra_eval, backend, '1/0')
        assert result.success is False
        assert result.error is not None
        assert 'ZeroDivision' in result.error or 'ZeroDivision' in (result.error_traceback or '')

    def test_variable_assignment(self, backend):
        """Assigning to 'result' variable returns that value."""
        result = run_async(pyghidra_eval, backend, 'result = 42')
        assert result.success is True
        assert result.result == '42'


class TestScriptingPersistence:
    """Persistent scripting session tests — variables survive between calls."""

    @pytest.fixture(autouse=True)
    def reset_scripting_state(self, backend):
        """Reset persistent globals before and after each test."""
        run_async(pyghidra_eval, backend, '', reset=True)
        yield
        run_async(pyghidra_eval, backend, '', reset=True)

    def test_variable_persists_between_calls(self, backend):
        """Variable set in call 1 is readable in call 2."""
        r1 = run_async(pyghidra_eval, backend, 'x = 42')
        assert r1.success

        r2 = run_async(pyghidra_eval, backend, 'x')
        assert r2.success
        assert r2.result == '42'

    def test_function_persists(self, backend):
        """Function defined in call 1 is callable in call 2."""
        run_async(pyghidra_eval, backend, 'def greet(): return "hello"')
        r = run_async(pyghidra_eval, backend, 'greet()')
        assert r.success
        assert r.result == 'hello'

    def test_import_persists(self, backend):
        """Module imported in call 1 is accessible in call 2."""
        run_async(pyghidra_eval, backend, 'import os')
        r = run_async(pyghidra_eval, backend, 'os.path.sep')
        assert r.success
        assert r.result in ('/', '\\')

    def test_reset_clears_user_state(self, backend):
        """reset=True clears user-defined variables."""
        run_async(pyghidra_eval, backend, 'persist_var = 99')
        r = run_async(pyghidra_eval, backend, 'persist_var')
        assert r.result == '99'

        # Reset session
        run_async(pyghidra_eval, backend, '', reset=True)

        # Variable should be gone
        r = run_async(pyghidra_eval, backend, 'persist_var')
        assert r.success is False  # NameError

    def test_reset_preserves_platform_apis(self, backend):
        """After reset, Ghidra APIs are still accessible."""
        run_async(pyghidra_eval, backend, '', reset=True)
        r = run_async(pyghidra_eval, backend, 'currentProgram.getName()')
        assert r.success

    def test_reset_then_execute(self, backend):
        """reset=True clears state before executing the supplied code."""
        run_async(pyghidra_eval, backend, 'x = 1')
        # After reset, x no longer exists — this should fail with NameError
        r = run_async(pyghidra_eval, backend, 'y = x + 1\ny', reset=True)
        assert r.success is False  # NameError on x

    def test_reset_only_returns_session_reset(self, backend):
        """reset=True with empty code returns 'Session reset' result."""
        r = run_async(pyghidra_eval, backend, '', reset=True)
        assert r.success is True
        assert r.result == 'Session reset'
