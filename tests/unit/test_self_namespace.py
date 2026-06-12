"""Unit tests for mcp.self in-process tool projection (tools/scripting.py).

`mcp.self.*` exposes this server's own published tools inside the pyghidra
script environment, dispatched IN-PROCESS (not reverse-RPC'd back to the
client, which would re-enter the server mid-request and deadlock). Always
injected, independent of any mcpy/rpcCallbacks client.

These tests do NOT require Ghidra/Java — they exercise the namespace-building
and dispatch-wiring logic with a mock backend.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from mcpyghidra.rpc_callbacks import ToolNamespace
from mcpyghidra.tools.scripting import (
    _SELF_EXCLUDED_TOOLS,
    _build_self_namespace,
    _get_script_limiter,
    _install_self_namespace,
    _make_self_dispatch,
)


def _make_backend() -> MagicMock:
    backend = MagicMock()
    backend.is_headless = True  # excludes the GUI-only open_program tool
    return backend


# ===========================================================================
# TestBuildSelfNamespace
# ===========================================================================

class TestBuildSelfNamespace:
    def test_contains_published_tools(self):
        ns = _build_self_namespace(_make_backend(), 'mcp')
        assert isinstance(ns, ToolNamespace)
        for t in ('decompile', 'rename', 'list', 'types', 'xrefs', 'patch'):
            assert t in ns._children, f'{t} missing from mcp.self'
            assert callable(ns._children[t])

    def test_excludes_pyghidra_and_open_program(self):
        ns = _build_self_namespace(_make_backend(), 'mcp')
        assert 'pyghidra' not in ns._children
        assert 'open_program' not in ns._children
        assert _SELF_EXCLUDED_TOOLS == frozenset({'pyghidra', 'open_program'})

    def test_leaf_carries_dotted_name_and_docstring(self):
        ns = _build_self_namespace(_make_backend(), 'mcp')
        leaf = ns._children['decompile']
        # help()/repr show the projected dotted path, not the bare leaf.
        assert leaf.__name__ == 'mcp.self.decompile'
        assert leaf.__qualname__ == 'mcp.self.decompile'
        assert leaf.__doc__  # the handler docstring flows through for help()


# ===========================================================================
# TestInstallSelfNamespace
# ===========================================================================

class TestInstallSelfNamespace:
    def test_creates_mcp_root_when_absent(self):
        roots: dict = {}
        _install_self_namespace(roots, _make_backend(), {})
        assert isinstance(roots['mcp'], ToolNamespace)
        assert isinstance(roots['mcp']._children['self'], ToolNamespace)
        assert 'decompile' in roots['mcp'].self._children

    def test_merges_into_existing_reverse_rpc_root(self):
        # A reverse-RPC projection already built mcp.other.* under the mcp root.
        roots: dict = {}
        mcp_root = ToolNamespace('mcp')
        other = ToolNamespace('mcp.other')
        other._children['foo'] = lambda: None
        mcp_root._children['other'] = other
        roots['mcp'] = mcp_root

        _install_self_namespace(roots, _make_backend(), {})

        assert 'other' in roots['mcp']._children  # reverse-RPC preserved
        assert isinstance(roots['mcp']._children['self'], ToolNamespace)

    def test_escapes_mcp_when_shadowing_existing_global(self):
        roots: dict = {}
        _install_self_namespace(roots, _make_backend(), {'mcp': 'user_var'})
        assert 'mcp' not in roots
        assert isinstance(roots['_mcp'], ToolNamespace)
        assert 'self' in roots['_mcp']._children

    def test_skips_when_mcp_and_escaped_both_shadowed(self):
        roots: dict = {}
        _install_self_namespace(roots, _make_backend(), {'mcp': 1, '_mcp': 2})
        assert roots == {}

    def test_skips_when_mcp_root_is_callable(self):
        sentinel = lambda: None  # noqa: E731
        roots: dict = {'mcp': sentinel}
        _install_self_namespace(roots, _make_backend(), {})
        assert roots['mcp'] is sentinel  # unchanged; cannot nest under a callable


# ===========================================================================
# TestMakeSelfDispatch
# ===========================================================================

class TestMakeSelfDispatch:
    def test_metadata(self):
        async def handler(items):
            """Decompile docstring."""

        d = _make_self_dispatch(handler, 'mcp.self.decompile')
        assert d.__name__ == 'mcp.self.decompile'
        assert d.__qualname__ == 'mcp.self.decompile'
        assert d.__doc__ == 'Decompile docstring.'

    def test_dispatch_forwards_args_and_kwargs_to_handler(self):
        captured: dict = {}

        async def handler(items, flag=False):
            captured['args'] = (items, flag)
            return 'ok'

        d = _make_self_dispatch(handler, 'decompile')

        def _fake_from_thread_run(part):
            # `part` is functools.partial(handler, *args, **kwargs) — run it.
            import asyncio
            return asyncio.run(part())

        with patch('anyio.from_thread.run', side_effect=_fake_from_thread_run):
            result = d([1, 2], flag=True)

        assert result == 'ok'
        assert captured['args'] == ([1, 2], True)


# ===========================================================================
# TestScriptLimiter
# ===========================================================================

class TestScriptLimiter:
    def test_dedicated_limiter_is_cached(self):
        import mcpyghidra.tools.scripting as s

        s._script_limiter = None
        lim1 = _get_script_limiter()
        lim2 = _get_script_limiter()
        assert lim1 is lim2
        assert lim1.total_tokens == s._SCRIPT_LIMITER_TOKENS


# ===========================================================================
# TestScopedImporter — `import mcp...` resolves to the projected tree (REPL only)
# ===========================================================================

class TestScopedImporter:
    """The script-scoped __import__ makes `mcp`/`mcp.*` import the projected
    namespaces, deferring everything else to the real importer, without touching
    sys.modules or the real `mcp` SDK package."""

    def _tree(self) -> dict:
        mcp = ToolNamespace('mcp')
        ida1 = ToolNamespace('mcp.ida1')
        mcp._children['ida1'] = ida1
        ida1._children['echo'] = lambda m: f'e:{m}'
        svc = ToolNamespace('mcp.svc')
        mcp._children['svc'] = svc
        math = ToolNamespace('mcp.svc.math')
        svc._children['math'] = math
        math._children['add'] = lambda a, b: a + b
        return {'mcp': mcp}

    def _run(self, code: str) -> dict:
        import mcpyghidra.tools.scripting as s

        g: dict = {}
        s._install_scoped_importer(g)
        s._active_import_roots = self._tree()
        try:
            exec(code, g)
        finally:
            s._active_import_roots = None
        return g

    def test_bare_import_mcp_is_ours(self):
        g = self._run("import mcp\nr = mcp.ida1.echo('a')")
        assert g['r'] == 'e:a'

    def test_import_submodule_as(self):
        g = self._run("import mcp.ida1 as ida\nr = ida.echo('b')")
        assert g['r'] == 'e:b'

    def test_import_nested(self):
        g = self._run("import mcp.svc.math as m\nr = m.add(2, 3)")
        assert g['r'] == 5

    def test_from_import(self):
        g = self._run("from mcp.ida1 import echo\nr = echo('c')")
        assert g['r'] == 'e:c'

    def test_from_root_import_subnamespace(self):
        g = self._run("from mcp import ida1\nr = ida1.echo('d')")
        assert g['r'] == 'e:d'

    def test_real_imports_still_defer(self):
        g = self._run("import json\nr = json.dumps({'x': 1})")
        assert g['r'] == '{"x": 1}'

    def test_stdlib_not_shadowed_when_root_escaped(self):
        # A tool named os__... is projected under the ESCAPED root `_os` (see
        # _build_rpc_globals), so the real stdlib `os` is reachable as usual.
        import mcpyghidra.tools.scripting as s

        g: dict = {}
        s._install_scoped_importer(g)
        s._active_import_roots = {'_os': ToolNamespace('_os')}
        try:
            exec("import os\nr = os.path.join('a', 'b')", g)
        finally:
            s._active_import_roots = None
        assert g['r'] == 'a/b'  # real stdlib os, not our namespace

    def test_inactive_when_roots_none_defers_to_real_mcp_sdk(self):
        import mcpyghidra.tools.scripting as s

        g: dict = {}
        s._install_scoped_importer(g)
        s._active_import_roots = None  # between executions: transparent
        exec('import mcp as real_mcp\nr = hasattr(real_mcp, "client")', g)
        assert g['r'] is True  # got the real SDK, not our tree
