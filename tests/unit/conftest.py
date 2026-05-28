"""Pytest configuration for the unit test suite.

Problem addressed
-----------------
Several ``test_*_branches.py`` files (added in Phase 5.2/5.3) install
``MagicMock`` stubs for ``ghidra.*``, ``pyghidra*``, ``jpype*``, and
critically ``mcpyghidra.*`` into ``sys.modules`` at **module-load time**
(i.e. during pytest collection).  Once any of those files is collected,
``sys.modules['mcpyghidra.server']`` (and other ``mcpyghidra.*`` entries)
become ``MagicMock`` objects for the rest of the session.  Tests in
``test_server_info.py`` (and other files that import the real
``mcpyghidra`` package) then fail because
``from mcpyghidra.server import build_instructions`` gets a ``MagicMock``
with no such attribute.

Additionally, once the real ``mcpyghidra.server`` has been imported it is
cached as a **package attribute** (``mcpyghidra.server``).  Python's
``import mcpyghidra.server as _srv`` then resolves to that cached
attribute rather than consulting ``sys.modules``, so
``patch.dict(sys.modules, {'mcpyghidra.server': stub})`` does not
intercept the import.  Tests in ``test_scripting_branches.py`` rely on
that interception to inject their mock server.

The ``ghidra.*``, ``java.*``, ``jpype*`` etc. stubs are harmless because
no real Ghidra/JVM is installed; they may persist in ``sys.modules``
without causing cross-file interference.

Fix
---
1.  ``pytest_configure`` snapshots only the ``mcpyghidra.*`` entries in
    ``sys.modules`` **before** collection begins.
2.  ``pytest_collection_finish`` restores that snapshot **after** all test
    files have been imported (collection time), undoing any module-level
    pollution of ``mcpyghidra.*`` introduced by the branch-coverage test
    files.
3.  The ``_restore_mcpyghidra_modules`` autouse fixture restores the
    snapshot **after each test**, undoing any per-test mutations to
    ``sys.modules['mcpyghidra.*']`` keys.

The restore also keeps the ``mcpyghidra`` package's sub-module attributes
in sync with ``sys.modules`` so that ``import mcpyghidra.server as _srv``
inside production code respects ``patch.dict`` overrides in tests.

No test assertions are changed; isolation is purely mechanical.
"""
from __future__ import annotations

import contextlib
import sys
from typing import Dict, Iterator

import pytest


@contextlib.contextmanager
def patched_mcpyghidra_server(stub: object) -> Iterator[object]:
    """Override mcpyghidra.server in sys.modules AND on the package object.

    Python's ``IMPORT_FROM`` reads ``getattr(mcpyghidra, 'server')`` first,
    so a bare ``patch.dict(sys.modules, {'mcpyghidra.server': stub})`` is
    insufficient when production code does ``import mcpyghidra.server as _srv``.
    Use this helper to ensure the stub is visible through both lookup
    paths.  Saved values are restored on exit.
    """
    saved_module = sys.modules.get('mcpyghidra.server')
    pkg = sys.modules.get(_MCPYGHIDRA_PREFIX)
    saved_attr_set = pkg is not None and hasattr(pkg, 'server')
    saved_attr = getattr(pkg, 'server', None) if saved_attr_set else None

    sys.modules['mcpyghidra.server'] = stub  # type: ignore[assignment]
    if pkg is not None:
        setattr(pkg, 'server', stub)
    try:
        yield stub
    finally:
        if saved_module is None:
            sys.modules.pop('mcpyghidra.server', None)
        else:
            sys.modules['mcpyghidra.server'] = saved_module
        if pkg is not None:
            if saved_attr_set:
                setattr(pkg, 'server', saved_attr)
            elif hasattr(pkg, 'server'):
                try:
                    delattr(pkg, 'server')
                except AttributeError:
                    pass

# ---------------------------------------------------------------------------
# Only mcpyghidra.* keys must be kept isolated.
# Ghidra/Java/JPype stubs may persist freely (no real JVM is installed).
# ---------------------------------------------------------------------------
_MCPYGHIDRA_PREFIX = 'mcpyghidra'

# Global snapshot populated in pytest_configure (before collection).
_snapshot: Dict[str, object] = {}


def _is_mcpyghidra(key: str) -> bool:
    """Return True for any sys.modules key under the mcpyghidra namespace."""
    return key == _MCPYGHIDRA_PREFIX or key.startswith(_MCPYGHIDRA_PREFIX + '.')


# ---------------------------------------------------------------------------
# Hook: snapshot before collection
# ---------------------------------------------------------------------------

def pytest_configure(config: pytest.Config) -> None:  # noqa: ARG001
    """Snapshot mcpyghidra.* entries in sys.modules before any file is imported."""
    global _snapshot
    _snapshot = {k: v for k, v in sys.modules.items() if _is_mcpyghidra(k)}


# ---------------------------------------------------------------------------
# Hook: restore after collection (before any test runs)
# ---------------------------------------------------------------------------

def pytest_collection_finish(session: pytest.Session) -> None:  # noqa: ARG001
    """Restore mcpyghidra.* sys.modules entries to the pre-collection snapshot.

    This undoes module-level ``sys.modules['mcpyghidra.xxx'] = MagicMock()``
    statements that ran when branch-coverage test files were imported during
    collection.
    """
    _apply_snapshot()


# ---------------------------------------------------------------------------
# Autouse fixture: restore after each test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _restore_mcpyghidra_modules():
    """Yield to the test, then restore mcpyghidra.* sys.modules entries."""
    yield
    _apply_snapshot()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_snapshot() -> None:
    """Bring mcpyghidra.* entries in sys.modules back to pre-collection state.

    * Keys absent from the snapshot that are now stubs (MagicMock or bare
      ModuleType injected by test files) are removed.
    * Keys present in the snapshot are restored to their original values if
      they have been replaced.
    * Snapshot keys that were deleted are re-inserted.
    * The ``mcpyghidra`` package's sub-module attributes are kept in sync so
      that ``import mcpyghidra.submod as x`` inside production code consults
      ``sys.modules`` rather than a stale cached package attribute.
    """
    from unittest.mock import MagicMock

    # Walk all current mcpyghidra.* keys
    current_mcpy = {k: v for k, v in sys.modules.items() if _is_mcpyghidra(k)}

    for key, value in current_mcpy.items():
        if key in _snapshot:
            # Was present before collection — restore if changed.
            if sys.modules.get(key) is not _snapshot[key]:
                sys.modules[key] = _snapshot[key]
                _sync_package_attr(key, _snapshot[key])
        else:
            # Was absent before collection — it is a stub; remove it.
            if isinstance(value, MagicMock) or _is_stub_module(value):
                sys.modules.pop(key, None)
                _clear_package_attr(key)

    # Re-insert any snapshotted keys that were deleted.
    for key, value in _snapshot.items():
        if key not in sys.modules:
            sys.modules[key] = value
            _sync_package_attr(key, value)

    # If the real mcpyghidra.server was imported during the session (but was
    # not present at snapshot time), ensure the package attribute is cleared
    # so that subsequent patch.dict overrides work correctly.
    _clear_stale_package_attrs()


def _submodule_name(dotted_key: str) -> str | None:
    """Return the immediate sub-module name if *dotted_key* is a direct child of mcpyghidra.

    E.g. 'mcpyghidra.server' → 'server'; 'mcpyghidra.tools.core' → None.
    """
    parts = dotted_key.split('.')
    if len(parts) == 2 and parts[0] == _MCPYGHIDRA_PREFIX:
        return parts[1]
    return None


def _sync_package_attr(key: str, value: object) -> None:
    """Update the mcpyghidra package object's attribute to match sys.modules."""
    attr = _submodule_name(key)
    if attr is None:
        return
    pkg = sys.modules.get(_MCPYGHIDRA_PREFIX)
    if pkg is not None:
        setattr(pkg, attr, value)


def _clear_package_attr(key: str) -> None:
    """Remove the sub-module attribute from the mcpyghidra package object."""
    attr = _submodule_name(key)
    if attr is None:
        return
    pkg = sys.modules.get(_MCPYGHIDRA_PREFIX)
    if pkg is not None and hasattr(pkg, attr):
        delattr(pkg, attr)


def _clear_stale_package_attrs() -> None:
    """Keep the ``mcpyghidra.server`` package attribute aligned with sys.modules.

    Two patching styles co-exist in the unit suite:

    * ``patch.dict(sys.modules, {'mcpyghidra.server': stub})`` — used
      by ``test_scripting_branches.py``.  Those tests ALSO patch the
      package attribute (via ``patched_mcpyghidra_server`` helper)
      because Python's ``IMPORT_FROM`` reads the attribute first and
      the bare sys.modules entry alone is not enough.

    * ``patch('mcpyghidra.server.SomeFunc')`` — used by
      ``test_rpc_server_integration.py``.  ``unittest.mock._dot_lookup``
      reads the package attribute via ``getattr``.  On Python 3.10,
      its ``__import__`` fallback does NOT re-establish a
      previously-deleted attribute when the module is already in
      sys.modules — so the attribute MUST be set for ``patch()`` to
      resolve.  3.11/3.12 are more forgiving but 3.10 is strict.

    Resolution: keep the package attribute pointing at whatever is
    currently in ``sys.modules['mcpyghidra.server']``.  This is right
    for the ``patch()`` style and harmless for the patch.dict style
    when paired with explicit attribute patching.
    """
    pkg = sys.modules.get(_MCPYGHIDRA_PREFIX)
    if pkg is None:
        return
    server_mod = sys.modules.get('mcpyghidra.server')
    if server_mod is not None:
        setattr(pkg, 'server', server_mod)
    elif hasattr(pkg, 'server'):
        try:
            delattr(pkg, 'server')
        except AttributeError:
            pass


def _is_stub_module(obj: object) -> bool:
    """Return True for bare ``types.ModuleType`` objects created by test stubs.

    The import machinery sets ``__spec__`` on every module it loads from disk.
    Hand-crafted stubs (``types.ModuleType('name')`` without a real loader)
    lack ``__spec__`` and ``__file__``.
    """
    import types
    return (
        isinstance(obj, types.ModuleType)
        and getattr(obj, '__spec__', None) is None
        and getattr(obj, '__file__', None) is None
    )
