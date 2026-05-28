"""Unit tests for open_program.py — branch coverage expansion.

Targets: src/mcpyghidra/tools/open_program.py
Goal:    75%+ line / ~95% branch

All Ghidra/Java/JPype imports are mocked via sys.modules so the tests run
without a live Ghidra environment.

Branches covered here (the existing test_open_program.py already covers
_find_file_by_name happy/sad paths and the is_headless guard):

1. open_program_sync — AutoImporter returns None → error_container set
2. open_program_sync — AutoImporter returns empty list → error_container set
3. open_program_sync — file does not exist on disk AND not in project → error_container set
4. open_program_sync — _do_open thread raises generic Exception → error_container set
5. open_program_sync — result ready but MCPPortManager.get_port_by_path returns None
   and wait=True → 'timeout' status response
6. open_program_sync — result ready, port found → 'ready' status response
7. open_program_sync — wait=False, no port → 'analyzing' status response
8. open_program_sync — deadline expires before result → ValueError('Timed out')
"""
from __future__ import annotations

import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub out Java / Ghidra / JPype top-level packages so that
# open_program.py's lazy imports inside _do_open() resolve to mocks.
# NOTE: mcpyghidra.mcpserver is intentionally NOT stubbed here — it is
# provided per-test via the _mock_mcpserver_in_sys_modules autouse fixture
# below so that the real mcpyghidra.* modules are never permanently
# replaced in sys.modules (which would break other test files).
# ---------------------------------------------------------------------------
_JAVA_STUBS = [
    'java',
    'java.util',
    'java.io',
    'java.lang',
    'jpype',
    'ghidra',
    'ghidra.app',
    'ghidra.app.util',
    'ghidra.app.util.importer',
    'ghidra.util',
    'ghidra.util.task',
]
for _mod in _JAVA_STUBS:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# ---------------------------------------------------------------------------
# Module-level mock for mcpyghidra.mcpserver, installed per-test via fixture.
# ---------------------------------------------------------------------------
_MOCK_MCPSERVER = MagicMock()


@pytest.fixture(autouse=True)
def _mock_mcpserver_in_sys_modules():
    """Install _MOCK_MCPSERVER as sys.modules['mcpyghidra.mcpserver'] for each test.

    Using patch.dict ensures the real mcpyghidra.mcpserver is restored after
    every test, regardless of how the test mutates MCPPortManager on the stub.
    """
    with patch.dict(sys.modules, {'mcpyghidra.mcpserver': _MOCK_MCPSERVER}):
        yield


def _make_backend(*, is_headless: bool = False) -> MagicMock:
    """Minimal PluginBackend-like mock (is_headless=False by default)."""
    backend = MagicMock()
    backend.is_headless = is_headless

    # project / project_data / tool_services chain
    project = MagicMock()
    project_data = MagicMock()
    tool_services = MagicMock()
    project.getProjectData.return_value = project_data
    project.getToolServices.return_value = tool_services
    backend._tool.getProject.return_value = project

    return backend


def _make_folder(*, files: list | None = None, subfolders: list | None = None) -> MagicMock:
    folder = MagicMock()
    folder.getFiles.return_value = files or []
    folder.getFolders.return_value = subfolders or []
    return folder


# ---------------------------------------------------------------------------
# Helper: run open_program_sync with a controlled _do_open side-effect.
# We replace threading.Thread so _do_open runs *synchronously* (in the
# same thread), which makes the test deterministic without real waits.
# ---------------------------------------------------------------------------

def _run_sync_with_thread_patch(backend, path_or_name, *, wait=True, timeout=5):
    """Run open_program_sync with Thread.start() executing the target inline."""
    from mcpyghidra.tools.open_program import open_program_sync

    class _InlineThread:
        """Executes target() immediately on start() rather than in a new thread."""
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            if self._target:
                self._target()

    with patch('mcpyghidra.tools.open_program.threading.Thread', _InlineThread):
        return open_program_sync(backend, path_or_name, wait=wait, timeout=timeout)


# ---------------------------------------------------------------------------
# 1. is_headless guard (already in test_open_program.py; kept for completeness
#    but marked to ensure branch is covered).
# ---------------------------------------------------------------------------

def test_headless_raises_value_error():
    """is_headless=True → ValueError before any thread is spawned."""
    from mcpyghidra.tools.open_program import open_program_sync

    backend = _make_backend(is_headless=True)
    with pytest.raises(ValueError, match='GUI mode'):
        open_program_sync(backend, '/some/file.bin')


# ---------------------------------------------------------------------------
# 2. File not on disk AND not in project → error branch
# ---------------------------------------------------------------------------

def test_file_not_found_and_not_in_project():
    """Path that is not a file and not in the project raises ValueError."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value
    root_folder = _make_folder()
    project_data.getRootFolder.return_value = root_folder

    # Patch MCPPortManager so we don't import it from outside our stubs
    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    # '/nonexistent/ghost.bin' is not a real path → is_file() returns False
    # and _find_file_by_name returns None (empty folder)
    with pytest.raises(ValueError, match='not in project'):
        _run_sync_with_thread_patch(backend, '/nonexistent/ghost.bin')


# ---------------------------------------------------------------------------
# 3. _find_file_by_name returns None path (not in project) but is real file
#    → AutoImporter.importByUsingBestGuess returns None
# ---------------------------------------------------------------------------

def test_autoimporter_returns_none_sets_error():
    """AutoImporter returns None → ValueError with 'Failed to import'."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value
    root_folder = _make_folder()
    project_data.getRootFolder.return_value = root_folder

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    # Make AutoImporter.importByUsingBestGuess return None
    sys.modules['ghidra.app.util.importer'].AutoImporter.importByUsingBestGuess.return_value = None
    sys.modules['ghidra.app.util.importer'].MessageLog.return_value = MagicMock()
    sys.modules['ghidra.util.task'].TaskMonitor.DUMMY = MagicMock()
    sys.modules['java.io'].File = MagicMock()
    sys.modules['java.lang'].Object = MagicMock()
    sys.modules['jpype'].JString = MagicMock()
    sys.modules['java.util'].Collections.singletonList = MagicMock()

    # Use a real temporary file so is_file() returns True
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp_path = tmp.name
    try:
        with pytest.raises(ValueError, match='Failed to import'):
            _run_sync_with_thread_patch(backend, tmp_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# 4. AutoImporter returns empty list (size() == 0) → error branch
# ---------------------------------------------------------------------------

def test_autoimporter_returns_empty_list_sets_error():
    """AutoImporter returns a list with size()==0 → ValueError with 'Failed to import'."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value
    root_folder = _make_folder()
    project_data.getRootFolder.return_value = root_folder

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    mock_load_results = MagicMock()
    mock_load_results.size.return_value = 0
    sys.modules['ghidra.app.util.importer'].AutoImporter.importByUsingBestGuess.return_value = (
        mock_load_results
    )
    sys.modules['ghidra.app.util.importer'].MessageLog.return_value = MagicMock()
    sys.modules['ghidra.util.task'].TaskMonitor.DUMMY = MagicMock()
    sys.modules['java.io'].File = MagicMock()
    sys.modules['java.lang'].Object = MagicMock()
    sys.modules['jpype'].JString = MagicMock()

    import tempfile
    import os
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp_path = tmp.name
    try:
        with pytest.raises(ValueError, match='Failed to import'):
            _run_sync_with_thread_patch(backend, tmp_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# 5. _do_open raises generic Exception → error_container set → ValueError
# ---------------------------------------------------------------------------

def test_do_open_exception_propagates_as_value_error():
    """Any exception inside _do_open is caught and re-raised as ValueError.

    The exception must occur inside _do_open's try block.  project_data is
    captured by the closure; project_data.getRootFolder() is the first call
    inside _do_open, so that's where we inject the failure.
    """
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value
    # getRootFolder is called inside _do_open → triggers the except branch
    project_data.getRootFolder.side_effect = RuntimeError('java crash')

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    with pytest.raises(ValueError, match='java crash'):
        _run_sync_with_thread_patch(backend, '/any/path.bin')


# ---------------------------------------------------------------------------
# 6. Result ready but MCPPortManager.get_port_by_path returns None (wait=True)
#    → timeout status (not a raised exception)
# ---------------------------------------------------------------------------

def test_port_not_registered_wait_true_returns_timeout_status():
    """Port not registered within timeout → {'status': 'timeout', ...}."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value

    # File already in project (existing path) so _do_open succeeds quickly
    mock_domain_file = MagicMock()
    mock_domain_file.getName.return_value = 'crackme.elf'
    mock_domain_file.getPathname.return_value = '/project/crackme.elf'
    root_folder = _make_folder(files=[mock_domain_file])
    project_data.getRootFolder.return_value = root_folder

    # Port never appears
    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    # Patch time.sleep to avoid real waiting and shrink the poll loop
    # timeout=1 (1 second) with mocked sleep still completes quickly via
    # our inline-thread approach (result_container is set immediately by _do_open).
    # The loop will find result but port=None after one iteration, then exit at deadline.
    # We need the loop to complete: patch monotonic to move past deadline after 1 check.
    original_monotonic = time.monotonic
    call_count: list[int] = [0]

    def _fast_monotonic():
        call_count[0] += 1
        # First call (deadline setup) returns 0.0; second+ calls return values
        # that approach the deadline quickly.
        base = original_monotonic()
        # After 3 calls allow deadline to expire
        if call_count[0] >= 4:
            return base + 9999
        return base

    with patch('mcpyghidra.tools.open_program.time.monotonic', _fast_monotonic), \
         patch('mcpyghidra.tools.open_program.time.sleep'):
        result = _run_sync_with_thread_patch(backend, 'crackme.elf', wait=True, timeout=5)

    assert result['status'] == 'timeout'
    assert result['binary'] == 'crackme.elf'
    assert result['new_server'] is None


# ---------------------------------------------------------------------------
# 7. Result ready + port found → 'ready' status
# ---------------------------------------------------------------------------

def test_port_found_wait_true_returns_ready_status():
    """Port registered → {'status': 'ready', 'new_server': {'host':..., 'port':...}}."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value

    mock_domain_file = MagicMock()
    mock_domain_file.getName.return_value = 'firmware.bin'
    mock_domain_file.getPathname.return_value = '/project/firmware.bin'
    root_folder = _make_folder(files=[mock_domain_file])
    project_data.getRootFolder.return_value = root_folder

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = 18000
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    with patch('mcpyghidra.tools.open_program.time.sleep'):
        result = _run_sync_with_thread_patch(backend, 'firmware.bin', wait=True, timeout=5)

    assert result['status'] == 'ready'
    assert result['binary'] == 'firmware.bin'
    assert result['new_server'] == {'host': '127.0.0.1', 'port': 18000}
    assert result['analysis_status'] == 'complete'


# ---------------------------------------------------------------------------
# 8. wait=False, no port → 'analyzing' status (no ValueError)
# ---------------------------------------------------------------------------

def test_wait_false_no_port_returns_analyzing_status():
    """wait=False → returns immediately with 'analyzing' even with no port."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value

    mock_domain_file = MagicMock()
    mock_domain_file.getName.return_value = 'target.bin'
    mock_domain_file.getPathname.return_value = '/project/target.bin'
    root_folder = _make_folder(files=[mock_domain_file])
    project_data.getRootFolder.return_value = root_folder

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    # Shrink the loop: deadline expires after a couple of monotonic calls
    original_monotonic = time.monotonic
    call_count2: list[int] = [0]

    def _expire_fast():
        call_count2[0] += 1
        if call_count2[0] >= 4:
            return original_monotonic() + 9999
        return original_monotonic()

    with patch('mcpyghidra.tools.open_program.time.monotonic', _expire_fast), \
         patch('mcpyghidra.tools.open_program.time.sleep'):
        result = _run_sync_with_thread_patch(backend, 'target.bin', wait=False, timeout=5)

    assert result['status'] == 'analyzing'
    assert result['analysis_status'] == 'analyzing'
    assert result['new_server'] is None


# ---------------------------------------------------------------------------
# 9. Deadline expires before result_container is set → ValueError('Timed out')
# ---------------------------------------------------------------------------

def test_timeout_before_result_raises():
    """Deadline expires before _do_open sets result → ValueError with 'Timed out'."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value

    # _find_file_by_name will return None (no files in folder), and the path
    # is not a real file, and we need _do_open to NOT set result_container.
    # But with our _InlineThread approach, _do_open runs synchronously and
    # WILL set error_container (not found). We need a different approach:
    # patch _do_open so it does nothing (simulates a stuck background thread).
    root_folder = _make_folder()
    project_data.getRootFolder.return_value = root_folder

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    from mcpyghidra.tools.open_program import open_program_sync

    # Use a real Thread but make _do_open a no-op so result_container stays None.
    # We also patch time to instantly expire the deadline.
    original_monotonic = time.monotonic

    call_seq: list[int] = [0]

    def _instant_expire():
        call_seq[0] += 1
        if call_seq[0] == 1:
            # First call: set the deadline base
            return original_monotonic()
        # All subsequent calls: already past deadline
        return original_monotonic() + 9999

    class _NoOpThread:
        def __init__(self, target=None, daemon=None):
            pass  # do not store target; _do_open never runs

        def start(self):
            pass  # nothing happens → result_container stays [None]

    with patch('mcpyghidra.tools.open_program.threading.Thread', _NoOpThread), \
         patch('mcpyghidra.tools.open_program.time.monotonic', _instant_expire), \
         patch('mcpyghidra.tools.open_program.time.sleep'):
        with pytest.raises(ValueError, match='Timed out'):
            open_program_sync(backend, 'ghost.bin', wait=True, timeout=5)


# ---------------------------------------------------------------------------
# 10. _find_file_by_name — file found in project → existing branch taken
# ---------------------------------------------------------------------------

def test_existing_file_in_project_opens_without_import():
    """File already in project → tool_services.launchDefaultTool called, no AutoImporter."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value
    tool_services = backend._tool.getProject.return_value.getToolServices.return_value

    mock_domain_file = MagicMock()
    mock_domain_file.getName.return_value = 'existing.elf'
    mock_domain_file.getPathname.return_value = '/project/existing.elf'
    root_folder = _make_folder(files=[mock_domain_file])
    project_data.getRootFolder.return_value = root_folder

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = 19000
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm
    sys.modules['java.util'].Collections.singletonList.return_value = MagicMock()

    with patch('mcpyghidra.tools.open_program.time.sleep'):
        result = _run_sync_with_thread_patch(backend, 'existing.elf', wait=True, timeout=5)

    assert result['status'] == 'ready'
    assert result['binary'] == 'existing.elf'
    tool_services.launchDefaultTool.assert_called_once()


# ---------------------------------------------------------------------------
# 11. _find_file_by_name — not found at root, found in nested subfolder
#     (re-tests recursion; exists in test_open_program.py but ensures
#     _find_file_by_name returns result, not None, for the recursive branch)
# ---------------------------------------------------------------------------

def test_find_file_by_name_returns_none_in_fully_empty_tree():
    """An empty folder tree returns None (both loops have no items)."""
    from mcpyghidra.tools.open_program import _find_file_by_name

    root = _make_folder(files=[], subfolders=[])
    assert _find_file_by_name(root, 'missing.bin') is None


def test_find_file_by_name_subfolder_miss_then_found_at_sibling():
    """File not in first subfolder but found in second subfolder."""
    from mcpyghidra.tools.open_program import _find_file_by_name

    target = MagicMock()
    target.getName.return_value = 'found.elf'

    empty_sub = _make_folder(files=[], subfolders=[])
    target_sub = _make_folder(files=[target], subfolders=[])
    root = _make_folder(files=[], subfolders=[empty_sub, target_sub])

    result = _find_file_by_name(root, 'found.elf')
    assert result is target


# ---------------------------------------------------------------------------
# 13. Error set after deadline expires (line 131 branch)
#
# Scenario: _do_open finishes *after* the while loop exits but *before* line 131
# is reached.  We simulate this by having the NoOp thread NOT execute, then
# manually setting error_container from outside — but we can't access the
# local list.  Instead, we use a thread that sleeps briefly then sets the
# error (we patch sleep so the deadline expires, but error_container is set
# just before line 131).
#
# The simplest deterministic approach: patch monotonic so the loop runs 0
# iterations (deadline already passed on first check), then our inline thread
# has already set error_container.  We inject the error via getRootFolder
# so _do_open sets error_container, and we need that to happen with an
# inline thread AND the loop to skip directly to line 130.
# ---------------------------------------------------------------------------

def test_error_container_set_after_deadline_raises_at_line_131():
    """Error set by _do_open; loop never fires (deadline=0); line-131 check raises."""
    backend = _make_backend()
    project_data = backend._tool.getProject.return_value.getProjectData.return_value
    # Raise inside _do_open so error_container gets set
    project_data.getRootFolder.side_effect = RuntimeError('late error')

    mock_pm = MagicMock()
    mock_pm.get_port_by_path.return_value = None
    sys.modules['mcpyghidra.mcpserver'].MCPPortManager = mock_pm

    from mcpyghidra.tools.open_program import open_program_sync

    call_seq2: list[int] = [0]

    def _deadline_already_passed():
        call_seq2[0] += 1
        if call_seq2[0] == 1:
            # First call sets the deadline base; return 0 so deadline = timeout seconds.
            return 0.0
        # Subsequent calls are the while-loop condition: already past deadline.
        return 9999.0

    class _InlineThread:
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            if self._target:
                self._target()  # Sets error_container before loop runs (inline)

    with patch('mcpyghidra.tools.open_program.threading.Thread', _InlineThread), \
         patch('mcpyghidra.tools.open_program.time.monotonic', _deadline_already_passed), \
         patch('mcpyghidra.tools.open_program.time.sleep'):
        with pytest.raises(ValueError, match='late error'):
            open_program_sync(backend, '/some/path.bin', wait=True, timeout=5)
