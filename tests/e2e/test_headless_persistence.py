"""E2E: analysis edits survive a SIGTERM-based shutdown.

This is the regression test for the persistence fix in headless.py: the
embedded JVM normally grabs SIGTERM and hard-terminates the process, skipping
open_program's `finally: project.save(...)`. Launching the JVM with `-Xrs` and
converting SIGTERM into KeyboardInterrupt lets the `with` block unwind so the
project is saved.

The test proves the end-to-end contract:
  1. Launch with an explicit --project-dir, rename a function, send SIGTERM.
  2. The process exits gracefully (returncode 0), not killed.
  3. Relaunch against the SAME project dir; the rename is still there.

Skips when Ghidra/pyghidra is unavailable (mirrors the e2e conftest fixtures).
"""
import os
import subprocess
import sys

import pytest

from tests.conftest import CRACKME_ELF
from tests.e2e.conftest import LAUNCH_TIMEOUT, _wait_for_ready
from tests.e2e.test_headless_launch import mcp_call

# Bound the graceful-shutdown wait: SIGTERM -> save -> exit. Project save on the
# small crackme.elf is fast; 30s is generous headroom over observed timings.
SHUTDOWN_TIMEOUT = 30

# Function we rename in launch #1 and look for again in launch #2.
ORIGINAL_FN = 'check_password'
RENAMED_FN = 'persist_marker_fn'


def _ghidra_available() -> bool:
    if os.environ.get('GHIDRA_INSTALL_DIR'):
        return True
    try:
        __import__('pyghidra')
        return True
    except ImportError:
        return False


def _launch(project_dir, project_name: str) -> subprocess.Popen:
    """Launch mcpyghidra-headless against an explicit project dir, port auto-assigned."""
    cmd = [sys.executable, '-m', 'mcpyghidra.headless']
    if os.environ.get('MCPYGHIDRA_COVERAGE_SUBPROCESS') == '1':
        cmd = [sys.executable, '-m', 'coverage', 'run', '-p', '-m', 'mcpyghidra.headless']
    return subprocess.Popen(
        cmd + [
            '--binary', CRACKME_ELF,
            '--port', '0',
            '--project-dir', str(project_dir),
            '--project-name', project_name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _terminate_gracefully(proc: subprocess.Popen) -> int:
    """SIGTERM the process and wait for it to unwind. Returns the exit code.

    Falls back to kill() only if graceful shutdown overruns, so a hang is
    surfaced as a failed return-code assertion rather than a frozen test.
    """
    proc.terminate()  # SIGTERM -> _on_sigterm -> KeyboardInterrupt -> with-block save
    try:
        return proc.wait(timeout=SHUTDOWN_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return -1


@pytest.mark.skipif(not _ghidra_available(), reason='Ghidra/pyghidra not available')
def test_rename_survives_sigterm(tmp_path):
    project_dir = tmp_path / 'proj'
    project_dir.mkdir()
    project_name = 'persist_test'

    # --- Launch #1: rename a function, then SIGTERM ---------------------------
    proc = _launch(project_dir, project_name)
    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        result = mcp_call(status, 'rename', {
            'items': [{'name': ORIGINAL_FN, 'new_name': RENAMED_FN}],
        })
        assert 'error' not in result.lower() or RENAMED_FN in result, (
            f'rename did not succeed: {result[:500]}'
        )
    finally:
        rc = _terminate_gracefully(proc)

    # Core of the fix: SIGTERM must unwind cleanly (saved), not hard-terminate.
    assert rc == 0, (
        f'expected graceful exit (0) after SIGTERM, got {rc}; '
        'project save likely did not run'
    )

    # --- Launch #2: reopen SAME project dir, rename must persist --------------
    proc2 = _launch(project_dir, project_name)
    try:
        status2 = _wait_for_ready(proc2, LAUNCH_TIMEOUT)
        funcs = mcp_call(status2, 'list', {
            'entry_type': 'function', 'offset': 0, 'limit': 500,
        })
        assert RENAMED_FN in funcs, (
            f'rename did not persist across SIGTERM restart; '
            f'expected "{RENAMED_FN}" in function list, got: {funcs[:500]}'
        )
    finally:
        _terminate_gracefully(proc2)
