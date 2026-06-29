"""E2E test fixtures — launches headless server as subprocess."""
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
import time

import pytest

from tests.conftest import CRACKME_ELF, STRUCT_TEST_ELF

LAUNCH_TIMEOUT = 180  # seconds — Ghidra analysis can be slow


def _clean_project_artifacts(binary_path: str) -> None:
    """Remove stale Ghidra project files left beside a test binary.

    Covers both the nested ``<name>_ghidra/`` layout (legacy open_program) and
    the standalone ``<name>_ghidra.gpr`` / ``.rep/`` / ``.lock`` layout that the
    modern open_project API produces.
    """
    base = os.path.dirname(binary_path)
    matches = glob.glob(os.path.join(base, '*_ghidra')) + glob.glob(os.path.join(base, '*_ghidra.*'))
    for path in matches:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                os.remove(path)
            except OSError:
                pass


def _wait_for_ready(proc: subprocess.Popen, timeout: float) -> dict:
    """Read stdout lines until we get the JSON ready signal.

    Uses a watchdog timer to kill the process if readline() blocks
    past the deadline (readline is blocking and cannot be interrupted
    by the deadline check alone).
    """
    deadline = time.monotonic() + timeout

    # Watchdog: kill process if we exceed the deadline while blocked in readline()
    watchdog = threading.Timer(timeout + 5, proc.kill)
    watchdog.daemon = True
    watchdog.start()

    try:
        for line in proc.stdout:
            if time.monotonic() > deadline:
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get('status') == 'ready':
                    return data
            except json.JSONDecodeError:
                # Non-JSON output (analysis logs, etc.) — skip
                continue

        # stdout closed or deadline passed without ready signal
        exit_code = proc.poll()
        pytest.fail(
            f'Server did not become ready within {timeout}s. '
            f'Process exit code: {exit_code}'
        )
    finally:
        watchdog.cancel()


@pytest.fixture(scope='module')
def headless_server(request):
    """Launch mcpyghidra-headless as subprocess, wait for ready signal.

    Yields the status dict: {"status": "ready", "host": ..., "port": ..., "binary": ...}

    Skips if Ghidra/pyghidra is not available.
    """
    # Skip check inside fixture body instead of using @requires_ghidra decorator,
    # so the fixture itself is not decorated (avoids pytest fixture/decorator conflicts).
    import os

    def _can_import(module: str) -> bool:
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    if not os.environ.get('GHIDRA_INSTALL_DIR') and not _can_import('pyghidra'):
        pytest.skip(
            'Ghidra/pyghidra not available '
            '(set GHIDRA_INSTALL_DIR or install pyghidra)'
        )

    # Clean stale Ghidra project files before launching
    _clean_project_artifacts(CRACKME_ELF)

    # Wrap with `coverage run -p` when MCPYGHIDRA_COVERAGE_SUBPROCESS=1 so
    # the headless subprocess contributes to combined coverage reports.
    # CI's test:full job sets this before invoking pytest.
    cmd = [sys.executable, '-m', 'mcpyghidra.headless']
    if os.environ.get('MCPYGHIDRA_COVERAGE_SUBPROCESS') == '1':
        cmd = [sys.executable, '-m', 'coverage', 'run', '-p', '-m', 'mcpyghidra.headless']
    proc = subprocess.Popen(
        cmd + [
            CRACKME_ELF,
            '--port', '0',  # auto-assign port
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # suppress Ghidra stderr noise
        text=True,
    )

    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        yield status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope='class')
def fresh_headless_server(request):
    """Launch a FRESH headless server per test class — clean database, no stale state.

    Use this for mutation tests (rename, set_comments, patch, etc.) that
    modify the binary and might not restore cleanly.

    The existing 'headless_server' (module-scoped) is shared by read-only tests.
    """
    import os

    def _can_import(module):
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    if not os.environ.get('GHIDRA_INSTALL_DIR') and not _can_import('pyghidra'):
        pytest.skip('Ghidra/pyghidra not available')

    # Clean stale Ghidra project files for a fresh analysis
    _clean_project_artifacts(CRACKME_ELF)

    cmd = [sys.executable, '-m', 'mcpyghidra.headless']
    if os.environ.get('MCPYGHIDRA_COVERAGE_SUBPROCESS') == '1':
        cmd = [sys.executable, '-m', 'coverage', 'run', '-p', '-m', 'mcpyghidra.headless']
    proc = subprocess.Popen(
        cmd + [CRACKME_ELF, '--port', '0'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        yield status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        # Clean up after ourselves
        _clean_project_artifacts(CRACKME_ELF)


@pytest.fixture(scope='class')
def struct_test_server(request):
    """Launch a FRESH headless server loaded with struct_test.elf.

    struct_test.elf has debug info with Config/Point structs and known
    local variables in process_config (total: int, p: Point on stack).

    Use this for tests that change local variable types to user-defined
    struct pointers — the binary already has the struct definitions.
    """
    import os

    def _can_import(module):
        try:
            __import__(module)
            return True
        except ImportError:
            return False

    if not os.environ.get('GHIDRA_INSTALL_DIR') and not _can_import('pyghidra'):
        pytest.skip('Ghidra/pyghidra not available')

    # Clean stale Ghidra project files for struct_test.elf
    _clean_project_artifacts(STRUCT_TEST_ELF)

    proc = subprocess.Popen(
        [sys.executable, '-m', 'mcpyghidra.headless',
         STRUCT_TEST_ELF, '--port', '0'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    try:
        status = _wait_for_ready(proc, LAUNCH_TIMEOUT)
        yield status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        # Clean up Ghidra project files for struct_test.elf
        _clean_project_artifacts(STRUCT_TEST_ELF)
