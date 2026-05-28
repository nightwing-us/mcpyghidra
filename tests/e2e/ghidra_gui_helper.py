"""Helper for launching Ghidra GUI under Xvfb+bwrap for e2e testing.

Provides fully isolated Ghidra GUI instances using:
- Xvfb: virtual framebuffer (no physical display needed)
- bwrap: filesystem isolation (test config/cache, real system untouched)

Requires: xvfb-run, bwrap, pyghidra, Ghidra 12.0.4+
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

# Test fixture paths
FIXTURE_DIR = Path(__file__).parent.parent / 'fixtures' / 'ghidra_gui_test'
GUI_PROJECT = FIXTURE_DIR / 'gui_test' / 'gui_test'
GHIDRA_CONFIG = FIXTURE_DIR / 'ghidra_config'
DECAF_CACHE = FIXTURE_DIR / 'decaf_cache'
GHIDRA_CACHE = FIXTURE_DIR / 'ghidra_cache'

GHIDRA_VER = 'ghidra_12.0.4_PUBLIC'
# Resolve via env vars / PATH so the same helper works from a developer
# machine and the CI test-docker image (which installs Ghidra at
# $GHIDRA_INSTALL_DIR=/opt/ghidra and pyghidra into the system venv).
PYGHIDRA_BIN = os.environ.get('PYGHIDRA_BIN') or shutil.which('pyghidra') or ''
GHIDRA_INSTALL = os.environ.get('GHIDRA_INSTALL_DIR', '/opt/ghidra')

# Test port range (avoid conflict with real Ghidra on 6050)
TEST_MCP_PORT = 16050


def _check_prerequisites() -> str | None:
    """Return error message if prerequisites are missing, None if OK."""
    if not shutil.which('xvfb-run'):
        return 'xvfb-run not found'
    if not shutil.which('bwrap'):
        return 'bwrap (bubblewrap) not found'
    if not Path(PYGHIDRA_BIN).exists():
        return f'pyghidra not found at {PYGHIDRA_BIN}'
    if not Path(GHIDRA_INSTALL).exists():
        return f'Ghidra not found at {GHIDRA_INSTALL}'
    if not GUI_PROJECT.with_suffix('.gpr').exists():
        return f'Test project not found at {GUI_PROJECT}'
    return None


def _kill_port(port: int) -> None:
    """Kill any process listening on the given port."""
    try:
        result = subprocess.run(
            ['lsof', '-ti', f':{port}'],
            capture_output=True, text=True, timeout=5,
        )
        for pid in result.stdout.strip().split('\n'):
            if pid.strip():
                os.kill(int(pid.strip()), signal.SIGKILL)
        if result.stdout.strip():
            time.sleep(1)  # wait for port to free
    except (subprocess.TimeoutExpired, FileNotFoundError, ProcessLookupError):
        pass


def launch_ghidra_gui(timeout: float = 120) -> subprocess.Popen:
    """Launch Ghidra GUI under Xvfb+bwrap with fully isolated config.

    Kills any leftover process on TEST_MCP_PORT before launching.
    Returns the subprocess. Caller must kill it when done.
    """
    _kill_port(TEST_MCP_PORT)

    home = os.path.expanduser('~')
    config_dir = str(GHIDRA_CONFIG / GHIDRA_VER)
    ghidra_config_target = f'{home}/.config/ghidra/{GHIDRA_VER}'
    decaf_target = f'{home}/.config/decaf'
    cache_target = '/var/tmp/user-ghidra'
    lastrun_file = f'{home}/.config/ghidra/lastrun'

    # Clean stale lock files
    for lock in GUI_PROJECT.parent.glob('*.lock*'):
        lock.unlink(missing_ok=True)

    # Ensure writable dirs exist
    GHIDRA_CACHE.mkdir(exist_ok=True)

    # Create a dummy lastrun file to bind over (avoids read-only error)
    lastrun_dummy = FIXTURE_DIR / 'lastrun'
    lastrun_dummy.touch(exist_ok=True)

    cmd = [
        'xvfb-run', '-a',
        'bwrap',
        '--ro-bind', '/', '/',
        '--dev', '/dev',
        '--proc', '/proc',
        '--bind', '/tmp', '/tmp',
        '--bind', config_dir, ghidra_config_target,
        '--bind', str(DECAF_CACHE), decaf_target,
        '--bind', str(GHIDRA_CACHE), cache_target,
        '--bind', str(GUI_PROJECT.parent), str(GUI_PROJECT.parent),
        '--bind', str(Path(__file__).parent.parent.parent), str(Path(__file__).parent.parent.parent),  # project root
        '--bind', str(lastrun_dummy), lastrun_file,
        '--bind', '/var/tmp', '/var/tmp',
        '--',
        PYGHIDRA_BIN,
        '--gui',
        '--install-dir', GHIDRA_INSTALL,
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def wait_for_mcp_server(
    port: int = TEST_MCP_PORT,
    timeout: float = 120,
    proc: subprocess.Popen | None = None,
) -> bool:
    """Poll until MCP server is responding on the given port."""
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc and proc.poll() is not None:
            return False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except (ConnectionRefusedError, OSError, TimeoutError):
            pass
        time.sleep(2)
    return False
