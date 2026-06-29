"""Unit + subprocess tests for the headless CLI surface (no JVM reached)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from mcpyghidra.cli_status import StartupError
from mcpyghidra.headless import _resolve_startup
from tests.conftest import CRACKME_ELF

# Placeholder GHIDRA_INSTALL_DIR value: the tests that use it never validate the
# directory (they set the env on the "env already present" path, or exit before
# the pyghidra import); the one test that validates a --ghidra-dir builds a fake
# install under tmp_path. Kept generic so no real/dev-machine path ships publicly.
GHIDRA_DIR = '/opt/ghidra'


def _args(**kw):
    base = dict(binary=CRACKME_ELF, port='6050-6059', ghidra_dir=None,
               host='127.0.0.1', project_dir=None, project_name=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_resolve_ok_with_env(monkeypatch):
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', GHIDRA_DIR)
    binary_path, candidates = _resolve_startup(_args())
    assert binary_path.name == 'crackme.elf'
    assert candidates == list(range(6050, 6060))


def test_resolve_binary_not_found(monkeypatch):
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', GHIDRA_DIR)
    with pytest.raises(StartupError) as e:
        _resolve_startup(_args(binary='/no/such/bin'))
    assert e.value.reason == 'binary_not_found'


def test_resolve_bad_port(monkeypatch):
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', GHIDRA_DIR)
    with pytest.raises(StartupError) as e:
        _resolve_startup(_args(port='not-a-port'))
    assert e.value.reason == 'bad_port'


def test_resolve_missing_install_dir(monkeypatch):
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)
    with pytest.raises(StartupError) as e:
        _resolve_startup(_args())
    assert e.value.reason == 'missing_install_dir'


def test_resolve_bad_ghidra_dir(monkeypatch):
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)
    with pytest.raises(StartupError) as e:
        _resolve_startup(_args(ghidra_dir='/tmp'))
    assert e.value.reason == 'missing_install_dir'


def test_resolve_good_ghidra_dir_sets_env(monkeypatch, tmp_path):
    # Build a fake Ghidra install (just the validity marker) so this runs on CI
    # runners without a real Ghidra at any fixed path.
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)
    fake = tmp_path / 'ghidra'
    (fake / 'Ghidra').mkdir(parents=True)
    (fake / 'Ghidra' / 'application.properties').write_text('application.version=12.0\n')
    _resolve_startup(_args(ghidra_dir=str(fake)))
    assert os.environ['GHIDRA_INSTALL_DIR'] == str(fake.resolve())


def _run(*argv, env=None):
    e = dict(os.environ)
    e.pop('GHIDRA_INSTALL_DIR', None)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, '-m', 'mcpyghidra.headless', *argv],
                          capture_output=True, text=True, timeout=30, env=e)


def test_subprocess_missing_positional_is_argparse_error():
    p = _run()
    assert p.returncode == 2  # argparse: missing positional


def test_subprocess_binary_flag_rejected():
    p = _run('--binary', CRACKME_ELF)
    assert p.returncode == 2  # --binary no longer exists


def test_subprocess_binary_not_found_json_exit3():
    p = _run('/no/such/bin', env={'GHIDRA_INSTALL_DIR': GHIDRA_DIR})
    assert p.returncode == 3
    assert json.loads(p.stdout.strip().splitlines()[-1])['reason'] == 'binary_not_found'


def test_subprocess_bad_port_json_exit5():
    p = _run(CRACKME_ELF, '--port', 'xyz', env={'GHIDRA_INSTALL_DIR': GHIDRA_DIR})
    assert p.returncode == 5
    assert json.loads(p.stdout.strip().splitlines()[-1])['reason'] == 'bad_port'


def test_subprocess_missing_install_dir_json_exit4():
    p = _run(CRACKME_ELF)  # env strips GHIDRA_INSTALL_DIR
    assert p.returncode == 4
    assert json.loads(p.stdout.strip().splitlines()[-1])['reason'] == 'missing_install_dir'
