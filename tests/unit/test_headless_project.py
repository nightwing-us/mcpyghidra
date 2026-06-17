"""Unit tests for headless._resolve_project — CLI project option resolution.

Targets: src/mcpyghidra/headless.py::_resolve_project

headless.py's top-level imports are stdlib only (no JVM), so importing it is
safe without a live Ghidra environment.
"""
from __future__ import annotations

from pathlib import Path

from mcpyghidra.headless import _resolve_project

BIN = Path('/data/samples/crackme.elf')


def test_defaults_mirror_legacy_open_program():
    """No options -> auto-named '<binary>_ghidra' project beside the binary."""
    parent, name, program_path = _resolve_project(None, None, BIN)
    assert parent == '/data/samples'
    assert name == 'crackme_ghidra'
    assert program_path == '/crackme.elf'


def test_explicit_project_dir_overrides_parent():
    parent, name, program_path = _resolve_project('/projects', None, BIN)
    assert parent == '/projects'
    assert name == 'crackme_ghidra'
    assert program_path == '/crackme.elf'


def test_explicit_project_name_overrides_name():
    parent, name, _ = _resolve_project(None, 'myproj', BIN)
    assert parent == '/data/samples'
    assert name == 'myproj'


def test_both_options_honored():
    parent, name, program_path = _resolve_project('/projects', 'myproj', BIN)
    assert (parent, name, program_path) == ('/projects', 'myproj', '/crackme.elf')


def test_program_path_uses_full_filename_not_stem():
    """The program is imported under its file name (with extension) at root."""
    _, _, program_path = _resolve_project(None, None, Path('/x/firmware.bin'))
    assert program_path == '/firmware.bin'
