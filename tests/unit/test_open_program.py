"""Unit tests for the open_program tool (GUI-only).

The actual open_program_sync logic requires a live Ghidra GUI and cannot be
unit tested here.  These tests cover:

1. Headless mode raises ValueError immediately.
2. _find_file_by_name helper — found at root level.
3. _find_file_by_name helper — not found → returns None.
4. _find_file_by_name helper — found recursively in a subfolder.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mcpyghidra.tools.open_program import _find_file_by_name, open_program_sync


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_backend(is_headless: bool) -> MagicMock:
    backend = MagicMock()
    backend.is_headless = is_headless
    return backend


def _make_domain_file(name: str) -> MagicMock:
    f = MagicMock()
    f.getName.return_value = name
    return f


def _make_folder(files: list, subfolders: list) -> MagicMock:
    folder = MagicMock()
    folder.getFiles.return_value = files
    folder.getFolders.return_value = subfolders
    return folder


# ---------------------------------------------------------------------------
# open_program_sync — headless guard
# ---------------------------------------------------------------------------

def test_open_program_raises_in_headless() -> None:
    """open_program_sync must raise ValueError immediately in headless mode."""
    backend = _make_mock_backend(is_headless=True)
    with pytest.raises(ValueError, match='GUI mode'):
        open_program_sync(backend, '/tmp/firmware.bin')


# ---------------------------------------------------------------------------
# _find_file_by_name
# ---------------------------------------------------------------------------

def test_find_file_by_name_found() -> None:
    """File found at root level returns the matching DomainFile."""
    target = _make_domain_file('crackme.elf')
    other = _make_domain_file('other.bin')
    folder = _make_folder([target, other], [])

    result = _find_file_by_name(folder, 'crackme.elf')

    assert result is target


def test_find_file_by_name_not_found() -> None:
    """Returns None when no file matches the given name."""
    f1 = _make_domain_file('firmware.bin')
    folder = _make_folder([f1], [])

    result = _find_file_by_name(folder, 'nonexistent.elf')

    assert result is None


def test_find_file_by_name_recursive() -> None:
    """File nested in a subfolder is found via recursive traversal."""
    nested = _make_domain_file('deep.elf')
    subfolder = _make_folder([nested], [])
    root = _make_folder([], [subfolder])

    result = _find_file_by_name(root, 'deep.elf')

    assert result is nested


def test_find_file_by_name_prefers_first_match() -> None:
    """When the same name appears at multiple levels, the first (root) match wins."""
    root_match = _make_domain_file('dup.elf')
    sub_match = _make_domain_file('dup.elf')
    subfolder = _make_folder([sub_match], [])
    root = _make_folder([root_match], [subfolder])

    result = _find_file_by_name(root, 'dup.elf')

    assert result is root_match


def test_find_file_by_name_empty_tree() -> None:
    """Empty folder tree returns None."""
    root = _make_folder([], [])
    assert _find_file_by_name(root, 'anything.elf') is None
