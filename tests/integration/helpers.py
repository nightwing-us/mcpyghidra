"""Integration test helpers — assertion utilities and test data finders."""
from __future__ import annotations

import contextlib
import os
from typing import Any

import anyio


@contextlib.contextmanager
def open_analyzed_program(pyghidra, binary_path: str, project_dir: str):
    """Import + analyze a binary via the modern pyghidra API, yield the Program.

    Mirrors the headless launcher's open path (open_project + program_loader /
    program_context) instead of the deprecated open_program. Creates the project
    under ``project_dir`` (use a tmp dir so the fixtures tree stays clean) and
    yields the analyzed Program for direct backend/tool calls.
    """
    from ghidra.program.util import GhidraProgramUtilities

    name = os.path.basename(binary_path)
    program_path = '/' + name
    with pyghidra.open_project(project_dir, f'{name}_proj', create=True) as project:
        if project.getProjectData().getFile(program_path) is None:
            loader = (
                pyghidra.program_loader()
                .project(project)
                .source(str(binary_path))
                .name(name)
                .projectFolderPath('/')
            )
            with loader.load() as load_results:
                load_results.save(pyghidra.task_monitor())
        with pyghidra.program_context(project, program_path) as program:
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                pyghidra.analyze(program)
            yield program


def run_async(async_fn, *args, **kwargs):
    """Run an async tool function synchronously for tests."""
    async def wrapper():
        return await async_fn(*args, **kwargs)
    return anyio.run(wrapper)


def assert_valid_address(addr: str) -> None:
    """Assert addr is a valid hex string."""
    assert isinstance(addr, str), f'Expected string, got {type(addr).__name__}'
    assert addr.startswith('0x') or addr.startswith('-0x'), (
        f'Expected hex address, got {addr!r}'
    )
    int(addr, 16)  # Raises ValueError if invalid


def assert_non_empty(value: Any) -> None:
    """Assert value is not None and not empty."""
    assert value is not None, 'Value is None'
    if hasattr(value, '__len__'):
        assert len(value) > 0, f'Value is empty: {value!r}'
