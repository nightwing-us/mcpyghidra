"""Open or import a program in Ghidra GUI mode."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcpyghidra.backend import GhidraBackend


def open_program_sync(
    backend: 'GhidraBackend',
    path_or_name: str,
    wait: bool = True,
    timeout: int = 300,
) -> dict[str, Any]:
    """Open a binary in a new Ghidra CodeBrowser, returning new server info.

    For file paths: imports into the project then opens in new CodeBrowser.
    For existing project binary names: opens in new CodeBrowser.

    Only works in GUI mode (PluginBackend).
    """
    if backend.is_headless:
        raise ValueError('open_program is only available in GUI mode')

    # backend._tool is on PluginBackend; the is_headless guard above
    # ensures we only get here in GUI mode.
    tool = backend._tool  # type: ignore[attr-defined]

    project = tool.getProject()
    project_data = project.getProjectData()
    tool_services = project.getToolServices()

    file_path = Path(path_or_name)

    result_container: list[dict[str, Any] | None] = [None]
    error_container: list[str | None] = [None]

    def _do_open() -> None:
        """Run the import+open on a background thread.

        Ghidra API calls are thread-safe (transaction-based).
        Tool launch via launchDefaultTool is handled internally by Ghidra
        which dispatches to the EDT as needed.
        """
        try:
            from java.util import Collections  # type: ignore[import-not-found]

            # Check if binary already exists in the project by filename
            existing = _find_file_by_name(
                project_data.getRootFolder(),
                file_path.name if file_path.is_file() else path_or_name,
            )

            if existing is not None:
                # Already in project — just open in new CodeBrowser
                domain_file = existing
                arch = None
            elif file_path.is_file():
                # Import from disk, save to project
                from ghidra.app.util.importer import AutoImporter, MessageLog  # type: ignore[import-not-found]
                from ghidra.util.task import TaskMonitor  # type: ignore[import-not-found]
                from java.io import File as JFile  # type: ignore[import-not-found]
                from java.lang import Object as JObject  # type: ignore[import-not-found]
                from jpype import JString  # type: ignore[import-untyped]

                log = MessageLog()
                consumer = JObject()
                load_results = AutoImporter.importByUsingBestGuess(
                    JFile(str(file_path)),
                    project,
                    JString('/'),
                    consumer,
                    log,
                    TaskMonitor.DUMMY,
                )
                if load_results is None or load_results.size() == 0:
                    error_container[0] = f'Failed to import {path_or_name}: {log}'
                    return

                loaded = load_results.getPrimary()
                domain_file = loaded.save(TaskMonitor.DUMMY)
                program = loaded.getDomainObject()
                arch = str(program.getLanguage().getLanguageID())
                load_results.close()
            else:
                error_container[0] = (
                    f'File not found and not in project: {path_or_name}'
                )
                return

            # Open in a new CodeBrowser
            tool_services.launchDefaultTool(Collections.singletonList(domain_file))

            result_container[0] = {
                'name': str(domain_file.getName()),
                'path': str(domain_file.getPathname()),
                'arch': arch,
            }
        except Exception as exc:
            error_container[0] = str(exc)

    # Run on background thread to avoid blocking the MCP event loop
    t = threading.Thread(target=_do_open, daemon=True)
    t.start()

    # Poll for completion and new server port
    from mcpyghidra.mcpserver import MCPPortManager  # type: ignore[import-not-found]

    deadline = time.monotonic() + timeout
    new_port: int | None = None

    while time.monotonic() < deadline:
        if error_container[0]:
            raise ValueError(error_container[0])

        if result_container[0] is not None:
            domain_path = result_container[0]['path']
            port = MCPPortManager.get_port_by_path(domain_path)
            if port is not None:
                new_port = port
                break

        time.sleep(0.5)

    if error_container[0]:
        raise ValueError(error_container[0])

    binary_name = result_container[0]['name'] if result_container[0] else path_or_name

    if result_container[0] is None:
        raise ValueError(f'Timed out waiting for Ghidra to open {path_or_name}')

    if new_port is None and wait:
        return {
            'status': 'timeout',
            'binary': binary_name,
            'new_server': None,
            'analysis_status': 'unknown',
            'message': f'Opened {binary_name} but MCP server did not start within {timeout}s',
        }

    status = 'ready' if (wait and new_port) else 'analyzing'

    return {
        'status': status,
        'binary': binary_name,
        'architecture': result_container[0].get('arch'),
        'new_server': {'host': '127.0.0.1', 'port': new_port} if new_port else None,
        'analysis_status': 'complete' if (wait and new_port) else 'analyzing',
        'message': f'Opened {binary_name} — new MCP server on port {new_port}'
        if new_port
        else f'Opened {binary_name} — check project://binaries for server status',
    }


def _find_file_by_name(folder: Any, name: str) -> Any:
    """Recursively search a Ghidra project folder tree for a domain file by name."""
    for f in folder.getFiles():
        if str(f.getName()) == name:
            return f
    for sub in folder.getFolders():
        result = _find_file_by_name(sub, name)
        if result is not None:
            return result
    return None


async def open_program(
    backend: 'GhidraBackend',
    path_or_name: str,
    wait: bool = True,
    timeout: int = 300,
) -> dict[str, Any]:
    """Async wrapper around open_program_sync."""
    import anyio

    return await anyio.to_thread.run_sync(
        lambda: open_program_sync(backend, path_or_name, wait, timeout)
    )
