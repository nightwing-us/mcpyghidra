"""MCPyGhidra headless MCP server.

Launch Ghidra headless, open a binary, run auto-analysis, and start
the MCP server. Blocks until interrupted.

Usage:
    mcpyghidra-headless --binary /path/to/elf [--host 127.0.0.1] [--port 6050]
    python -m mcpyghidra.headless --binary /path/to/elf

Prints JSON readiness signal to stdout when the server is ready:
    {"status": "ready", "host": "127.0.0.1", "port": 6050, "binary": "/path/to/elf"}

This is the contract that test harnesses and MCP client CLIs rely on.

Requires Ghidra 11.1+ (pyghidra was integrated starting ~11.1).
MCPyGhidra targets Ghidra 11.x and 12.0+.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
from pathlib import Path


def _resolve_project(
    project_dir: str | None,
    project_name: str | None,
    binary_path: Path,
) -> tuple[str, str, str]:
    """Resolve project location/name and the program's in-project path.

    ``pyghidra.open_project(parent, name)`` creates a standalone (non-nested)
    project at ``<parent>/<name>`` — the same layout the Ghidra GUI uses, so a
    project reopens cleanly on a subsequent launch. With no ``--project-dir`` we
    mirror the legacy ``open_program`` default: an auto-named ``<binary>_ghidra``
    project beside the binary.

    Returns ``(project_parent, project_name, program_path)``. The program is
    imported at the project root under its file name, so its project path is
    ``/<binary filename>``.
    """
    project_parent = project_dir or str(binary_path.parent)
    name = project_name or f'{binary_path.stem}_ghidra'
    program_path = '/' + binary_path.name
    return project_parent, name, program_path


def _run_server(program, host: str, port: int, binary_path: Path) -> None:
    """Start the MCP server for an opened program and block until interrupted.

    Returns when interrupted (SIGTERM/SIGINT -> KeyboardInterrupt) so the caller
    can persist the program on the way out.
    """
    import time

    print(f'Starting MCP server on {host}:{port}...', file=sys.stderr)
    server = _create_server(program, host, port)

    # Verify port was actually assigned (required when --port 0 is used)
    actual_port = server['port']
    if actual_port is None or actual_port <= 0:
        print(
            f'Error: server port not assigned correctly (got {actual_port!r})',
            file=sys.stderr,
        )
        sys.exit(1)

    status = {
        'status': 'ready',
        'host': host,
        'port': actual_port,
        'binary': str(binary_path),
    }
    # JSON ready signal on stdout (parsed by tests and MCP client CLIs)
    print(json.dumps(status), flush=True)

    try:
        # Block until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('Shutting down...', file=sys.stderr)
        server['stop']()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCPyGhidra headless MCP server',
    )
    parser.add_argument(
        '--binary',
        required=True,
        help='Path to binary file to analyze',
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind MCP server (default: 127.0.0.1)',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=6050,
        help='Port for MCP server (default: 6050, 0 for auto-assign)',
    )
    parser.add_argument(
        '--project-dir',
        default=None,
        help='Directory for the Ghidra project. Default: an auto-named project '
        '"<binary>_ghidra" beside the binary (still persisted on graceful exit).',
    )
    parser.add_argument(
        '--project-name',
        default=None,
        help='Name of the Ghidra project (default: derived from the binary).',
    )
    args = parser.parse_args()

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        print(f'Error: binary not found: {binary_path}', file=sys.stderr)
        sys.exit(1)

    # Check prerequisites before expensive imports
    if not os.environ.get('GHIDRA_INSTALL_DIR'):
        print(
            'Error: GHIDRA_INSTALL_DIR environment variable not set.\n'
            '\n'
            'Set it to your Ghidra installation directory:\n'
            '  export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.3_PUBLIC\n'
            '\n'
            'Prerequisites:\n'
            '  1. Install Ghidra 11.1+ from https://ghidra-sre.org\n'
            '  2. pip install mcpyghidra pyghidra\n'
            '  3. export GHIDRA_INSTALL_DIR=/path/to/ghidra\n'
            '  4. mcpyghidra-headless --binary /path/to/elf',
            file=sys.stderr,
        )
        sys.exit(1)

    # Late imports — pyghidra starts the JVM
    import signal as _signal

    import pyghidra
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    # Persist analysis/edits on shutdown. By default the JVM grabs SIGINT/SIGTERM
    # and hard-terminates the process, which SKIPS our `finally: program.save()`
    # below — so changes are lost on any signal-based stop. Launch with -Xrs so
    # the JVM leaves signals to Python, and convert SIGTERM into KeyboardInterrupt
    # so SIGTERM (the signal a process supervisor sends to stop a background
    # task) unwinds the `with` blocks and the program is saved.
    # Empirically validated on Ghidra 12.0.4 + pyghidra 3.0.2/3.1.0: a function
    # rename survives SIGTERM with this change; without it the rename is lost.
    def _on_sigterm(signum, frame):  # noqa: ANN001, ARG001
        raise KeyboardInterrupt

    _signal.signal(_signal.SIGTERM, _on_sigterm)

    print('Starting Ghidra headless...', file=sys.stderr)
    try:
        _launcher = HeadlessPyGhidraLauncher()
        _launcher.add_vmargs('-Xrs')
        _launcher.start()
    except Exception as e:
        print(
            f'Error: Failed to start Ghidra headless: {e}\n'
            '\n'
            f'GHIDRA_INSTALL_DIR is set to: {os.environ.get("GHIDRA_INSTALL_DIR")}\n'
            'Make sure this points to a valid Ghidra installation.',
            file=sys.stderr,
        )
        sys.exit(1)

    print(f'Opening and analyzing {binary_path.name}...', file=sys.stderr)
    from ghidra.program.util import GhidraProgramUtilities

    project_parent, project_name, program_path = _resolve_project(
        args.project_dir,
        args.project_name,
        binary_path,
    )
    # Modern pyghidra API (open_program is deprecated). open_project +
    # program_loader (first run: import) / program_context (reopen) gives us
    # explicit control over the save, which the signal handling above relies on.
    with pyghidra.open_project(project_parent, project_name, create=True) as project:
        # First launch imports the binary into the project; later launches reopen
        # the existing program so prior analysis and edits are preserved.
        if project.getProjectData().getFile(program_path) is None:
            loader = (
                pyghidra
                .program_loader()
                .project(project)
                .source(str(binary_path))
                .name(binary_path.name)
                .projectFolderPath('/')
            )
            with loader.load() as load_results:
                load_results.save(pyghidra.task_monitor())

        with pyghidra.program_context(project, program_path) as program:
            # analyze() always re-analyzes; only run it when the program has not
            # been analyzed yet (fresh import) so reopens stay fast and keep edits.
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                pyghidra.analyze(program)
            try:
                _run_server(program, args.host, args.port, binary_path)
            finally:
                # We own the save now (open_program used to do it). This runs on
                # the SIGTERM->KeyboardInterrupt unwind, persisting to the project.
                program.save('MCPyGhidra session', pyghidra.task_monitor())


def _create_server(program, host: str, port: int) -> dict:
    """Create and start the MCP server with HeadlessBackend.

    Uses create_mcp_app from server.py directly, then starts uvicorn
    with a pre-bound socket (to support port=0 auto-assign).

    Returns a dict with 'port' (int) and 'stop' (callable).
    """
    import threading
    import time

    from mcpyghidra.backend import HeadlessBackend
    from mcpyghidra.server import create_mcp_app, ThreadedServer
    import uvicorn

    backend = HeadlessBackend(program)

    # port_container is a mutable one-element list shared between create_mcp_app()
    # and the socket-bind below.  The server://info resource closure reads
    # port_container[0] at request time, so it always returns the live port even
    # though the socket is bound after the app is created.
    port_container: list[int | None] = [None]
    app, _mcp = create_mcp_app(backend, get_port=lambda: port_container[0])

    # Create socket with SO_REUSEADDR and SO_LINGER for immediate port reuse
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    sock.bind((host, port))
    sock.listen(100)
    sock.setblocking(False)
    actual_port = sock.getsockname()[1]
    port_container[0] = actual_port  # now visible to server://info via the lambda

    config = uvicorn.Config(app, log_level='info', lifespan='on')
    server = ThreadedServer(config=config, sockets=[sock])

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server to start (up to 5 seconds)
    deadline = time.time() + 5.0
    while not server.started:
        time.sleep(1e-3)
        if time.time() > deadline:
            print('Error: timed out waiting for MCP server to start.', file=sys.stderr)
            server.should_exit = True
            server_thread.join(timeout=2.0)
            sock.close()
            sys.exit(1)

    def stop():
        server.should_exit = True
        server_thread.join(timeout=1.0)
        if server_thread.is_alive():
            server.force_exit = True
            server_thread.join(timeout=4.0)
        try:
            sock.close()
        except Exception:
            pass

    return {'port': actual_port, 'stop': stop}


if __name__ == '__main__':
    main()
