"""MCPyGhidra headless MCP server.

Launch Ghidra headless, open a binary, run auto-analysis, and start
the MCP server. Blocks until interrupted.

Usage:
    mcpyghidra-headless /path/to/elf [--host 127.0.0.1] [--port 6050-6059]
    python -m mcpyghidra.headless /path/to/elf

Prints JSON readiness signal to stdout when the server is ready:
    {"status": "ready", "host": "127.0.0.1", "port": 6050, "binary": "/path/to/elf"}

This is the contract that test harnesses and MCP client CLIs rely on.

Requires Ghidra 11.1+ (pyghidra was integrated starting ~11.1).
MCPyGhidra targets Ghidra 11.x and 12.0+.
"""

from __future__ import annotations

import argparse
import os
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


def _resolve_startup(args) -> tuple[Path, list[int]]:
    """Validate args before the pyghidra import. Returns (binary_path, candidates).

    Raises StartupError(reason, detail, remediation) on any pre-import failure and
    sets GHIDRA_INSTALL_DIR from --ghidra-dir when given.
    """
    from mcpyghidra.cli_status import StartupError
    from mcpyghidra.portspec import parse_port_spec

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        raise StartupError(
            'binary_not_found',
            f'binary not found: {binary_path}',
            f'binary not found: {binary_path}',
        )

    try:
        candidates = parse_port_spec(args.port)
    except ValueError as e:
        raise StartupError(
            'bad_port', f'invalid --port {args.port!r}: {e}', 'use N, N-M, or 0'
        ) from e

    if args.ghidra_dir:
        gdir = Path(args.ghidra_dir).resolve()
        if not (gdir / 'Ghidra' / 'application.properties').is_file():
            raise StartupError(
                'missing_install_dir',
                f'not a Ghidra install: {gdir}',
                f'pass --ghidra-dir <dir> or set GHIDRA_INSTALL_DIR. Searched: {gdir}',
            )
        os.environ['GHIDRA_INSTALL_DIR'] = str(gdir)
    elif not os.environ.get('GHIDRA_INSTALL_DIR'):
        raise StartupError(
            'missing_install_dir',
            'GHIDRA_INSTALL_DIR not set and --ghidra-dir not given',
            'pass --ghidra-dir <dir> or set GHIDRA_INSTALL_DIR',
        )

    return binary_path, candidates


def _run_server(program, host: str, candidates: list[int], binary_path: Path) -> None:
    """Start the MCP server for an opened program and block until interrupted.

    Returns when interrupted (SIGTERM/SIGINT -> KeyboardInterrupt) so the caller
    can persist the program on the way out.
    """
    import time

    from mcpyghidra.cli_status import emit_error, emit_ready

    print(f'Starting MCP server on {host} (ports {candidates})...', file=sys.stderr)
    try:
        server = _create_server(program, host, candidates)
    except OSError as e:
        sys.exit(
            emit_error(
                'port_unavailable',
                f'could not bind a port in {candidates}: {e}',
                remediation='pass a --port range (e.g. 6150-6159) or omit --port',
            )
        )

    actual_port = server['port']
    if actual_port is None or actual_port <= 0:
        sys.exit(
            emit_error(
                'port_unavailable',
                f'server port not assigned correctly (got {actual_port!r})',
            )
        )

    emit_ready(host, actual_port, str(binary_path))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('Shutting down...', file=sys.stderr)
        server['stop']()


def _main() -> None:
    parser = argparse.ArgumentParser(
        description='MCPyGhidra headless MCP server',
    )
    parser.add_argument(
        'binary',
        help='Path to the binary file to analyze (positional).',
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host to bind MCP server (default: 127.0.0.1)',
    )
    parser.add_argument(
        '--port',
        type=str,
        default='6050-6059',
        help=(
            'Port or inclusive range for the MCP server (default: 6050-6059; '
            'a single port is strict; 0 = OS auto-assign). Binds the first free port.'
        ),
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
    parser.add_argument(
        '--ghidra-dir',
        default=None,
        help='Ghidra installation directory. Overrides GHIDRA_INSTALL_DIR. '
        'If neither is set, the launcher errors.',
    )
    args = parser.parse_args()

    from mcpyghidra.cli_status import StartupError, emit_error

    try:
        binary_path, port_candidates = _resolve_startup(args)
    except StartupError as e:
        sys.exit(emit_error(e.reason, e.detail, remediation=e.remediation))

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
        sys.exit(
            emit_error(
                'jvm_not_found',
                f'failed to start the JVM: {e}',
                remediation='no compatible JDK found; Ghidra 12 needs JDK 21+ on PATH or JAVA_HOME',
            )
        )

    from ghidra.framework import Application

    print(
        f'Using Ghidra {Application.getApplicationVersion()} '
        f'({os.environ["GHIDRA_INSTALL_DIR"]}) · binary {binary_path.name}',
        file=sys.stderr,
    )

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
    try:
        with pyghidra.open_project(
            project_parent, project_name, create=True
        ) as project:
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
                    _run_server(program, args.host, port_candidates, binary_path)
                finally:
                    # We own the save now (open_program used to do it). This runs on
                    # the SIGTERM->KeyboardInterrupt unwind, persisting to the project.
                    program.save('MCPyGhidra session', pyghidra.task_monitor())
    except Exception as e:
        sys.exit(
            emit_error(
                'open_failed', f'failed to open or analyze {binary_path.name}: {e}'
            )
        )


def main() -> None:
    from mcpyghidra.cli_status import emit_error

    try:
        _main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print('Interrupted before ready.', file=sys.stderr)
        sys.exit(130)
    except Exception as e:  # pragma: no cover - last-resort guard
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(emit_error('internal', f'unexpected error: {e}'))


def _create_server(program, host: str, candidates: list[int]) -> dict:
    """Create and start the MCP server with HeadlessBackend.

    Uses create_mcp_app from server.py directly, then starts uvicorn
    with a pre-bound socket (to support port=0 auto-assign and range specs).

    Returns a dict with 'port' (int) and 'stop' (callable).
    Raises OSError if no candidate port in `candidates` can be bound.
    """
    import threading
    import time

    from mcpyghidra.backend import HeadlessBackend
    from mcpyghidra.portspec import bind_listen_socket
    from mcpyghidra.server import create_mcp_app, ThreadedServer
    import uvicorn

    backend = HeadlessBackend(program)

    # port_container is a mutable one-element list shared between create_mcp_app()
    # and the socket-bind below.  The server://info resource closure reads
    # port_container[0] at request time, so it always returns the live port even
    # though the socket is bound after the app is created.
    port_container: list[int | None] = [None]
    app, _mcp = create_mcp_app(backend, get_port=lambda: port_container[0])

    sock, actual_port = bind_listen_socket(host, candidates)
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
            from mcpyghidra.cli_status import emit_error

            server.should_exit = True
            server_thread.join(timeout=2.0)
            sock.close()
            sys.exit(emit_error('internal', 'MCP server did not start within 5s'))

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
