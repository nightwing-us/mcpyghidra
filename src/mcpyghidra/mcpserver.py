from __future__ import annotations

# Standard Libraries
import socket
import struct
import sys
from datetime import (
    datetime,
    timedelta,
)
from enum import Enum
from threading import (
    RLock,
    Thread,
)
import time
from typing import (
    Any,
    Callable,
    List,
    TYPE_CHECKING,
)

# Third Party Libraries
import uvicorn

# Our Libraries
from mcpyghidra.backend import GhidraError, OverwritePolicy  # noqa: F401 — re-exported for plugin consumers
from mcpyghidra.server import ThreadedServer  # noqa: F401 — re-exported; also used in start()

if TYPE_CHECKING:
    # Third Party Libraries
    from ghidra.framework.plugintool import PluginTool  # type: ignore[attr-defined]
    from ghidra.program.database import ProgramDB  # type: ignore[import-not-found]
    from ghidra.program.model.listing import Program  # type: ignore[import-not-found]
    from pyghidra_decaf.stubs.jplugin import DecafPlugin as JDecafPlugin

    # Our Libraries
    from mcpyghidra.backend import GhidraBackend, HeadlessBackend


def _Msg():
    """Return the Ghidra Msg class, imported lazily at call time.

    Using a late import here (instead of module-level ``from ghidra.util import Msg``)
    avoids a hard JVM dependency when mcpserver.py is imported in test environments
    before pyghidra has started the JVM.
    """
    from ghidra.util import Msg  # type: ignore[import-not-found]

    return Msg


class MCPPortManager:
    """Manages ephemeral port assignments for MCP servers in GUI mode.

    Ports are assigned at runtime starting from the configured base port.
    No state is persisted to program options — each Ghidra session starts fresh.
    """

    _instance = None

    @staticmethod
    def get_instance(
        plugin_tool: PluginTool, plugin: 'JDecafPlugin', port_start: int = 6050
    ) -> 'MCPPortManager':
        if MCPPortManager._instance is None:
            MCPPortManager._instance = MCPPortManager(
                plugin_tool, plugin, port_start=port_start
            )
        return MCPPortManager._instance

    def __init__(
        self, plugin_tool: PluginTool, plugin: 'JDecafPlugin', port_start: int = 6050
    ):
        self._plugin = plugin
        self._program_path_to_port: dict[str, int] = {}
        self._port_start = port_start

    @classmethod
    def get_port_by_path(cls, program_path: str) -> int | None:
        """Get the MCP port assigned to a program by its project path."""
        if cls._instance is None:
            return None
        return cls._instance._program_path_to_port.get(program_path)

    def assign_port(self, program: 'ProgramDB') -> int:
        """Assign the next available port to a program.

        If the program already has a port assigned this session, return it.
        Otherwise assign the lowest available port starting from _port_start.
        """
        domain_file = program.getDomainFile()
        path = str(domain_file.getPathname())

        if path in self._program_path_to_port:
            return self._program_path_to_port[path]

        used_ports = set(self._program_path_to_port.values())
        port = self._port_start
        while port in used_ports:
            port += 1

        self._program_path_to_port[path] = port
        _Msg().info(self._plugin, f'Assigned port {port} to program {path}')
        return port

    def free_port(self, program: 'ProgramDB') -> None:
        """Release a program's port assignment."""
        path = str(program.getDomainFile().getPathname())
        if path in self._program_path_to_port:
            del self._program_path_to_port[path]
            _Msg().info(self._plugin, f'Freed port for {path}')


class GhidraMcpServerState(Enum):
    STOPPED = 0
    STARTING = 1
    RUNNING = 2
    STOPPING = 3
    ERROR = sys.maxsize


class GhidraMcpServer:
    StartStopHandler = Callable[['GhidraMcpServer', GhidraMcpServerState], None]

    def __init__(
        self,
        plugin: 'JDecafPlugin',
        plugin_tool: 'PluginTool',
        host: str = '',
        port_start: int = 6050,
    ) -> None:
        _msg = _Msg()
        _msg.info(plugin, 'GhidraMcpServer init Started')
        self.plugin = plugin
        self.plugin_tool = plugin_tool
        self._port_manager = MCPPortManager.get_instance(
            plugin_tool, plugin, port_start=port_start
        )

        self.host = host
        self.port: int | None = None
        self.state = GhidraMcpServerState.STOPPED
        self._watchers: List[GhidraMcpServer.StartStopHandler] = []
        self._lock = RLock()

        # FastAPI/MCP app objects are populated lazily in start(); keep
        # them as Optional[Any] (FastAPI/FastMCP types pulled in only at
        # runtime so we don't tie this module to those imports).
        self._app: Any = None
        self._mcp: Any = None
        self._server_thread: Thread | None = None
        self._server: ThreadedServer | None = None
        self._socket: socket.socket | None = None

        # Set by create_headless(); None in plugin mode (PluginBackend
        # is created on demand in _get_backend()).
        self._backend: 'GhidraBackend | None' = None

        _msg.info(plugin, 'GhidraMcpServer init done')

    @classmethod
    def create_headless(
        cls, backend: 'HeadlessBackend', host: str = ''
    ) -> 'GhidraMcpServer':
        """Alternative constructor for headless mode.

        Bypasses __init__ to avoid plugin/plugin_tool/MCPPortManager dependencies.
        Sets all attributes that __init__ would set, using safe headless defaults.
        """
        # The factory bypass intentionally substitutes plugin-mode types
        # with headless-friendly stand-ins; mypy can't see this through
        # the class-level attribute types so suppress per-line.
        instance = object.__new__(cls)
        instance.plugin = 'MCPyGhidra-headless'  # type: ignore[assignment]
        instance.plugin_tool = None  # type: ignore[assignment]
        instance._backend = backend
        instance._port_manager = None  # type: ignore[assignment]

        instance.host = host
        instance.port = None
        instance.state = GhidraMcpServerState.STOPPED
        instance._watchers = []
        instance._lock = RLock()

        instance._app = None
        instance._mcp = None
        instance._server_thread = None
        instance._server = None
        instance._socket = None

        return instance

    def _update_state(self, state: GhidraMcpServerState) -> None:
        with self._lock:
            self.state = state

            for handler in self._watchers:
                handler(self, self.state)

    def start(self, host: str | None = None, port: int | None = None) -> None:
        if self._server_thread is None:
            self._update_state(GhidraMcpServerState.STARTING)

            # Get or create backend, then build app with all tools/resources registered.
            # Pass get_port as a lambda so server://info always reflects the live port.
            # self.port is None until the socket is bound (a few lines below), so the
            # lambda reads self.port lazily at request time — not at app-creation time.
            from .server import create_mcp_app

            backend = self._get_backend()
            self._app, self._mcp = create_mcp_app(backend, get_port=lambda: self.port)

            host = host or self.host
            if port:
                pass  # explicit port provided — use it as-is
            elif self.port:
                port = self.port
            elif self._port_manager is not None:
                port = self._port_manager.assign_port(self.current_program)
            else:
                port = 0  # headless auto-assign: let OS pick a free port

            _Msg().info(self.plugin, f'Starting MCP Server on {host}:{port}')
            self.host = host
            self.port = port

            # Create socket with SO_REUSEADDR and SO_LINGER for immediate port reuse
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)
            )
            self._socket.bind((host, port))
            self._socket.listen(100)
            self._socket.setblocking(False)
            # Update self.port with the OS-assigned port (important when port=0)
            self.port = self._socket.getsockname()[1]

            # Don't pass host/port to config when providing pre-bound sockets
            config = uvicorn.Config(self._app, log_level='info', lifespan='on')
            self._server = ThreadedServer(config=config, sockets=[self._socket])

            self._server_thread = Thread(target=self._server.run, daemon=True)
            self._server_thread.start()
            req_time = datetime.now()
            while not self._server.started:
                time.sleep(1e-3)
                if datetime.now() - req_time > timedelta(seconds=1):
                    _Msg().error(self.plugin, 'Timed out waiting for server to start.')
                    self.stop()
                    return
            print(f'MCP Server started: http://{self.host}:{self.port}/mcp')
            print(f'OpenAPI: http://{self.host}:{self.port}/openapi.json')
            self._update_state(GhidraMcpServerState.RUNNING)
        else:
            _Msg().warning(self.plugin, 'Ghidra MCP already started')

    def stop(self) -> None:
        if self._server_thread is not None and self._server is not None:
            self._update_state(GhidraMcpServerState.STOPPING)
            self._server.should_exit = True
            self._server_thread.join(timeout=1.0)
            if self._server_thread.is_alive():
                self._server.force_exit = True
                self._server_thread.join(timeout=4.0)
            if self._server_thread.is_alive():
                _Msg().error(self.plugin, 'Could not stop MCP server.')

            # Explicitly close uvicorn server sockets
            try:
                if hasattr(self._server, 'servers') and self._server.servers:
                    for server in self._server.servers:
                        if server and hasattr(server, 'close'):
                            server.close()
            except Exception as e:
                _Msg().warn(self.plugin, f'Error closing server sockets: {e}')

            # Explicitly close main socket
            if self._socket is not None:
                try:
                    self._socket.close()
                except Exception as e:
                    _Msg().warn(self.plugin, f'Error closing main socket: {e}')
                finally:
                    self._socket = None

            self._server = None
            self._server_thread = None
            self._mcp = None

            self._update_state(GhidraMcpServerState.STOPPED)

    def add_watcher(self, watcher: StartStopHandler) -> None:
        self._watchers.append(watcher)

    def remove_watcher(self, watcher: StartStopHandler) -> None:
        try:
            self._watchers.remove(watcher)
        except ValueError:
            ...

    @property
    def running(self) -> bool:
        return (
            self._server_thread is not None
            and self._server is not None
            and self._server_thread.is_alive()
            and self._server.started
        )

    @property
    def is_headless(self) -> bool:
        """True when running without Ghidra GUI (delegates to backend)."""
        return self._get_backend().is_headless

    @property
    def current_program(self) -> 'Program':
        backend = self._backend
        if backend is not None:
            return backend.program
        from ghidra.app.services import ProgramManager

        pm = self.plugin_tool.getService(ProgramManager.class_)
        if pm is None:
            raise GhidraError('Ghidra Program Manager service not available')
        prog = pm.getCurrentProgram()
        if prog is None:
            raise GhidraError('No program is open')
        return prog

    def _get_backend(self) -> 'GhidraBackend':
        """Return the active GhidraBackend for delegation to tools/.

        In headless mode self._backend is already set via create_headless().
        In plugin mode a PluginBackend is created on demand and cached so that
        a single instance is reused across calls (important for dialog state).
        """
        if self._backend is not None:
            return self._backend
        # Plugin mode — create PluginBackend on demand and cache it
        from .backend import PluginBackend

        self._backend = PluginBackend(self.plugin_tool, self.plugin)
        return self._backend
