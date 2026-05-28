# Standard Libraries
import sys
from typing import (
    Any,
    List,
    TextIO,
    Tuple,
    Type,
)

# Third Party Libraries
from docking import ActionContext
from docking.action.builder import ActionBuilder
from ghidra.framework.options import (
    OptionType,
    SaveState,
)
from ghidra.program.model.listing import Program
from ghidra.util import Msg
from java.util.function import Consumer  # type: ignore[import-not-found]
from javax.swing import JLabel
from jpype.types import (  # type: ignore[import-untyped]
    JBoolean,
    JInt,
    JString,
)
from pyghidra_decaf.decaf.plugin import (
    DecafPlugin,
    DecafProgramPlugin,
)

from .mcpserver import (
    GhidraMcpServer,
    GhidraMcpServerState,
)


class StdoutInterceptor:
    """
    Necessary because _PyhidraStdout/_PyGhidraStdout implementation isn't fully compliant with
    sys.stdout and causes exceptions when uvicorn initializes
    Sometimes sys.stdout becomes null?
    """

    def __init__(self, original_stdout: TextIO | None = None):
        self.original_stdout = original_stdout or sys.stdout

    def write(self, data: str) -> int:
        # Pass it through to the original stdout
        Msg.info('stdout', str(data))
        try:
            return self.original_stdout.write(data)
        except Exception:
            return 0

    def flush(self) -> None:
        try:
            self.original_stdout.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        return True

    def __getattr__(self, attr: str) -> Any:
        """Delegate attribute access to original stdout."""
        return getattr(self.original_stdout, attr)


# _mcp_server: GhidraMcpServer | None = None


class MCPyGhidraPlugin(DecafProgramPlugin):
    OPTION_CATEGORY_NAME = 'MCPyGhidra'
    HOST_OPTION_NAME = 'MCP Server Bind Address'
    PORT_OPTION_NAME = 'MCP Server Port'
    AUTOSTART_OPTION_NAME = 'Automatically Start MCP Server'
    AUTORESUME_OPTION_NAME = 'Automatically Resume MCP Server'
    OVERWRITE_POLICY_OPTION_NAME = 'AI Overwrite Policy'
    HOST_DEFAULT = '127.0.0.1'
    PORT_DEFAULT = 6050
    AUTO_MCP_DEFAULT = True
    OVERWRITE_POLICY_DEFAULT = 'Ask'
    STATE_MCP_RUNNING = 'MCPyGhidra.MCP_Running'

    def __init__(self, plugin: 'MCPyGhidraPlugin') -> None:
        """
        Initialize a new Ghidra _plugin.
        """
        Msg.debug('MCPyGhidraPlugin', f'__init__({plugin})')
        super().__init__(plugin)  # type: ignore[arg-type]

        self._previously_running = False

        Msg.trace(
            self._plugin,
            f'Getting options group: {MCPyGhidraPlugin.OPTION_CATEGORY_NAME}',
        )
        options = self.tool.getOptions(MCPyGhidraPlugin.OPTION_CATEGORY_NAME)  # type: ignore[call-arg]

        Msg.trace(self._plugin, 'Registering options 1...')
        options.registerOption(
            MCPyGhidraPlugin.HOST_OPTION_NAME,
            OptionType.STRING_TYPE,
            JString @ MCPyGhidraPlugin.HOST_DEFAULT,
            None,
            'The address the MCP server will bind to.',
        )
        options.registerOption(
            MCPyGhidraPlugin.PORT_OPTION_NAME,
            OptionType.INT_TYPE,
            JInt @ MCPyGhidraPlugin.PORT_DEFAULT,
            None,
            'The base network port number for embedded MCP servers.',
        )
        options.registerOption(
            MCPyGhidraPlugin.AUTOSTART_OPTION_NAME,
            OptionType.BOOLEAN_TYPE,
            JBoolean @ MCPyGhidraPlugin.AUTO_MCP_DEFAULT,
            None,
            "Start MCP Server Automatically for every program that's opened",
        )
        options.registerOption(
            MCPyGhidraPlugin.AUTORESUME_OPTION_NAME,
            OptionType.BOOLEAN_TYPE,
            JBoolean @ True,
            None,
            'Automatically resume MCP server if it was previously running.',
        )
        options.registerOption(
            MCPyGhidraPlugin.OVERWRITE_POLICY_OPTION_NAME,
            OptionType.STRING_TYPE,
            JString @ MCPyGhidraPlugin.OVERWRITE_POLICY_DEFAULT,
            None,
            'How to handle AI overwrites of user-defined symbols: '
            "'Ask' (show dialog), 'Always Allow', or 'Always Skip'",
        )

        # Read configured base port from tool options
        configured_port = int(
            options.getInt(
                MCPyGhidraPlugin.PORT_OPTION_NAME,
                JInt @ MCPyGhidraPlugin.PORT_DEFAULT,
            )
        )
        self._mcp_server: GhidraMcpServer = GhidraMcpServer(
            self._plugin, self.tool, port_start=configured_port
        )

        # Initialize GUI components only if not in headless mode
        self._init_gui_components()

        sys.stdout = StdoutInterceptor(sys.stdout)
        sys.stderr = StdoutInterceptor(sys.stderr)

        # self.tool.p

        Msg.trace(self._plugin, '__init__() complete')

    def _init_gui_components(self) -> None:
        """Initialize GUI-specific components. Skipped in headless mode."""
        if self._mcp_server.is_headless:
            Msg.info(
                self._plugin, 'Headless mode detected - skipping GUI initialization'
            )
            return

        try:
            startName = 'Start MCP Server'
            stopName = 'Stop MCP Server'

            Msg.debug(self._plugin, 'Building Start MCP action')
            self._action_startMCP = (
                ActionBuilder(startName, self.name)
                .onAction(Consumer @ self._start_mcp_server)
                .menuPath('MCP Server', startName)
                .menuGroup(self.name)
                .buildAndInstall(self.tool)
            )
            self._docking_actions.append(self._action_startMCP)

            Msg.info(self._plugin, 'Building Stop MCP action')
            self._action_stopMCP = (
                ActionBuilder(startName, self.name)
                .onAction(Consumer @ self._stop_mcp_server)
                .menuPath('MCP Server', stopName)
                .menuGroup(self.name)
                .buildAndInstall(self.tool)
            )
            self._docking_actions.append(self._action_stopMCP)

            self._action_startMCP.setEnabled(not self._mcp_server.running)
            self._action_stopMCP.setEnabled(self._mcp_server.running)

            # Create the JLabel to show MCP status
            mcp_label_text = f'MCP {self._mcp_server.state.name.capitalize()}'
            if self._mcp_server.state == GhidraMcpServerState.RUNNING:
                mcp_label_text += f': {self._mcp_server.port}'
            else:
                mcp_label_text += ' ' * 12

            self._mcp_status_label = JLabel(mcp_label_text)

            # Get the status bar from the plugin_tool
            self.tool.addStatusComponent(self._mcp_status_label, True, True)

            def handle_server_update(_: GhidraMcpServer, state: GhidraMcpServerState):
                self._action_startMCP.setEnabled(state == GhidraMcpServerState.STOPPED)
                self._action_stopMCP.setEnabled(state == GhidraMcpServerState.RUNNING)

                mcp_label_text = f'MCP {state.name.capitalize()}'
                if state == GhidraMcpServerState.RUNNING:
                    mcp_label_text += f': {self._mcp_server.port}'
                self._mcp_status_label.setText(mcp_label_text)

            self._mcp_server.add_watcher(handle_server_update)
        except Exception as e:
            Msg.warn(self._plugin, f'Failed to initialize GUI components: {e}')

    def _start_mcp_server(self, action_context: ActionContext) -> None:
        self.__start_mcp_server()

    def __start_mcp_server(self) -> None:
        try:
            Msg.info(self._plugin, 'Start MCP server clicked')

            options = self.tool.getOptions(MCPyGhidraPlugin.OPTION_CATEGORY_NAME)  # type: ignore[call-arg]
            host_addr = str(
                options.getString(
                    MCPyGhidraPlugin.HOST_OPTION_NAME,
                    JString @ MCPyGhidraPlugin.HOST_DEFAULT,
                )
            )

            self._mcp_server.start(host_addr)
            # Msg.info(self._plugin, 'MCP Server started')
            # self._action_startMCP.setEnabled(not self._mcp_server.running)
            # self._action_stopMCP.setEnabled(self._mcp_server.running)
            self._previously_running = True
            self.tool.setConfigChanged(True)
        except Exception as e:
            # Standard Libraries
            import traceback

            tb = traceback.format_exc()
            Msg.error(self._plugin, f'Error starting MCP Server: {e}\n{tb}')

    def _stop_mcp_server(self, action_context: ActionContext) -> None:
        Msg.info(self._plugin, 'STOP MCP Server Clicked')
        self._previously_running = False
        self.tool.setConfigChanged(True)
        self.__stop_mcp_server()

    def __stop_mcp_server(self) -> None:
        try:
            self._mcp_server.stop()
            Msg.info(self._plugin, 'MCP Server stopped')
            # self._action_startMCP.setEnabled(not self._mcp_server.running)
            # self._action_stopMCP.setEnabled(self._mcp_server.running)
        except Exception as e:
            Msg.error(self._plugin, f'Error stopping MCP Server: {e}')

    def read_data_state(self, saveState: SaveState) -> None:
        run_mcp = bool(
            saveState.getBoolean(MCPyGhidraPlugin.STATE_MCP_RUNNING, JBoolean(False))
        )
        Msg.info(self._plugin, f'Read MCP Server state: {run_mcp}')
        self._previously_running = run_mcp

    def write_data_state(self, saveState: SaveState) -> None:
        Msg.info(
            self._plugin,
            f'Resume flags: {self._mcp_server.running} && {self._previously_running}',
        )
        saveState.putBoolean(
            MCPyGhidraPlugin.STATE_MCP_RUNNING,
            self._mcp_server.running or self._previously_running,
        )

    def _program_closed(self, program: Program) -> None:
        Msg.info(self._plugin, 'STOP MCP Server because program was closed')
        self._mcp_server.stop()

    def _post_program_activated(self, program: Program) -> None:
        try:
            options = self.tool.getOptions(MCPyGhidraPlugin.OPTION_CATEGORY_NAME)  # type: ignore[call-arg]
            auto_start = bool(
                options.getBoolean(
                    MCPyGhidraPlugin.AUTOSTART_OPTION_NAME,
                    JBoolean @ MCPyGhidraPlugin.AUTO_MCP_DEFAULT,
                )
            )
            auto_resume = bool(
                options.getBoolean(
                    MCPyGhidraPlugin.AUTORESUME_OPTION_NAME,
                    JBoolean @ MCPyGhidraPlugin.AUTO_MCP_DEFAULT,
                )
            )

            if auto_start or (auto_resume and self._previously_running):
                self.__start_mcp_server()
        except Exception as e:
            Msg.error(self._plugin, f'Error opening MCP Server: {e}')


def decaf_load() -> List[Tuple[str, Type[DecafPlugin]]]:
    return [('mcpyghidra.mcpyghidra.MCPyGhidraPlugin', MCPyGhidraPlugin)]
