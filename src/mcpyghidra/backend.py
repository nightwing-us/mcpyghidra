"""
Backend adapter for MCPyGhidra.

Provides a uniform interface for tool logic regardless of whether
we're running as a Ghidra GUI plugin (PluginBackend) or headless
via pyghidra (HeadlessBackend).

Tool logic depends on GhidraBackend — never on PluginTool directly.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Literal

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Function, Program
    from pyghidra_decaf.tamer.program import (
        DecompiledFunction,
        GhidraTransactionContext,
    )


class GhidraError(Exception):
    """Raised when a Ghidra operation fails (service unavailable, no open program, etc.)."""

    ...


class OverwritePolicy(Enum):
    """Persistent configuration for handling AI overwrites of higher-priority symbols."""

    ASK = 'Ask'
    ALWAYS_ALLOW = 'Always Allow'
    ALWAYS_SKIP = 'Always Skip'


class GhidraBackend(ABC):
    """Abstract interface — what tools need regardless of execution mode.

    Subclasses:
        PluginBackend  — wraps DecafProgramPlugin (GUI mode)
        HeadlessBackend — wraps a bare Program (pyghidra headless)
    """

    def __init__(self) -> None:
        self._decompiled_funcs: Dict[int, 'DecompiledFunction'] = {}
        self._batch_state: dict = {}

    def begin_batch(self) -> None:
        """Clear batch state at the start of a multi-item tool call."""
        self._batch_state = {}

    def end_batch(self) -> None:
        """Clear batch state at the end of a multi-item tool call."""
        self._batch_state = {}

    # --- Abstract: subclasses must implement ---

    @property
    @abstractmethod
    def program(self) -> 'Program':
        """The currently open Ghidra Program."""
        ...

    @property
    @abstractmethod
    def flat_api(self) -> 'FlatProgramAPI':
        """FlatProgramAPI wrapping the current program."""
        ...

    @property
    @abstractmethod
    def is_headless(self) -> bool:
        """True if running without Ghidra GUI."""
        ...

    @abstractmethod
    def get_overwrite_policy(self) -> Literal['ask', 'always_allow', 'always_skip']:
        """Current overwrite policy for symbol renaming."""
        ...

    @abstractmethod
    def confirm_overwrite(self, description: str) -> bool:
        """Ask whether to overwrite an existing symbol.

        In plugin mode with no MCP context: shows a GUI dialog.
        In headless mode or with MCP context: uses MCP elicitation (falls back to auto-allow).
        Returns True to proceed, False to skip.
        """
        ...

    @abstractmethod
    def log(self, level: str, message: str) -> None:
        """Log a message at the given level ('debug', 'info', 'warn', 'error').

        PluginBackend uses Ghidra's Msg.* methods.
        HeadlessBackend uses Python's logging module.
        Tools call backend.log(...) instead of Msg.* directly.
        """
        ...

    @abstractmethod
    def get_data_type_managers(self) -> list[Any]:
        """Return available DataTypeManager instances.

        PluginBackend retrieves these from DataTypeManagerService.
        HeadlessBackend retrieves them from the Program directly.
        """
        ...

    # --- Shared implementations (use only program/flat_api) ---

    def create_transaction(self, desc: str = '') -> 'GhidraTransactionContext':
        """Create a Ghidra transaction context manager."""
        # Late import to avoid import-time Java class resolution
        from pyghidra_decaf.tamer.program import GhidraTransactionContext

        return GhidraTransactionContext(self.program, desc)

    def get_decompiled_func(
        self,
        func: 'Function',
        reset: bool = False,
    ) -> 'DecompiledFunction':
        """Get (cached) decompiled function. Pass reset=True to re-decompile."""
        # Late import to avoid import-time Java class resolution
        from pyghidra_decaf.tamer.program import DecompiledFunction

        ea = func.getEntryPoint().offset
        dec_func = self._decompiled_funcs.get(ea)
        if reset or dec_func is None:
            dec_func = DecompiledFunction(self.flat_api, func)
            self._decompiled_funcs[ea] = dec_func
        return dec_func

    def clear_decompilation_cache(self) -> None:
        """Clear all cached decompilations."""
        self._decompiled_funcs.clear()


class HeadlessBackend(GhidraBackend):
    """Backend for headless mode (pyghidra, no GUI).

    Constructed with a Program object from pyghidra.open_program().

    Requires Ghidra 11.1+ (pyghidra was integrated into Ghidra starting ~11.1).
    """

    def __init__(self, program: 'Program') -> None:
        super().__init__()
        self._program = program
        self._logger = logging.getLogger(__name__)
        # Import here to avoid import-time Java class resolution
        from ghidra.program.flatapi import FlatProgramAPI as _FlatProgramAPI

        self._flat_api = _FlatProgramAPI(program)

    @property
    def program(self) -> 'Program':
        return self._program

    @property
    def flat_api(self) -> 'FlatProgramAPI':
        return self._flat_api

    @property
    def is_headless(self) -> bool:
        return True

    def get_overwrite_policy(self) -> Literal['ask', 'always_allow', 'always_skip']:
        return 'ask'

    def confirm_overwrite(self, description: str) -> bool:
        """Sync wrapper that bridges to async elicitation via anyio.from_thread."""
        import anyio.from_thread

        try:
            return anyio.from_thread.run(self._confirm_overwrite_async, description)
        except Exception:
            return True  # Fallback on any error (e.g. no portal, no event loop)

    async def _confirm_overwrite_async(self, description: str) -> bool:
        from mcpyghidra.server import elicit_confirmation

        return await elicit_confirmation(description, self._batch_state)

    def log(self, level: str, message: str) -> None:
        """Log using Python's logging module."""
        log_fn = getattr(
            self._logger, level if level != 'warn' else 'warning', self._logger.info
        )
        log_fn(message)

    def get_data_type_managers(self) -> 'list[Any]':
        """Return only the program's own data type manager.

        In headless mode, DataTypeManagerService is not available,
        so archive/built-in managers are not included. This means
        type-related tools will have reduced capability (program types only).
        """
        return [self._program.getDataTypeManager()]


class PluginBackend(GhidraBackend):
    """Backend for Ghidra GUI plugin mode (DecafProgramPlugin)."""

    def __init__(self, plugin_tool: Any, plugin: Any) -> None:
        super().__init__()
        self._tool = plugin_tool
        self._plugin = plugin
        self._overwrite_dialog_builder: Any = (
            None  # lazy init; preserves Apply-to-all state
        )
        self._flat_api: Any = None  # cached FlatProgramAPI instance
        self._flat_api_program: Any = None  # program the cache was built for

    @property
    def program(self) -> 'Program':
        """The currently open Ghidra Program, via ProgramManager service."""
        from ghidra.app.services import ProgramManager

        pm = self._tool.getService(ProgramManager.class_)
        if pm is None:
            raise GhidraError('Program Manager service not available')
        prog = pm.getCurrentProgram()
        if prog is None:
            raise GhidraError('No program is open')
        return prog

    @property
    def flat_api(self) -> 'FlatProgramAPI':
        """FlatProgramAPI wrapping the current program, cached per-program.

        A new FlatProgramAPI is only allocated when the current program changes.
        This avoids the overhead of allocating a new Java wrapper object on every
        call while still staying correct when the user switches programs.
        """
        prog = self.program
        if self._flat_api is None or self._flat_api_program is not prog:
            from ghidra.program.flatapi import FlatProgramAPI

            self._flat_api = FlatProgramAPI(prog)
            self._flat_api_program = prog
        return self._flat_api

    @property
    def is_headless(self) -> bool:
        """True when no CodeViewerService is available (i.e. no Ghidra GUI)."""
        from ghidra.app.services import CodeViewerService

        try:
            return self._tool.getService(CodeViewerService.class_) is None
        except Exception:
            return True

    def get_overwrite_policy(self) -> Literal['ask', 'always_allow', 'always_skip']:
        """Read the persistent overwrite policy from tool options."""
        try:
            options = self._tool.getOptions('MCPyGhidra')
            raw = str(options.getString('AI Overwrite Policy', 'Ask'))
            for policy in OverwritePolicy:
                if policy.value == raw:
                    return policy.value.lower().replace(' ', '_')  # type: ignore[return-value]
            return 'ask'
        except Exception:
            return 'ask'

    def confirm_overwrite(self, description: str) -> bool:
        """Return True to proceed with overwrite, False to skip.

        Tries MCP elicitation first (via anyio.from_thread bridge). If no MCP
        context is available, reads the persistent policy; falls back to showing
        a GUI dialog when the policy is 'ask' and we are not in headless mode.
        Raises ToolError if the user cancels the dialog.
        """
        from mcpyghidra.server import get_current_context

        if get_current_context() is not None:
            # MCP client connected — use elicitation bridge
            import anyio.from_thread

            try:
                return anyio.from_thread.run(self._confirm_overwrite_async, description)
            except Exception:
                return True  # Fallback if bridge unavailable

        policy = self.get_overwrite_policy()
        if policy == 'always_allow':
            return True
        if policy == 'always_skip':
            return False
        if self.is_headless:
            return True
        # Extract symbol_name and addr from description for the legacy dialog
        return self._show_overwrite_dialog_from_description(description)

    async def _confirm_overwrite_async(self, description: str) -> bool:
        from mcpyghidra.server import elicit_confirmation

        return await elicit_confirmation(description, self._batch_state)

    def _show_overwrite_dialog_from_description(self, description: str) -> bool:
        """Derive symbol_name/addr from the description and show GUI dialog."""
        # Description format: "Confirm renaming {old_name} ({old_type}) at {addr} to {new_name}?"
        # Use the full description as the message for the legacy dialog.
        import re as _re

        m = _re.search(r'renaming (.+?) \((.+?)\) at (.+?) to (.+?)\?', description)
        if m:
            symbol_name = m.group(1)
            addr = m.group(3)
        else:
            symbol_name = description[:50]
            addr = 'unknown'
        return self._show_overwrite_dialog(symbol_name, addr)

    def _show_overwrite_dialog(self, symbol_name: str, addr: str) -> bool:
        """Show a Swing confirmation dialog on the EDT and block until dismissed.

        Returns True to overwrite, False to skip.
        Raises ToolError if the user cancels (closes the dialog without choosing).
        """
        from docking.widgets import OptionDialog, OptionDialogBuilder
        from ghidra.util import Swing
        from mcp.server.fastmcp.exceptions import ToolError

        message = (
            f'AI wants to rename symbol:\n\n'
            f"  Symbol: '{symbol_name}'\n"
            f'  Address: {addr}\n\n'
            f'The existing value has higher priority. Overwrite it?'
        )

        result_holder: list[int] = [OptionDialog.CANCEL_OPTION]

        def _show_on_edt() -> None:
            try:
                # Lazily create or update the builder.
                # Reusing the builder preserves DialogRememberOption state
                # so "Apply to remaining" works across MCP calls.
                if self._overwrite_dialog_builder is None:
                    self._overwrite_dialog_builder = OptionDialogBuilder(
                        'Confirm AI Overwrite', message
                    )
                    self._overwrite_dialog_builder.addOption('Overwrite')
                    self._overwrite_dialog_builder.addOption('Skip')
                    self._overwrite_dialog_builder.addApplyToAllOption()
                else:
                    self._overwrite_dialog_builder.setMessage(message)

                tool_frame = self._tool.getToolFrame()
                result_holder[0] = self._overwrite_dialog_builder.show(tool_frame)
            except Exception as e:
                self.log('error', f'Error showing overwrite dialog: {e}')
                result_holder[0] = OptionDialog.CANCEL_OPTION

        # Dispatch to EDT and block until the dialog is dismissed
        Swing.runNow(_show_on_edt)

        result = result_holder[0]
        if result == OptionDialog.OPTION_ONE:  # "Overwrite"
            return True
        elif result == OptionDialog.OPTION_TWO:  # "Skip"
            return False
        else:  # CANCEL_OPTION (0) — dialog closed/cancelled
            raise ToolError(f"User cancelled overwrite of '{symbol_name}' at {addr}")

    def log(self, level: str, message: str) -> None:
        """Log via Ghidra's Msg class (appears in Ghidra console)."""
        from ghidra.util import Msg

        log_fn = getattr(Msg, level if level != 'warn' else 'warning', Msg.info)
        log_fn(self._plugin, message)

    def get_data_type_managers(self) -> 'list[Any]':
        """Return all available DataTypeManager instances.

        Queries DataTypeManagerService so that built-in types and imported
        archives (.gdt files) are included alongside the program's own DTM.
        Falls back gracefully to the program DTM if the service is unavailable.
        """
        managers: list[Any] = [self.program.getDataTypeManager()]
        try:
            from ghidra.app.services import DataTypeManagerService

            dtm_service = self._tool.getService(DataTypeManagerService.class_)
            if dtm_service is not None:
                for mgr in dtm_service.getDataTypeManagers():
                    if mgr != managers[0]:
                        managers.append(mgr)
        except Exception:
            pass
        return managers
