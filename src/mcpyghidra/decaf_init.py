# Standard Libraries
from importlib.metadata import version

# Third Party Libraries
from pyghidra_decaf.launch import (
    DecafExtensionInfo,
    DecafLauncher,
    DecafPluginInfo,
    PluginStatus,
    PluginType,
)


def decaf_init(launcher: DecafLauncher) -> DecafExtensionInfo:
    lib_version = version('MCPyGhidra')
    return DecafExtensionInfo(
        name='MCPyGhidra',
        description='Ghidra MCP server',
        author='Nightwing Group, LLC.',
        version=lib_version,
        plugins=[
            DecafPluginInfo(
                type=PluginType.ProgramPlugin,
                qualname='MCPyGhidraPlugin',
                class_name='MCPyGhidraPlugin',
                status=PluginStatus.STABLE,
                module_name='mcpyghidra.mcpyghidra',
                category='Analysis',
                shortDescription='Ghidra MCP server',
                description='Ghidra MCP server',
            )
        ],
        java_package='',
    )
