# MCPyGhidra

An MCP (Model Context Protocol) server that exposes [Ghidra](https://ghidra-sre.org/)
reverse-engineering capabilities to LLM clients. Built on [pyghidra-decaf](https://github.com/nightwing-us/pyghidra-decaf).

MCPyGhidra exposes binary analysis capabilities via MCP: decompilation, disassembly, symbol lookup, cross-references, type inspection, binary patching, and scriptable analysis.

> **Related project:** If you use IDA Pro rather than Ghidra, see
> [MCPyIDA](https://github.com/nightwing-us/mcpyida) for an equivalent MCP
> server for IDA Pro.

## Prerequisites

- **Ghidra** a recent release (tested with Ghidra 11.x+; [download](https://ghidra-sre.org/))
- **Java** a compatible JDK (bundled with Ghidra)
- **Python** 3.10–3.13
- **pyghidra-decaf** (installed via PyPI alongside mcpyghidra)

## Installation

```bash
pip install mcpyghidra
```

Then configure your Ghidra installation:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
```

For detailed setup, see [docs/installation.md](docs/installation.md).

## Quick Start

### Headless Mode

Launch the MCP server in headless mode for non-interactive analysis:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
mcpyghidra-headless --binary /path/to/firmware.elf
```

The server prints a JSON readiness signal to stdout:

```json
{"status": "ready", "host": "127.0.0.1", "port": 6050, "binary": "/path/to/firmware.elf"}
```

Then configure your MCP client to connect to `http://127.0.0.1:6050/mcp`.

### With an MCP Client

Point any MCP-compatible client at the running server:

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:6050/mcp"
    }
  }
}
```

See [docs/mcp-client-config.md](docs/mcp-client-config.md) for client-specific examples.

## What's Exposed

MCPyGhidra exposes 26 tools organized into categories:

- **Listing & context:** list entries, inspect binary metadata, resolve functions
- **Analysis:** decompile, disassemble, cross-references, control-flow graphs
- **Types:** type enumeration and detailed inspection
- **Modification:** rename symbols, update variables, set comments, patch instructions
- **Scripting:** Python code execution with back-to-client RPC callbacks
- **Search:** binary pattern and instruction sequence matching

See [docs/tools-reference.md](docs/tools-reference.md) for full details.

## Troubleshooting

- **`GHIDRA_INSTALL_DIR not set`** — point it at your Ghidra install: `export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC`.
- **Client can't connect** — confirm the server is running and reachable at the Streamable HTTP endpoint `http://127.0.0.1:6050/mcp`.
- **Server startup hangs** — analyzing large binaries can take minutes; try a small binary (e.g. `mcpyghidra-headless --binary /bin/ls`) to verify the setup.

See [docs/installation.md](docs/installation.md) and [docs/quickstart.md](docs/quickstart.md) for the full troubleshooting guides.

## Documentation

- [Installation & Setup](docs/installation.md)
- [Quickstart Guide](docs/quickstart.md)
- [Connecting MCP Clients](docs/mcp-client-config.md)
- [Tools Reference](docs/tools-reference.md)
- [Running Modes (Headless & GUI)](docs/quickstart.md)
- [RPC Callbacks (Advanced)](docs/specs/rpc-callbacks.md)
- [Documentation Hub](docs/index.md)

## Development

This project uses `uv` for environment and package management.

### Setup

```bash
curl -sSf https://astral.sh/uv/install.sh | bash
git clone https://github.com/nightwing-us/mcpyghidra.git
cd mcpyghidra
uv venv
uv pip install -e ".[dev]"
```

### Testing

```bash
uv run pytest --tb=short
```

### Type Checking

```bash
uv run mypy
```

### Linting

```bash
uv run ruff check src tests
uv run ruff format src tests
```

## Related Projects

MCPyGhidra and MCPyIDA are maintained in parallel as sister projects with
intended feature parity — MCPyGhidra targets Ghidra and MCPyIDA targets IDA Pro.

- [MCPyIDA](https://github.com/nightwing-us/mcpyida) — equivalent MCP server
  for IDA Pro
- [pyghidra-decaf](https://github.com/nightwing-us/pyghidra-decaf) — Python-native
  Ghidra plugin development framework (underpins MCPyGhidra)

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

Copyright © 2026 Nightwing Group, LLC.
