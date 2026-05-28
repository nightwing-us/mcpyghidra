# MCPyGhidra Documentation

MCPyGhidra is an MCP (Model Context Protocol) server that exposes Ghidra reverse-engineering tools to LLM clients. The documents below cover installation, running the server, client configuration, and tool usage.

## Getting Started

- **[Installation & Setup](installation.md)** — Prerequisites, installing from PyPI, configuring Ghidra
- **[Quickstart Guide](quickstart.md)** — Your first MCPyGhidra server and client connection
- **[Connecting MCP Clients](mcp-client-config.md)** — Configure Claude, Cline, and other MCP clients

## Using MCPyGhidra

- **[Tools Reference](tools-reference.md)** — Every exposed tool, grouped by category: listing & navigation, analysis & decompilation, control flow, types, modification & patching, scripting, and search
- Running modes (headless server and Ghidra GUI plugin) are covered in the **[Quickstart Guide](quickstart.md)**

## Advanced Topics

- **[RPC Callbacks Protocol](specs/rpc-callbacks.md)** — Bidirectional function calls between server and client (for advanced `pyghidra_eval` scripts)

## FAQ & Troubleshooting

Refer to the Quickstart and Installation guides for common setup issues. If you encounter problems:

- Verify `GHIDRA_INSTALL_DIR` is set to a valid Ghidra 11.1+ installation
- Ensure Java 11+ is available (usually bundled with Ghidra)
- Check that Python 3.10+ is in use
- Review logs for connection errors between client and server

## Contributing

MCPyGhidra welcomes contributions! See the repository's [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on code style, testing, and submitting pull requests.

## License

MCPyGhidra is licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

Copyright © 2026 Nightwing Group, LLC.
