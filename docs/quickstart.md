# Quickstart Guide

## Step 1: Install MCPyGhidra

```bash
pip install mcpyghidra
```

See [Installation & Setup](installation.md) for detailed instructions.

## Step 2: Set GHIDRA_INSTALL_DIR

Before running the server, set the environment variable to your Ghidra installation:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
```

Verify it's set:

```bash
echo $GHIDRA_INSTALL_DIR
# Should print your Ghidra path
```

## Step 3: Launch the Headless Server

Start MCPyGhidra with a binary to analyze:

```bash
mcpyghidra-headless /path/to/firmware.elf
```

Expected output:

```
Starting Ghidra headless...
Opening and analyzing firmware.elf...
Starting MCP server on 127.0.0.1:6050...
{"status": "ready", "host": "127.0.0.1", "port": 6050, "binary": "/path/to/firmware.elf"}
```

The server is now running and listening on `http://127.0.0.1:6050/mcp`.

## Step 4: Configure an MCP Client

In a separate terminal, configure your MCP client to connect to the running server.

### Using Claude Desktop (via mcpo)

If using mcpo as a bridge to Claude Desktop, configure it in `~/.mcpo/config.json`:

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

Ensure mcpo is installed and running. Restart Claude Desktop. You should now see `ghidra` in the MCP server list.

### Using a Generic MCP Client

Any MCP-compatible client supporting Streamable HTTP can connect. Configure it with:

- **Type:** Streamable HTTP
- **URL:** `http://127.0.0.1:6050/mcp`

## Step 5: Use MCPyGhidra from Your Client

Once connected, you can use the exposed tools. For example, in Claude:

> What functions are exported from the binary? Use the `list_entries` tool to show me functions with "main" in their name.

The client will:

1. Send a request to MCPyGhidra (via MCP)
2. MCPyGhidra calls Ghidra APIs to extract function information
3. Returns results to the client
4. The client displays or processes the results

## Common Commands

### List Functions

View functions in the binary:

```
Use list_entries tool with category="functions" and limit=20
```

### Decompile a Function

Get high-level code for a function (by name or address):

```
Use decompile tool with the function name or address
```

### Find Cross-References

See where a function is called:

```
Use xrefs tool with direction="to" and name="function_name"
```

### Patch Instructions

Modify binary instructions:

```
Use patch tool to replace instruction bytes at an address
```

### Inspect Types

List and inspect custom types (structures, enums, unions):

```
Use types tool to enumerate, type_info to inspect details
```

## Stopping the Server

In the terminal where MCPyGhidra is running, press **Ctrl+C**:

```
^CShutting down...
```

The server will stop gracefully.

## Headless Server Options

The `mcpyghidra-headless` command accepts these options:

```bash
mcpyghidra-headless <binary> [--host <host>] [--port <port>] [--project-dir <dir>] [--project-name <name>] [--ghidra-dir <dir>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `binary` (positional, required) | — | Path to the binary to analyze |
| `--host` | `127.0.0.1` | Host to bind the server (localhost by default) |
| `--port` | `6050-6059` | Port or inclusive range (default `6050-6059`); the first free port is bound. Use a bare port for strict, or `0` to let the OS assign. |
| `--project-dir` | An auto-named `<binary>_ghidra` project beside the binary | Directory for the Ghidra project |
| `--project-name` | Derived from the binary | Name of the Ghidra project |
| `--ghidra-dir` | `$GHIDRA_INSTALL_DIR` | Override Ghidra installation directory |

**Output:** On success, the server prints a JSON readiness signal:

```json
{"status": "ready", "host": "127.0.0.1", "port": 6050, "binary": "/path/to/firmware.elf"}
```

On failure, it prints a JSON error signal and exits with a descriptive exit code:

```json
{"status": "error", "reason": "<reason>", "detail": "..."}
```

The `reason` field indicates the error type. Possible values:
- `binary_not_found` — The binary file does not exist or is not readable
- `missing_install_dir` — Ghidra installation directory not found or not configured
- `bad_port` — Invalid port specification (not a number or out of range)
- `port_unavailable` — The specified port is already in use
- `jvm_not_found` — Java runtime not found or not properly configured
- `open_failed` — Failed to open or analyze the binary in Ghidra
- `internal` — Unexpected internal error

This allows launcher integrations to parse stdout for status and diagnostics.

Example: auto-assign port and bind to all interfaces:

```bash
mcpyghidra-headless /path/to/firmware.elf --host 0.0.0.0 --port 0
```

The readiness JSON will show the actual assigned port.

## Next Steps

- Explore [Tools Reference](tools-reference.md) for all available functions
- Learn [MCP Client Configuration](mcp-client-config.md) for advanced setups
- See [RPC Callbacks](specs/rpc-callbacks.md) for advanced scripting features

## Troubleshooting

### "GHIDRA_INSTALL_DIR not set"

Set the environment variable:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
```

### "Binary file not found"

Verify the binary path exists and is readable:

```bash
ls -la /path/to/firmware.elf
```

### Client can't connect

Ensure the server is still running and listening:

```bash
curl http://127.0.0.1:6050/mcp
# Should show a streaming response (may not print visually, Ctrl+C to cancel)
```

### Server startup hangs

Analysis of large binaries can take minutes. Wait longer or use a smaller test binary:

```bash
mcpyghidra-headless /bin/ls
```

For more help, see [Installation & Setup](installation.md) and [Tools Reference](tools-reference.md).
