# Installation & Setup

This guide covers installing MCPyGhidra and configuring its dependencies.

## Prerequisites

Before installing MCPyGhidra, ensure you have:

### Ghidra (Recent Release)

Download and extract Ghidra from [ghidra-sre.org](https://ghidra-sre.org/):

```bash
# Example: extract to ~/tools/ghidra
cd ~/tools
unzip ghidra_12.0_PUBLIC.zip
export GHIDRA_INSTALL_DIR=~/tools/ghidra_12.0_PUBLIC
```

**Tested versions:** Ghidra 11.1, 11.3, 12.0+

### Java (Bundled with Ghidra)

Java is included with Ghidra, but you can verify it:

```bash
java -version
# openjdk version "11.0.x" or higher
```

If Java is not available, install from [openjdk.java.net](https://openjdk.java.net/) or your system package manager.

### Python 3.10–3.13

Check your Python version:

```bash
python3 --version
# Python 3.10 or later
```

### pyghidra-decaf

This is installed automatically as a dependency of mcpyghidra. Verify it's available:

```bash
pip list | grep pyghidra
# pyghidra-decaf  (version)
```

## Installing MCPyGhidra

### From PyPI

The easiest way to install is from PyPI:

```bash
pip install mcpyghidra
```

This installs mcpyghidra and its dependencies (including pyghidra-decaf and fastapi).

### From Source (Development)

To work on MCPyGhidra itself, clone the repository and use `uv`:

```bash
git clone https://github.com/nightwing-us/mcpyghidra.git
cd mcpyghidra
uv venv
uv pip install -e ".[dev]"
```

## Configuring GHIDRA_INSTALL_DIR

MCPyGhidra requires the `GHIDRA_INSTALL_DIR` environment variable to find your Ghidra installation.

### Linux / macOS

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
```

Then reload your shell:

```bash
source ~/.bashrc
```

Or set it per-session:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
mcpyghidra-headless /path/to/firmware.elf
```

### Windows (Command Prompt)

```cmd
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.0_PUBLIC
mcpyghidra-headless C:\path\to\firmware.elf
```

### Windows (PowerShell)

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_12.0_PUBLIC"
mcpyghidra-headless C:\path\to\firmware.elf
```

## Verifying the Installation

### Test the Headless Server

Create a simple binary or use an existing one:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
mcpyghidra-headless /bin/ls
```

You should see output like:

```
Starting Ghidra headless...
Opening and analyzing ls...
Starting MCP server on 127.0.0.1:6050...
{"status": "ready", "host": "127.0.0.1", "port": 6050, "binary": "/bin/ls"}
```

Press Ctrl+C to stop the server.

### Verify Dependencies

Check that all dependencies are installed:

```bash
python -c "import mcpyghidra; import pyghidra_decaf; import fastapi; print('All dependencies OK')"
```

## Troubleshooting

### Error: GHIDRA_INSTALL_DIR not set

If you see this error:

```
Error: GHIDRA_INSTALL_DIR environment variable not set.
```

Verify that the environment variable is set:

```bash
echo $GHIDRA_INSTALL_DIR
# Should print a path
```

If it's empty, set it and try again:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
```

### Error: Failed to start Ghidra headless

This usually means:

1. **Invalid `GHIDRA_INSTALL_DIR`:** Verify the path exists and is a valid Ghidra installation:
   ```bash
   ls $GHIDRA_INSTALL_DIR/ghidraRun
   ```

2. **Java not available:** Verify Java 11+ is in your PATH:
   ```bash
   java -version
   ```

3. **pyghidra installation issue:** Reinstall pyghidra-decaf:
   ```bash
   pip install --upgrade pyghidra-decaf
   ```

### Error: Binary file not found

Ensure the binary path is correct and readable:

```bash
ls -la /path/to/firmware.elf
# Should show the file
```

## Next Steps

Once installation is complete, proceed to [Quickstart Guide](quickstart.md) to run your first MCPyGhidra server.
