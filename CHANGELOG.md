# Changelog

All notable changes to **mcpyghidra** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/) and the
format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.7.2] — 2026-06-26

Tool ergonomics for smaller LLM clients (single-or-batch calls), a simpler tool
surface, parallel-safe ports, and a self-diagnosing headless CLI.

### Added

- **Items-based tools now accept a single flat call *or* a batch.** Call
  `decompile(name="main")` / `decompile(addr="0x401000")`, `funcs(target="main")`,
  `symbols(addr="0x401000")` directly, or keep the batch form
  `decompile(items=[{…}, {…}])`. A single (flat) call returns one result; a batch
  returns a list. Applies to `decompile`, `disasm`, `xrefs`, `symbols`, `funcs`,
  `type_info`, `get_comment`, `rename`, `set_comments`, `set_prototype`, `patch`,
  and `add_field`.
- **The headless `--port` accepts a range (default `6050-6059`) and binds the
  first free port.** Multiple headless servers can now launch in parallel without
  colliding. A bare single port is strict; `0` lets the OS auto-assign. The JSON
  ready signal reports the actually-bound port.
- **The headless launcher now prints a structured JSON status line for every
  outcome.** `{"status":"ready",…}` on success and
  `{"status":"error","reason":…,"detail":…}` on failure, each with a per-reason
  exit code; the resolved Ghidra install/version/binary is echoed on startup. A
  background or polling launcher can now diagnose the first failure from stdout
  alone, without a foreground re-run.
- **`--ghidra-dir DIR`** pins the Ghidra installation for a self-contained
  invocation (overrides `GHIDRA_INSTALL_DIR`).

### Changed

- **`get_funcs` is renamed to `funcs`** for consistency with the other read tools.
- **Type enumeration moved into `list(entry_type="type")`; the standalone `types`
  tool was removed.** `match_filter` now applies to types as well.
- **The GUI MCP server binds the first free port in its configured range** instead
  of failing when the port is already in use.
- **`mcpyghidra-headless` takes the binary as a positional argument** —
  `mcpyghidra-headless /path/to/binary` (the `--binary` flag is removed).

### Fixed

- **Calling an items-based tool with no (or conflicting) arguments now returns a
  clear, instructive error** — e.g. pointing you at `list(entry_type="function")`
  — instead of an opaque "`items` is a required property" schema failure.

## [0.7.1] — 2026-06-17

Headless-server improvements: persistent, reusable Ghidra projects and reliable
saving of analysis and edits on shutdown.

### Added

- **Persistent Ghidra projects for the headless server via `--project-dir` and
  `--project-name`.** Point the launcher at a project directory to reuse prior
  analysis and keep your edits (renames, comments, types) across runs. When
  omitted, an auto-named project is created beside the binary as before.

### Changed

- **The headless launcher now uses pyghidra's current project API** instead of
  the deprecated `open_program`, removing the associated deprecation warning.
  Projects are created in the standard standalone Ghidra layout, so a
  `--project-dir` opens directly in the Ghidra GUI.

### Fixed

- **Analysis and edits are now persisted when the headless server is stopped by
  a signal (SIGTERM/SIGINT).** Previously the embedded JVM intercepted the
  signal and terminated before the project was saved, discarding changes; the
  launcher now shuts down gracefully and saves the project first.

## [0.7.0] — 2026-06-12

Ergonomics and reliability improvements for the `pyghidra` code-execution tool,
centered on how scripts call MCP tools provided by the connected client.

### Added

- **Client-provided MCP tools are now projected into nested namespaces inside the
  `pyghidra` REPL.** A callback advertised over the wire as `mcp__service__list`
  is reachable as `mcp.service.list(...)`, and each namespace is importable
  (`import mcp.service as service`). The projection is generic over every tool
  namespace the client offers.
- **`mcp.self.*` — call this server's own tools from within a script.** Re-entrant
  calls dispatch in-process without a round trip back through the client, so a
  script can compose MCPyGhidra's own tools directly.
- **`executesCode` annotation on the `pyghidra` tool**, so MCP clients can
  recognize it as a code-execution surface and apply appropriate handling.

### Changed

- **Namespaced callbacks are now called with dotted names instead of the flat
  double-underscore form.** `mcp__service__list(...)` is now `mcp.service.list(...)`.
  See **Upgrade** below — this is a breaking change to script call syntax.
- **Projected namespaces never shadow real Python.** A namespace whose name would
  collide with a Python builtin, keyword, or an importable module (e.g. `os`,
  `sys`, `json`) is escaped with a trailing underscore rather than overriding the
  real module in the script environment.

### Removed

- **The injected `rpc` discovery object has been removed.** Native `help()` and
  `dir()` now cover discovery of the projected namespaces (e.g. `dir(mcp)`).

### Fixed

- **Re-entrant or concurrent `pyghidra` invocations fail fast with a clear error**
  instead of deadlocking. A single-flight guard rejects a second execution while
  one is already in progress and returns an explanatory message.
- **Tools whose parameters declare a JSON-Schema union/list `type`** (for example
  `["string", "null"]`) no longer break callback signature generation and are now
  callable from the REPL.
- **Callbacks that receive an injected request `Context` now work**, by annotating
  the injected parameter as a plain `Context`.

### Upgrade

This release changes how client-provided callbacks are called from `pyghidra`
scripts. Update call sites:

- `mcp__service__list(arg)` → `mcp.service.list(arg)`
- Replace any use of the `rpc` object with the projected namespaces directly;
  use `dir(mcp)` / `help(mcp)` to discover what the client offers.

Tools whose names contain no `__` separator (e.g. `search_web`) remain flat
globals and are unaffected.

## [0.6.0]

First public release.

[Unreleased]: https://github.com/nightwing-us/mcpyghidra/compare/v0.7.2...HEAD
[0.7.2]: https://github.com/nightwing-us/mcpyghidra/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/nightwing-us/mcpyghidra/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/nightwing-us/mcpyghidra/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/nightwing-us/mcpyghidra/releases/tag/v0.6.0
