# Changelog

All notable changes to **mcpyghidra** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/) and the
format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

[Unreleased]: https://github.com/nightwing-us/mcpyghidra/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/nightwing-us/mcpyghidra/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/nightwing-us/mcpyghidra/releases/tag/v0.6.0
