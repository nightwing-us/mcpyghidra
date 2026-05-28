# MCPyGhidra Tools Reference

Authoritative reference for all tools exposed by the MCPyGhidra MCP server via Streamable HTTP.

**For setup:** See [docs/quickstart.md](./quickstart.md), [docs/index.md](./index.md), and [docs/mcp-client-config.md](./mcp-client-config.md).

---

## Core Listing & Navigation

### `list` (list_entries)

**Purpose:** Get a paginated list of binary entries by type (functions, imports, strings, etc.) with optional filtering.

**Parameters:**
- `entry_type` (string, required): Type of entries to list. Valid values: `function`, `memory_segment`, `import`, `export`, `string`, `class`, `namespace`
- `offset` (integer, optional, default: 0): Pagination offset (starting position)
- `limit` (integer, optional, default: 500, max: 10000): Maximum items to return per page
- `match_filter` (string, optional, default: ''): Substring filter on entry name (functions and strings only; case-insensitive)

**Returns:** `ListResult` containing:
- `items[]`: List of entries (each with name, address, and type-specific fields)
- `page_info`: Pagination state (offset, limit, total_count, has_more, next_offset)
- `summary`: Human-readable description of the list
- `entry_type`: The requested type
- `schema_version`: Format version (always 1)

**Examples:**
```
list(entry_type='function') → First 500 functions
list(entry_type='function', limit=50) → First 50 functions  
list(entry_type='function', offset=100, limit=50) → Functions 100–149
list(entry_type='string', match_filter='error', limit=20) → Strings containing "error"
```

**Note:** Batch-capable (via pagination; individual requests are single-page).

---

### `cursor`

**Purpose:** Get the address and function info at the user's current cursor position in Ghidra (GUI only; headless returns last-set position or entry point).

**Parameters:** None

**Returns:** `CurrentLocation` with:
- `addr`: Current hex address (e.g., `"0x401000"`)
- `function`: `FunctionInfo` (name, entrypoint, signature) if cursor is inside a function; null otherwise

**Use Case:** Contextual operations relative to user focus.

---

### `context`

**Purpose:** Get comprehensive metadata about the currently open binary, including architecture, memory layout, analysis state, and file info.

**Parameters:** None

**Returns:** `BinaryContext` with:
- `current_location`: Current cursor position and function
- `program`: Binary file details (path, name, format, size, MD5 hash)
- `architecture`: Processor, bitness, endianness, compiler
- `memory`: Address space layout (base, entry point, min/max addresses)
- `analysis`: Database path, function count, debug symbols, type libraries, analysis state
- `application`: Ghidra version info

---

### `get_funcs`

**Purpose:** Get detailed function info by address or name. Accepts batch of addresses/names.

**Parameters:**
- `items` (array of strings, required): Addresses (hex, e.g., `"0x401000"`) or function names (e.g., `"main"`)

**Returns:** Array of dicts, each with:
- `name`: Resolved function name
- `entrypoint`: Function entry point (hex address)
- `signature`: Function signature (on success) or null (on failure)
- `error`: null on success; error message on failure

**Batch-capable:** Yes (processes multiple addresses/names in one call).

---

## Analysis & Decompilation

### `decompile`

**Purpose:** Decompile function(s) to C pseudocode with optional function comments prepended.

**Parameters:**
- `items` (array of dicts, required): Functions to decompile. Each item:
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): e.g., `"main"`
  - At least one of `addr` or `name` must be provided

**Returns:** Array of dicts, each with:
- `code`: Decompiled C pseudocode (on success)
- `name`: Resolved function name
- `entrypoint`: Function entry point (hex)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

**Example:**
```
decompile(items=[
  {"addr": "0x401000"},
  {"name": "main"},
  {"addr": "0x402000"}
])
```

---

### `disasm`

**Purpose:** Disassemble function(s) or address ranges (merged tool: both function and address modes).

**Parameters:**
- `items` (array of dicts, required): Disassembly requests. Each item:
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): Function name
  - `count` (integer, optional): Number of instructions to disassemble from addr
  - **Mode selection:**
    - `count` set → Address mode (N instructions from addr)
    - `name` → Function mode (entire function)
    - `addr` only → Auto-detect (function containing addr, or 20 instructions from addr)

**Returns:** Array of dicts, each with:
- `asm`: Disassembly text (on success)
- `addr`: Resolved address
- `name`: Function name (if function mode)
- `mode`: 'function' or 'address'
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

**Examples:**
```
disasm(items=[
  {"name": "main"},  # Entire main function
  {"addr": "0x401000", "count": 20},  # 20 instructions from address
  {"addr": "0x402000"}  # Auto-detect
])
```

---

### `symbols`

**Purpose:** Get symbol info for address(es) — resolve addresses to names and symbol types.

**Parameters:**
- `items` (array of strings, required): Hex addresses to look up (e.g., `["0x401000", "0x402000"]`)

**Returns:** Array of dicts, each with:
- `addr`: Input address
- `name`: Symbol name (on success)
- `symbol_type`: One of `function`, `code_label`, `global_variable`, `data_label`, `unknown`
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `xrefs`

**Purpose:** Find cross-references to/from addresses or functions (merged tool: both directions).

**Parameters:**
- `items` (array of dicts, required): Cross-reference requests. Each item:
  - `target` (string, required): Hex address (e.g., `"0x401000"`) or function name
  - `direction` (string, optional, default: 'to'): `"to"` (refs pointing to target) or `"from"` (refs from target)
  - `offset` (integer, optional, default: 0): Pagination offset
  - `limit` (integer, optional, default: 500): Max results

**Returns:** Array of dicts, each with:
- `refs`: `ListResult` containing cross-reference items (on success)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

## Control Flow & Graphs

### `cfg`

**Purpose:** Extract control flow graph (CFG) for a function with basic blocks, successors, called functions, and strings.

**Parameters:**
- `address` (string, required): Function address (hex) or name
- `normalize` (boolean, optional, default: true): Apply cross-tool normalization
- `include_bytes` (boolean, optional, default: false): Include base64 raw bytes per block
- `include_disassembly` (boolean, optional, default: false): Include instruction list per block

**Returns:** `CFGResult` with:
- `function`: Function name and address
- `blocks[]`: Array of basic blocks, each with:
  - `address`: Block start address
  - `size`: Block size in bytes
  - `successors`: Array of successor block addresses
  - `called_functions[]`: Functions called from this block
  - `strings[]`: String references in this block
  - `bytes`: Base64-encoded bytes (if requested)
  - `disassembly`: Instruction list (if requested)

---

### `callgraph`

**Purpose:** Build call graph from a root function, traversing call relationships with configurable depth and limits.

**Parameters:**
- `address` (string, required): Root function address (hex) or name
- `direction` (string, optional, default: 'callees'): `'callees'` (called functions), `'callers'` (calling functions), or `'both'`
- `max_depth` (integer, optional, default: 5): Maximum traversal depth
- `max_nodes` (integer, optional, default: 1000): Maximum function nodes to return
- `max_edges` (integer, optional, default: 5000): Maximum call edges to return

**Returns:** `CallGraphResult` with:
- `root`: Root function name and address
- `direction`: Direction traversed
- `nodes[]`: Array of function nodes (name, address, depth)
- `edges[]`: Array of call edges (from, to)
- `depth`: Actual traversal depth

---

## Type Inspection & Manipulation

### `types`

**Purpose:** Enumerate and search available types across all type sources (structures, enums, typedefs, etc.) with pagination.

**Parameters:**
- `pattern` (string, optional, default: null): Substring filter (case-insensitive). Strips `*` if glob-style. None = no filter.
- `offset` (integer, optional, default: 0): Pagination offset
- `limit` (integer, optional, default: 500, max: 10000): Max items to return

**Returns:** Array of `TypeSummary` objects, each with:
- `name`: Short name (e.g., `"istream"`)
- `full_path`: Full path (e.g., `"std::istream"`)
- `type_string`: Exact string to pass to type-setting tools
- `kind`: Normalized type kind
- `size`: Size in bytes, or null if unknown/variable

**Paginated:** Yes (offset/limit).

**Examples:**
```
types() → First 500 types
types(pattern="stream", limit=100) → Search for stream-related types
types(offset=50, limit=50) → Next page
```

---

### `type_info`

**Purpose:** Get detailed type information (members, enum values, etc.) by type name. Batch-capable.

**Parameters:**
- `items` (array of strings, required): Type names to look up (short name or full path)

**Returns:** Array of dicts, each with:
- **On success:** `TypeDetails` with name, full_path, type_string, kind, size, comment, members[] (for struct/union), values[] (for enum), underlying_type (for typedef)
- **On failure:** `{target, error}`

**Batch-capable:** Yes.

---

### `create_struct`

**Purpose:** Create a new structure type in the Ghidra type database.

**Parameters:**
- `name` (string, required): Structure name (e.g., `"request_t"`)
- `size` (integer, optional, default: 0): Total size in bytes; 0 = auto-size from fields
- `fields` (array of dicts, optional): Initial fields, each with:
  - `name`: Field name
  - `type`: C-style type string (e.g., `"int"`, `"char *"`)
  - `offset`: Byte offset within structure
  - `comment` (optional): Field comment
- `packed` (boolean, optional, default: false): If true, no padding between fields

**Returns:** `StructureCreationResult` with:
- `name`: Structure name
- `size`: Structure size in bytes
- `created`: Boolean (true if new, false if already existed)
- `message`: Human-readable result summary

**Example:**
```
create_struct(
  name="NetworkPacket",
  fields=[
    {"name": "header_ptr", "type": "void *", "offset": 0},
    {"name": "length", "type": "int", "offset": 8}
  ]
)
```

---

### `add_field`

**Purpose:** Add field(s) to struct(s). Batch-capable. If a field already exists at the offset, it will be replaced. Structure is auto-expanded if needed.

**Parameters:**
- `items` (array of dicts, required): Field addition requests. Each item:
  - `struct_name` (string): Name of the target structure
  - `field_name` (string): New field name
  - `field_type` (string): C-style type string (e.g., `"int"`, `"char *"`)
  - `offset` (integer): Byte offset within structure
  - `comment` (string, optional): Field comment

**Returns:** Array of dicts with `FieldAdditionResult` fields (per-item status).

**Batch-capable:** Yes.

---

## Modification & Patching

### `rename`

**Purpose:** Rename symbol(s) in the database. Batched with per-item error handling. **This modifies the Ghidra database.**

**Parameters:**
- `items` (array of dicts, required): Symbol rename requests. Each item:
  - `new_name` (string, required): New symbol name
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): Existing symbol name
  - At least one of `addr` or `name` must be provided

**Returns:** Array of dicts, each with:
- `addr`: Resolved hex address
- `old_name`: Previous symbol name
- `new_name`: New name applied
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `update_vars`

**Purpose:** Rename and/or retype multiple variables in a function at once. **This modifies the Ghidra database.**

**Parameters:**
- `function_name` (string, required): Name of the function containing the variables
- `variables_to_update` (object, required): Mapping from current variable name to updates:
  - `new_name` (string, optional): New variable name
  - `new_type` (string, optional): New C-style type string
  - At least one of `new_name` or `new_type` per variable

**Returns:** Per-variable status report.

**Example:**
```
update_vars(
  function_name="main",
  variables_to_update={
    "local_8": {"new_name": "buffer", "new_type": "char *"},
    "param_1": {"new_name": "argc"}
  }
)
```

---

### `set_comments`

**Purpose:** Set comment(s) on addresses, functions, or lines (merged 3-in-1 tool). **This modifies the Ghidra database.**

**Parameters:**
- `items` (array of dicts, required): Comment set requests. Each item:
  - `comment` (string, required): Comment text
  - `kind` (string, optional, default: 'both'): Comment type:
    - `'disasm'` → EOL comment at address (requires addr)
    - `'decompiler'` → Pre-comment at decompiler line (requires line and addr or name)
    - `'function'` → Plate comment on function (requires addr or name)
    - `'both'` (default) → Disasm EOL at addr; ALSO decompiler if line given
  - `addr` (hex address, optional): e.g., `"0x401000"`
  - `name` (string, optional): Function name (alternative to addr)
  - `line` (integer, optional): Decompiler line number (for decompiler comments)

**Returns:** Array of dicts, each with:
- `kind`: Comment type applied
- `addr`: Target address
- `message`: Human-readable result (on success)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `get_comment`

**Purpose:** Get function plate comment(s) by address or name. Batch-capable.

**Parameters:**
- `items` (array of dicts, required): Functions to get comments for. Each item:
  - `addr` (hex address, optional)
  - `name` (string, optional)
  - At least one required

**Returns:** Array of dicts, each with:
- `name`: Function name
- `addr`: Function entry point address
- `comment`: Plate comment text (may be empty string)
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `set_prototype`

**Purpose:** Set function prototype(s) to update signature. **This modifies the Ghidra database.** Old signature is saved in the function comment for reference.

**Parameters:**
- `items` (array of dicts, required): Function prototype set requests. Each item:
  - `addr` (hex address, required): Function address
  - `prototype` (string, required): C-style signature, e.g., `"int main(int argc, char **argv)"`

**Returns:** Array of dicts, each with:
- `addr`: Function address
- `name`: Function name
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

### `patch`

**Purpose:** Overwrite bytes at address(es) to modify instruction(s). **This modifies the Ghidra database and is destructive.** Clears existing code unit, writes bytes, re-disassembles.

**Parameters:**
- `items` (array of dicts, required): Patch requests. Each item:
  - `addr` (hex address, required): Target address
  - `hex_bytes` (string, required): New instruction bytes as hex string (e.g., `"90"` for NOP)

**Returns:** Array of dicts, each with:
- `addr`: Patched address
- `error`: null on success; error message on failure

**Batch-capable:** Yes.

---

## Transaction Management

### `begin_trans`

**Purpose:** Start a manual transaction for multiple modifications to be atomic.

**Parameters:**
- `description` (string, required): Human-readable transaction description

**Returns:** `{transaction_id: string}` — ID to pass to `end_trans`.

**When to use:** Most modification tools handle transactions internally. Only use when making multiple modifications that must be atomic.

**Example:**
```
tx = begin_trans("Rename related functions")
# ... call rename, update_vars, etc. ...
end_trans(tx, commit=True)
```

---

### `end_trans`

**Purpose:** End a manual transaction started with `begin_trans`.

**Parameters:**
- `transaction_id` (string, required): ID returned by `begin_trans`
- `commit` (boolean, optional, default: true): True to save changes; False to discard/rollback

**Returns:** `{transaction_id: string, committed: boolean, message: string}`

---

## Scripting & Custom Logic

### `pyghidra` (pyghidra_eval)

**Purpose:** Execute Python code in Ghidra context with full API access. Variables persist between calls for the MCP server lifetime. Last expression is returned (Jupyter-style).

**Parameters:**
- `code` (string, required): Python code to execute. Has access to:
  - `currentProgram` — Ghidra Program object
  - `flat_api` — Ghidra flat API
  - `backend` — MCPyGhidra backend instance
  - `ghidra.*`, `java.*` — Full Ghidra and Java APIs
- `reset` (boolean, optional, default: false): If true, clear persistent session state before executing. Use to start a clean slate.

**Returns:** `ScriptResult` with:
- `result`: Last expression value (Jupyter-style)
- `stdout`: Captured stdout
- `stderr`: Captured stderr
- `output`: Interleaved stdout/stderr (ordered by time)

**Examples:**
```
pyghidra(code="currentProgram.getFunctionManager().getFunctionCount()")
→ Returns count

pyghidra(code="for f in currentProgram.getFunctionManager().getFunctions(True): print(f.getName())")
→ Prints function names to stdout

pyghidra(code="x = 1 + 1\nx") → Returns 2

pyghidra(code="x = 42") then pyghidra(code="x") → Returns 42 (persisted)

pyghidra(code="", reset=True) → Clears session state
```

**Advanced:** RPC Callbacks. If the client supports `mcpy/rpcCallbacks` capability, callback functions are injected into script globals. See [docs/rpc-callbacks.md](./specs/rpc-callbacks.md).

---

## Search & Pattern Matching

### `find_bytes`

**Purpose:** Search binary for byte patterns with wildcard support.

**Parameters:**
- `patterns` (array of strings, required): Byte patterns to search for. Space-separated hex tokens, `??` for wildcard.
  - Example: `["48 8B ?? ??", "55 48 89 E5"]`
- `limit` (integer, optional, default: 1000, max: 10000): Max results per pattern
- `offset` (integer, optional, default: 0): Skip first N results

**Returns:** Array of dicts, each with:
- `pattern`: Input pattern string
- `matches`: Array of `{addr, bytes}` dicts
- `has_more`: True if more results exist beyond limit
- `error`: null on success; error message on failure

**Examples:**
```
find_bytes(patterns=["90"]) → Find all NOP bytes
find_bytes(patterns=["48 8B ?? ??"]) → Find MOV r64, r/m64 variants
find_bytes(patterns=["55 48 89 E5"], limit=10) → First 10 matches of function prologue
```

---

### `find_insns`

**Purpose:** Search for consecutive instruction sequences matching patterns.

**Parameters:**
- `sequences` (array of arrays of dicts, required): Instruction sequences to search for. Each sequence is a list of instruction patterns. Each pattern has:
  - `mnemonic` (string): Instruction mnemonic (e.g., `"PUSH"`, `"MOV"`)
  - `operands` (array of strings, optional): Operands. Glob patterns by default; `/regex/` for regex.
- `limit` (integer, optional, default: 1000, max: 10000): Max results per sequence
- `offset` (integer, optional, default: 0): Skip first N results

**Returns:** Array of dicts, each with:
- `sequence`: Input sequence patterns
- `matches`: Array of `{addr, instructions}` dicts
- `has_more`: True if more results exist beyond limit
- `error`: null on success; error message on failure

**Examples:**
```
find_insns(sequences=[[{"mnemonic": "PUSH", "operands": ["RBP"]}]])
→ Find all PUSH RBP

find_insns(sequences=[[{"mnemonic": "PUSH"}, {"mnemonic": "MOV"}]])
→ PUSH followed by MOV

find_insns(sequences=[[{"mnemonic": "CALL", "operands": ["/.*malloc.*/"]}]])
→ CALL with regex operand match
```

---

## Server & Program Management

### `open_program` (GUI only)

**Purpose:** Open a binary in Ghidra. Imports from disk if needed, opens in a new CodeBrowser with its own MCP server. **Only available in GUI mode; not exposed in headless mode.**

**Parameters:**
- `path_or_name` (string, required): File path on disk (imports and opens) or name of an existing project binary (opens in new CodeBrowser)
- `wait` (boolean, optional, default: true): If true, block until the new MCP server port is registered or timeout
- `timeout` (integer, optional, default: 300): Max seconds to wait for new MCP server (when wait=true)

**Returns:** Dict with:
- `status`: `"ready"`, `"analyzing"`, or `"timeout"`
- `binary`: Name of the opened binary
- `architecture`: Processor/endian/bitness string, or null
- `new_server`: `{host, port}` for the new MCP server, or null
- `analysis_status`: `"complete"`, `"analyzing"`, or `"unknown"`
- `message`: Human-readable summary

**Examples:**
```
open_program(path_or_name="/tmp/firmware.bin")
→ Imports and opens, waits for analysis

open_program(path_or_name="crackme.elf")
→ Opens existing project binary

open_program(path_or_name="/tmp/large.bin", wait=False)
→ Returns immediately (not waiting for analysis)
```

---

## Resources (Read-Only via MCP URI)

MCPyGhidra also exposes several resources (read-only endpoints) accessible via URI rather than tool calls. These are available for streaming or polling context. See [docs/mcp-client-config.md](./mcp-client-config.md) for how to access resources in your client.

### Server Info Resource

**URI:** `server://info`

**Purpose:** Live server metadata including tool version, mode, binary name, architecture, and port.

---

### Binary Metadata

**URI:** `ghidra://program/metadata`

**Purpose:** Binary file info, architecture, base address, file hashes.

---

### Listings & Pagination

**URIs (paginated):**
- `ghidra://functions/{offset}/{limit}` — List functions
- `ghidra://program/segments/{offset}/{limit}` — Memory segments
- `ghidra://imports/{offset}/{limit}` — Imported functions/data
- `ghidra://exports/{offset}/{limit}` — Exported symbols
- `ghidra://strings/{offset}/{limit}` — String literals
- `ghidra://classes/{offset}/{limit}` — C++ classes
- `ghidra://namespaces/{offset}/{limit}` — C++ namespaces
- `ghidra://types/{offset}/{limit}` — All types

---

### Search Resources

**URIs:**
- `ghidra://search/functions/{pattern}` — Search functions by name substring
- `ghidra://search/strings/{pattern}` — Search strings by content substring

---

### Other Resources

- `ghidra://cursor` — Current cursor position and function
- `ghidra://program/entrypoints` — Program entry points
- `ghidra://selection` — Current selection range
- `ghidra://disasm/{addr}/{count}` — Disassembly at address
- `ghidra://bytes/{addr}/{size}` — Raw bytes as hex string
- `ghidra://xrefs/to-func/{identifier}` — Cross-references to function
- `ghidra://type/{type_name}` — Detailed type info

---

## Tool Count & Categories

**Total: 26 tools** (25 standard + 1 GUI-only)

**Core (4):** list, cursor, context, get_funcs  
**Analysis (5):** decompile, disasm, symbols, xrefs, cfg  
**Graphs (1):** callgraph  
**Types (4):** types, type_info, create_struct, add_field  
**Modification (6):** rename, update_vars, set_comments, get_comment, set_prototype, patch  
**Transactions (2):** begin_trans, end_trans  
**Scripting (1):** pyghidra  
**Search (2):** find_bytes, find_insns  
**Program Management (1):** open_program (GUI only)

### Read-Only vs. Write Tools

Tools marked with `readOnlyHint` are read-only and can be disabled via `MCPY_DISABLE_READONLY_TOOLS=1`.

**Read-only:** list, cursor, context, get_funcs, decompile, disasm, symbols, xrefs, cfg, callgraph, types, type_info, find_bytes, find_insns, get_comment

**Write-capable:** rename, update_vars, set_comments, set_prototype, patch, begin_trans, end_trans, create_struct, add_field, pyghidra, open_program

All tools are registered in [`src/mcpyghidra/server.py`](../src/mcpyghidra/server.py); implementations live in `src/mcpyghidra/tools/`.

---

## Next Steps

- **For MCP client setup:** See [docs/mcp-client-config.md](./mcp-client-config.md)
- **For quickstart:** See [docs/quickstart.md](./quickstart.md)
- **For advanced RPC callbacks:** See [docs/rpc-callbacks.md](./specs/rpc-callbacks.md)
- **For architecture details:** See [docs/index.md](./index.md)
