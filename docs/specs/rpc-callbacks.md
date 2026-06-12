# RPC Callbacks Protocol

**Version:** 1.0

## Overview

The RPC Callbacks Protocol extends the Model Context Protocol (MCP) to enable bidirectional function calling. While MCP's standard tool system allows servers to expose functions for clients to invoke, this extension defines the reverse: a mechanism for MCP **servers** to discover and invoke functions provided by the **client**.

The primary use case is exposing client-side capabilities (such as LLM access, web search, file operations, or connections to other MCP servers) as callable functions within a server's scripting environment. For example, a reverse engineering MCP server makes a client's `search_web()` or `ask_llm()` functions available as Python globals inside its `pyghidra_eval` tool.

## Capabilities Declaration

Servers and clients that support this protocol must declare the `mcpy/rpcCallbacks` capability during MCP initialization.

**Server capability (sent in initialize request):**
```json
{
  "capabilities": {
    "experimental": {
      "mcpy/rpcCallbacks": {}
    }
  }
}
```

**Client capability (sent in initialize response):**
```json
{
  "capabilities": {
    "experimental": {
      "mcpy/rpcCallbacks": {
        "listChanged": true
      }
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `listChanged` | boolean | No | If `true`, the client will emit `notifications/mcpy/functions/list_changed` when its available function list changes. |

The client decides which functions to expose based on its configuration and policies. Per-function authorization is managed client-side. If either party does not declare the capability, function callbacks **MUST NOT** be used.

## Messages

### mcpy/listFunctions: Discover Available Functions

After initialization, if both parties declared the `mcpy/rpcCallbacks` capability, the server sends a request to discover what functions the client provides.

**Request (Server → Client):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "mcpy/listFunctions",
  "params": {
    "cursor": "opaque-continuation-token"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cursor` | string | No | Opaque pagination cursor from a prior response's `nextCursor`. Omit for the first request. |

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "functions": [
      {
        "name": "search_web",
        "description": "Search the web for information",
        "parameterOrder": ["query", "max_results"],
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            },
            "max_results": {
              "type": "integer",
              "description": "Maximum number of results to return",
              "default": 10
            }
          },
          "required": ["query"]
        },
        "returnDescription": "Search results as formatted text"
      }
    ],
    "nextCursor": "opaque-continuation-token"
  }
}
```

Each function in the `functions` array contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique function identifier. **MUST** be a valid Python identifier. **MUST NOT** shadow Python builtins, keywords, or existing scripting globals. |
| `description` | string | No | Human-readable description of the function's purpose. |
| `parameterOrder` | array of string | Yes | Ordered list of parameter names defining positional argument order. **MUST** match keys in `inputSchema.properties`. |
| `inputSchema` | object | Yes | JSON Schema object (type: "object") defining the function's parameters and their types. Properties listed in `required` are mandatory; others are optional. |
| `returnDescription` | string | No | Human-readable description of the return value. |
| `annotations` | object | No | Optional metadata (e.g., `title`, `readOnlyHint`, `destructiveHint`). |

The `parameterOrder` array is the authoritative source for argument order; do not rely on JSON object property order.

### notifications/mcpy/functions/list_changed: Function List Update

When the client's available function list changes (e.g., a downstream MCP server connects or disconnects), the client sends a notification:

**Notification (Client → Server):**
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/mcpy/functions/list_changed"
}
```

Upon receiving this notification, the server re-sends `mcpy/listFunctions` to refresh its function list. Functions that were previously available but are no longer listed are removed from the scripting environment. New functions are added. Changes are deferred until the current tool execution completes to prevent mid-execution surprises.

### mcpy/callFunction: Invoke a Client Function

To invoke a client function, the server sends a request:

**Request (Server → Client):**
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "mcpy/callFunction",
  "params": {
    "name": "search_web",
    "arguments": {
      "query": "ghidra struct recovery",
      "max_results": 5
    },
    "_meta": {
      "progressToken": "some-progress-token"
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Name of the function to call. **MUST** match a function from the most recent `mcpy/listFunctions` response. |
| `arguments` | object | No | Arguments to pass to the function. **MUST** conform to the function's `inputSchema`. |
| `_meta` | object | No | MCP metadata object. MAY include `progressToken` for progress reporting. |

**Response (success):**
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": "Results: 1. Ghidra Struct Recovery Tutorial..."
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `content` | any | The raw return value of the function. MAY be a string, number, boolean, null, object, or array. This is a deliberate deviation from MCP's `list[ContentBlock]` pattern: callback return values are raw return values, not MCP content blocks. |

**Response (error):**
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32603,
    "message": "Function 'search_web' failed: connection timeout",
    "data": {
      "name": "search_web",
      "exception": {
        "type": "TimeoutError",
        "message": "connection timeout after 30s",
        "traceback": "Traceback (most recent call last):..."
      }
    }
  }
}
```

Common error codes:

| Code | Scenario |
|------|----------|
| `-32601` | Function not found |
| `-32602` | Invalid arguments (do not conform to `inputSchema`) |
| `-32603` | Internal error; function execution failed |

When raising exceptions in the scripting environment from a remote error response, implementations **SHOULD** attach the remote error as a cause using Python's `raise ... from ...` mechanism.

## Message Flow Example

```
1. Server connects to client
2. Server sends initialize (with mcpy/rpcCallbacks capability)
3. Client responds with initialize (with mcpy/rpcCallbacks capability)
4. Server sends mcpy/listFunctions
5. Client responds with available functions
6. Client invokes a server tool (e.g., pyghidra_eval)
7. Script inside the tool calls search_web() (a callback function)
8. Server sends mcpy/callFunction(search_web, ...)
9. Client executes the function and responds
10. Script receives result and continues
11. Server sends tool result back to client
12. Tool execution completes; callback functions expire
```

## Scripting Integration

Servers project discovered callback functions into the scripting environment by
interpreting `__` separators in a function name as namespace boundaries (see
**Namespace Projection** below):

1. **Flat globals** — a name with no `__` separator is available directly by
   name: `search_web("query")`.
2. **Nested namespaces** — `mcp__ghidra1__list` is projected to
   `mcp.ghidra1.list("...")`. Native `help(mcp.ghidra1.list)` and
   `dir(mcp.ghidra1)` cover documentation and discovery.

A flat `rpc` namespace object (`rpc.available()` / `rpc.help(...)`) is an
**optional, legacy** convenience; the recommended discovery mechanism is native
`help()` / `dir()` on the projected objects, and reference servers no longer
inject `rpc`.

### Namespace Projection

A function name is projected to an attribute path by treating runs of two or
more underscores as a single namespace separator. The projection is purely
mechanical — **no prefixes are hard-coded**.

- **Greedy separators.** A run of 2+ underscores is one separator:
  `mcp___ghidra1` → `mcp.ghidra1`, `a____b` → `a.b`.
- **Leading/trailing/repeated separators collapse.** Empty segments are dropped:
  `__foo` → `foo`, `foo__` → `foo`, `__mcp__ghidra1__list__` → `mcp.ghidra1.list`.
- **Single underscores are preserved** within a segment: `search_web`,
  `find_bytes` stay whole.
- **No segments** (name was all underscores, e.g. `____`) → the function is
  **skipped** with a warning.
- **Hard-keyword segments are escaped** with a leading underscore so they stay
  reachable as dotted attributes (`mcp.import` is a `SyntaxError`):
  `mcp__import__x` → `mcp._import.x`. Applies to every segment position.
  Builtins and soft keywords are valid attribute names and are **not** escaped.
- **Top-level shadow escaping.** Only the first segment becomes a real global. If
  it shadows an existing scripting global or a Python builtin/keyword it is
  escaped with a leading underscore (`list__foo` → `_list.foo`); if the escaped
  name still collides the function is skipped with a warning. Re-using an
  existing namespace **root** is not a collision — `mcp__a__x` and `mcp__b__y`
  both extend the same `mcp` namespace.
- **Leaf-vs-namespace conflict.** If one name wants a callable at `mcp.ghidra1`
  and another wants `mcp.ghidra1` to be a namespace, they cannot share the path.
  Functions are processed in **sorted raw-name order**; the first claim to a path
  wins and the conflicting function is skipped with a warning. The same rule
  covers two raw names that collapse to the same path after parsing/escaping.

### Generating Function Signatures

When creating callable wrappers from `FunctionDefinition` objects:

- Required properties (in `inputSchema.required`) become positional parameters
- Optional properties with defaults become keyword parameters
- Use `parameterOrder` to determine the correct argument order
- Provide a keyword-only `_rpc_timeout` parameter to allow per-call timeout overrides (e.g., `search_web("query", _rpc_timeout=60)`)

### JSON Schema to Python Type Mapping

| JSON Schema type | Python type |
|-----------------|-------------|
| `"string"` | `str` |
| `"integer"` | `int` |
| `"number"` | `float` |
| `"boolean"` | `bool` |
| `"array"` | `list` |
| `"object"` | `dict` |
| `"null"` | `None` |
| `["string", "null"]` | `Optional[str]` |

## Scope and Validity

Callback functions are scoped to the execution lifetime of the tool invocation that triggered them. Once tool execution completes, all callback function handles become invalid and **MUST** raise `RuntimeError("Callback expired")` when invoked.

Implementations **MUST** use an execution-scoped validity token to enforce this expiration, even when closures or local variable bindings capture references to callback functions.

**Example:**
```python
# During execution: works
result = search_web("query")

# After execution completes: raises RuntimeError
saved_fn = search_web           # captured during execution
# ... tool execution ends ...
saved_fn("query")               # raises RuntimeError("Callback expired")
```

## Name Collision Protection

Function names declared in `mcpy/listFunctions` do **not** have to be bare,
collision-free Python identifiers. Servers protect the scripting environment via
the server-side **Namespace Projection** (see *Scripting Integration*), which
handles reserved words and shadowing mechanically:

- **Hard keywords** in any segment (e.g. `import`, `class`) are escaped with a
  leading underscore (`mcp__import` → `mcp._import`) so they remain reachable as
  dotted attributes.
- **Top-level globals** — only the first projected segment becomes an actual
  global / importable root. If it shadows a Python builtin/keyword, an existing
  scripting global (e.g. `list`, `currentProgram`), or **any importable module**
  (a name resolvable via the import system — stdlib, the host's API modules
  (`ghidra`, `ida_*`), or installed packages), it is escaped with a leading
  underscore; if it still collides, the function is **skipped** with a warning.
  Protecting importable names matters because a server may make the projected
  roots importable in the scripting environment, so `import os` must keep
  reaching the real `os`, not a tool named `os__…`. The server's own root
  (conventionally `mcp`) is the one blessed exception — it intentionally
  shadows the unused MCP-SDK package in the REPL.
- **Path conflicts** (leaf-vs-namespace, or two names that collapse to the same
  path) are resolved deterministically in sorted raw-name order: first claim
  wins, the loser is skipped with a warning.

Servers **MUST** check the top-level root against reserved names (Python builtins
+ keywords), existing scripting globals, and importable modules
(`name in sys.modules` or `importlib.util.find_spec(name)`), and **SHOULD** log
every skipped or escaped function.

## Re-Entrancy & Recursion Limits

Implementations **MUST** enforce a maximum callback depth of **3** to prevent accidental infinite recursion or deadlocks (particularly on single-threaded environments like IDA Pro).

**Rules:**
1. Clients **MUST NOT** re-enter the originating server during a callback (i.e., issue a `tools/call` to the same server while handling a `mcpy/callFunction`).
2. If the depth limit is exceeded, the server **MUST** return error code `-32603` with `exception.type: "RecursionError"`.
3. Implementations **MUST** track the current nesting depth across all concurrent callbacks within a single tool execution.

## Security Considerations

### Servers MUST:
- Only invoke functions discovered via `mcpy/listFunctions`
- Validate that function arguments conform to the declared `inputSchema` before sending
- Enforce timeouts on all function calls (default: 30 seconds) to prevent resource exhaustion
- Enforce callback scope expiration via validity tokens, not merely by removing globals
- Enforce maximum callback depth to prevent re-entrancy attacks

### Clients MUST:
- Only expose functions appropriate for the server's context
- Validate incoming `mcpy/callFunction` requests against the published function list
- Apply the same authorization and rate-limiting policies as for direct function invocations
- Not execute functions from servers that did not declare the `mcpy/rpcCallbacks` capability

### Both parties SHOULD:
- Log all function calls for auditing purposes
- Implement rate limiting to prevent abuse
- In production, sanitize tracebacks in `exception.traceback` to remove absolute filesystem paths before transmission

## Error Handling & Exception Mapping

Standard exception types should map to their native equivalents in the scripting environment:

| Remote exception.type | Python Exception |
|-----------------------|------------------|
| `"TypeError"` | `TypeError` |
| `"ValueError"` | `ValueError` |
| `"KeyError"` | `KeyError` |
| `"FileNotFoundError"` | `FileNotFoundError` |
| `"PermissionError"` | `PermissionError` |
| `"RecursionError"` | `RecursionError` |
| `"TimeoutError"` | `TimeoutError` (or custom `RPCTimeoutError`) |
| `"NameError"` | `NameError` |
| *(unrecognized)* | `RuntimeError` |

Servers **MUST** handle gracefully:
- Client disconnection during an in-flight function call
- Function removed between discovery and invocation (raise `NameError`)
- Timeout exceeded (raise `TimeoutError` or custom `RPCTimeoutError`)
- Arguments that do not match the declared schema (raise `TypeError`)

## Related Documentation

- **[MCPyGhidra RPC Callbacks Integration](../tools-reference.md#pyghidra_eval)** — How MCPyGhidra uses RPC callbacks in the `pyghidra_eval` tool
- **[Tools Reference](../tools-reference.md)** — Overview of all MCPyGhidra tools
- **[Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)** — Official MCP specification

## References

This protocol is implemented in MCPyGhidra's:
- `/src/mcpyghidra/rpc_callbacks.py` — Function generation, callback scope, exception mapping
- `/src/mcpyghidra/rpc_types.py` — Pydantic models for protocol messages
