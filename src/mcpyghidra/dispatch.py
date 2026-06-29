"""Single-or-batch call normalization for MCP tool wrappers.

Pure helpers with no Ghidra/JPype dependency — unit-testable without a JVM.
The only FastMCP coupling is `ToolError` from mcp.server.fastmcp.exceptions.
Used by McpToolRegistration wrappers in server.py to accept either a flat
single call or a batch `items` list, and to mirror the return shape.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp.exceptions import ToolError


def single_or_batch(
    items: list | None,
    flat: dict[str, Any],
    *,
    kind: str,
    empty_hint: str | None = None,
) -> tuple[list, bool]:
    """Normalize a single-or-batch call into (items_list, was_single).

    kind="dict":   a single item is {k: v for k, v in flat.items() if v is not None}.
    kind="scalar": flat has exactly one entry; a single item is its value.

    Rules:
      - items not None AND any flat value set -> ToolError (both)
      - items not None (including [])         -> (items, False)   # batch
      - some flat value set                   -> ([one], True)    # single
      - nothing set                           -> ToolError, naming the fields
        and appending empty_hint when given.
    """
    if kind not in ('dict', 'scalar'):
        raise ValueError(f"kind must be 'dict' or 'scalar', got {kind!r}")
    flat_given = {k: v for k, v in flat.items() if v is not None}
    fields = ', '.join(flat.keys())
    if items is not None and flat_given:
        raise ToolError(f'pass either items=[...] OR {fields}, not both')
    if items is not None:
        return items, False
    if flat_given:
        if kind == 'scalar':
            (value,) = flat_given.values()
            return [value], True
        return [flat_given], True
    msg = f'provide {fields} (or items=[...] for batch)'
    if empty_hint is not None:
        msg += f'. To enumerate, use {empty_hint}'
    raise ToolError(msg)


def unwrap(results: list, was_single: bool) -> Any:
    """Mirror the call shape: a single call returns one dict, batch returns the list."""
    return results[0] if (was_single and len(results) == 1) else results
