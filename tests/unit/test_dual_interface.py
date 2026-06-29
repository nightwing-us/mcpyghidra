"""Schema + registration tests for the dual tool interface (no JVM)."""
from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

from mcpyghidra.server import McpToolRegistration


class _FakeBackend:
    is_headless = True


def test_funcs_registered_get_funcs_absent():
    names = {t[1] for t in McpToolRegistration(_FakeBackend()).iter_tools()}
    assert "funcs" in names
    assert "get_funcs" not in names


def test_types_tool_removed():
    names = {t[1] for t in McpToolRegistration(_FakeBackend()).iter_tools()}
    assert "types" not in names
    assert "type_info" in names  # the resolver stays


def _schema(tool_name: str) -> dict:
    reg = McpToolRegistration(_FakeBackend())
    mcp = FastMCP("t")
    for method_name, name, ann, _ro in reg.iter_tools():
        mcp.tool(name, annotations=ann)(getattr(reg, method_name))
    tools = asyncio.run(mcp.list_tools())
    return next(t for t in tools if t.name == tool_name).inputSchema


def test_decompile_schema_items_not_required_and_flat_present():
    s = _schema("decompile")
    assert "items" not in (s.get("required") or [])
    props = set(s.get("properties", {}))
    assert {"items", "addr", "name"} <= props


def test_funcs_schema_flat_target():
    s = _schema("funcs")
    assert "items" not in (s.get("required") or [])
    assert {"items", "target"} <= set(s.get("properties", {}))


def test_rename_schema_flat_present_items_optional():
    s = _schema("rename")
    assert "items" not in (s.get("required") or [])
    assert {"items", "new_name", "addr", "name"} <= set(s.get("properties", {}))


def test_patch_schema_flat_present():
    s = _schema("patch")
    assert "items" not in (s.get("required") or [])
    assert {"items", "addr", "hex_bytes"} <= set(s.get("properties", {}))


@pytest.mark.parametrize("tool", [
    "decompile", "disasm", "xrefs", "symbols", "type_info", "funcs", "get_comment",
    "rename", "set_comments", "set_prototype", "patch", "add_field",
])
def test_dual_tool_items_not_required(tool):
    s = _schema(tool)
    assert "items" not in (s.get("required") or []), f"{tool}: items must be optional"
    assert "items" in s.get("properties", {}), f"{tool}: items must still be a param"
