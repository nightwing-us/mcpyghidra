"""Unit tests for dispatch.single_or_batch / unwrap (pure, no JVM)."""
from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcpyghidra.dispatch import single_or_batch, unwrap


def test_batch_passthrough_dict():
    assert single_or_batch([{"a": 1}], {"a": None}, kind="dict") == ([{"a": 1}], False)


def test_empty_list_is_batch_not_error():
    assert single_or_batch([], {"a": None}, kind="dict") == ([], False)


def test_single_dict_drops_none():
    items, was_single = single_or_batch(None, {"addr": "0x1", "name": None}, kind="dict")
    assert items == [{"addr": "0x1"}]
    assert was_single is True


def test_single_scalar_builds_value_list():
    items, was_single = single_or_batch(None, {"addr": "0x1"}, kind="scalar")
    assert items == ["0x1"]
    assert was_single is True


def test_invalid_kind_raises_value_error():
    with pytest.raises(ValueError, match="kind must be"):
        single_or_batch([], {"a": None}, kind="bogus")


def test_both_given_raises():
    with pytest.raises(ToolError, match="not both"):
        single_or_batch([{"a": 1}], {"a": "x"}, kind="dict")


def test_neither_given_raises_names_fields():
    with pytest.raises(ToolError, match="addr"):
        single_or_batch(None, {"addr": None, "name": None}, kind="dict")


def test_empty_hint_appended():
    with pytest.raises(ToolError, match=r"list\(entry_type=\"function\"\)"):
        single_or_batch(None, {"target": None}, kind="scalar",
                        empty_hint='list(entry_type="function")')


def test_no_hint_when_none():
    with pytest.raises(ToolError) as e:
        single_or_batch(None, {"target": None}, kind="scalar")
    assert "use " not in str(e.value)


def test_unwrap_single_returns_dict():
    assert unwrap([{"x": 1}], True) == {"x": 1}


def test_unwrap_batch_returns_list():
    assert unwrap([{"x": 1}], False) == [{"x": 1}]


def test_unwrap_single_but_multiple_returns_list():
    assert unwrap([{"x": 1}, {"y": 2}], True) == [{"x": 1}, {"y": 2}]
