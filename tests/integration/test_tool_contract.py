"""Cross-tool contract conformance (mirrors MCPyIDA's conformance test).

Asserts the shared key vocabulary over every batched read tool:
- addresses under 'addr' (never a bare 'address' key),
- result rows under 'items' (never 'matches'/'result'),
- a top-level 'error' key present on every batched item,
- xrefs accepts addr/name AND the legacy 'target' alias.

Runs against crackme.elf via the session `backend` fixture (skipped without pyghidra).
"""
from __future__ import annotations

import anyio
import pytest

from mcpyghidra.tools import analysis, core, search


def _run(coro_fn, *args, **kwargs):
    return anyio.run(lambda: coro_fn(*args, **kwargs))


LIST_ENTRY_TYPES = ['function', 'import', 'export', 'string', 'class', 'namespace', 'type']


@pytest.mark.parametrize('entry_type', LIST_ENTRY_TYPES)
def test_list_items_use_addr_not_address(backend, entry_type):
    res = _run(core.list_entries, backend, entry_type, 0, 25)
    for item in res.items:
        assert 'address' not in item, f"{entry_type} item leaks 'address': {item!r}"
        # type/namespace/class entries may not carry an address; when present it's 'addr'.
        if entry_type in ('function', 'import', 'export', 'string'):
            assert 'addr' in item, f"{entry_type} item missing 'addr': {item!r}"


def test_segment_items_keep_start_end(backend):
    res = _run(core.list_entries, backend, 'memory_segment', 0, 25)
    for item in res.items:
        assert 'start' in item and 'end' in item


def test_find_bytes_rows_under_items(backend):
    out = _run(search.find_bytes, backend, ['55'], 10, 0)
    entry = out[0]
    assert 'items' in entry and 'matches' not in entry
    assert 'error' in entry
    for row in entry['items']:
        assert 'addr' in row


def test_xrefs_flat_items_and_alias(backend):
    # Resolve a real function address first.
    funcs_out = _run(core.list_entries, backend, 'function', 0, 1)
    addr = funcs_out.items[0]['addr']
    # addr/name form
    out = _run(analysis.xrefs, backend, [{'addr': addr, 'direction': 'to'}])
    item = out[0]
    assert 'result' not in item
    assert 'items' in item
    assert 'error' in item
    assert item['direction'] == 'to'
    # legacy target alias still works
    out2 = _run(analysis.xrefs, backend, [{'target': addr}])
    assert 'items' in out2[0]
    assert out2[0].get('error') is None


def test_batched_read_tools_have_error_key(backend):
    funcs_out = _run(core.list_entries, backend, 'function', 0, 1)
    addr = funcs_out.items[0]['addr']
    name = funcs_out.items[0]['name']
    for out in (
        _run(analysis.decompile, backend, [{'name': name}]),
        _run(analysis.disasm, backend, [{'name': name}]),
        _run(analysis.symbols, backend, [addr]),
        _run(core.funcs, backend, [name]),
    ):
        assert 'error' in out[0], f'batched item missing error key: {out[0]!r}'
