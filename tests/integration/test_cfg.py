"""Integration tests for CFG and callgraph tools."""
from __future__ import annotations

import base64

import pytest



class TestCFG:
    """Test CFG extraction against real Ghidra analysis."""

    def test_cfg_main(self, backend):
        """Extract CFG for main function."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'main')
        assert result.block_count > 0
        assert result.entry is not None
        assert len(result.blocks) == result.block_count

    def test_cfg_normalized_block_count(self, backend):
        """Normalized CFG should have fewer or equal blocks than raw."""
        from mcpyghidra.tools.cfg import cfg_sync
        raw = cfg_sync(backend, 'main', normalize=False)
        normalized = cfg_sync(backend, 'main', normalize=True)
        assert normalized.block_count <= raw.block_count

    def test_cfg_check_password_called_funcs(self, backend):
        """check_password should call strcmp."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'check_password')
        all_called = result.features.called_funcs
        # strcmp should appear (possibly as thunk-resolved name)
        assert any('strcmp' in name for name in all_called.values()), (
            f'Expected "strcmp" in called_funcs values, got: {list(all_called.values())}'
        )

    def test_cfg_with_disassembly(self, backend):
        """include_disassembly adds instruction list to blocks."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'main', include_disassembly=True)
        for block in result.blocks.values():
            assert block.instructions is not None
            assert len(block.instructions) > 0
            assert 'mnemonic' in block.instructions[0]

    def test_cfg_with_bytes(self, backend):
        """include_bytes adds base64 bytes to blocks."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'main', include_bytes=True)
        for block in result.blocks.values():
            assert block.bytes is not None
            decoded = base64.b64decode(block.bytes)
            assert len(decoded) == block.size

    def test_cfg_entry_is_valid_hex(self, backend):
        """Entry point should be a valid hex address string."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'main')
        assert result.entry.startswith('0x')
        int(result.entry, 16)  # Raises ValueError if invalid

    def test_cfg_features_instruction_count(self, backend):
        """Total instruction count should be positive."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'main')
        assert result.features.instruction_count > 0

    def test_cfg_model_dump_by_alias(self, backend):
        """model_dump(by_alias=True) serialises correctly for MCP output."""
        from mcpyghidra.tools.cfg import cfg_sync
        result = cfg_sync(backend, 'main')
        dumped = result.model_dump(by_alias=True)
        assert 'entry' in dumped
        assert 'block_count' in dumped
        assert 'blocks' in dumped
        assert 'features' in dumped


class TestCallgraph:
    """Test callgraph traversal against real Ghidra analysis."""

    def test_callgraph_callees_from_main(self, backend):
        """main should have callees."""
        from mcpyghidra.tools.cfg import callgraph_sync
        result = callgraph_sync(backend, 'main', direction='callees', max_depth=1)
        assert len(result.nodes) > 1  # at least main + one callee
        assert len(result.edges) > 0
        root_nodes = [n for n in result.nodes if n.depth == 0]
        assert len(root_nodes) == 1

    def test_callgraph_callers(self, backend):
        """check_password should have callers (main)."""
        from mcpyghidra.tools.cfg import callgraph_sync
        result = callgraph_sync(backend, 'check_password', direction='callers', max_depth=1)
        assert len(result.nodes) >= 2  # check_password + at least main
        caller_names = [n.name for n in result.nodes if n.depth == 1]
        assert 'main' in caller_names, (
            f'Expected "main" in caller names, got: {caller_names}'
        )

    def test_callgraph_depth_limit(self, backend):
        """Depth limit truncates graph."""
        from mcpyghidra.tools.cfg import callgraph_sync
        shallow = callgraph_sync(backend, 'main', max_depth=1)
        deep = callgraph_sync(backend, 'main', max_depth=3)
        assert len(deep.nodes) >= len(shallow.nodes)

    def test_callgraph_root_node_depth_zero(self, backend):
        """Root function node should have depth 0."""
        from mcpyghidra.tools.cfg import callgraph_sync
        result = callgraph_sync(backend, 'main', direction='callees', max_depth=1)
        root_nodes = [n for n in result.nodes if n.depth == 0]
        assert len(root_nodes) == 1
        assert root_nodes[0].name == 'main'

    def test_callgraph_model_dump_by_alias(self, backend):
        """model_dump(by_alias=True) uses 'from'/'to' aliases on edges."""
        from mcpyghidra.tools.cfg import callgraph_sync
        result = callgraph_sync(backend, 'main', direction='callees', max_depth=1)
        dumped = result.model_dump(by_alias=True)
        assert 'nodes' in dumped
        assert 'edges' in dumped
        assert len(dumped['edges']) > 0, 'main should have callees — alias test needs edges to verify'
        if dumped['edges']:
            edge = dumped['edges'][0]
            assert 'from' in edge, f'Expected "from" alias in edge, got keys: {list(edge.keys())}'
            assert 'to' in edge, f'Expected "to" alias in edge, got keys: {list(edge.keys())}'

    def test_callgraph_direction_field(self, backend):
        """Result includes the direction field."""
        from mcpyghidra.tools.cfg import callgraph_sync
        result = callgraph_sync(backend, 'main', direction='callees')
        assert result.direction == 'callees'

    def test_callgraph_invalid_direction_raises(self, backend):
        """Invalid direction should raise ValueError."""
        from mcpyghidra.tools.cfg import callgraph_sync
        with pytest.raises(ValueError, match="Invalid direction"):
            callgraph_sync(backend, 'main', direction='invalid')
