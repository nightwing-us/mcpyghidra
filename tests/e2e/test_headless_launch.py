"""E2E test: prove that headless launch works.

This test IS the contract for MCP client integration.
If it passes, any MCP client can launch mcpyghidra-headless
and connect to the server.

Uses the MCP client library (mcp package) for proper protocol-level
communication, not raw HTTP POST.
"""
import anyio

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Timeout for individual MCP tool calls (seconds)
MCP_CALL_TIMEOUT = 30


class TestHeadlessLaunch:
    """Validate the headless launch contract."""

    def test_server_reports_ready(self, headless_server):
        """Server process launched and reported ready with valid status."""
        assert headless_server['status'] == 'ready'
        assert headless_server['port'] > 0
        assert headless_server['host'] == '127.0.0.1'
        assert 'crackme' in headless_server['binary']

    def test_mcp_endpoint_reachable(self, headless_server):
        """MCP endpoint responds to client initialize."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 1,
        })
        # If we got here without exception, the endpoint is reachable
        assert result is not None

    def test_list_functions_finds_main(self, headless_server):
        """Can call 'list' tool and find 'main' in our test binary."""
        result = mcp_call(headless_server, 'list', {
            'entry_type': 'function',
            'offset': 0,
            'limit': 100,
        })
        assert 'main' in result, (
            f'Expected "main" in function list, got: {result[:500]}'
        )

    def test_decompile_main(self, headless_server):
        """Can decompile 'main' and see call to check_password."""
        result = mcp_call(headless_server, 'decompile', {
            'items': [{'name': 'main'}],
        })
        assert 'check_password' in result, (
            f'Expected "check_password" in decompilation, got: {result[:500]}'
        )


async def _mcp_call(url: str, tool_name: str, arguments: dict) -> str:
    """Call an MCP tool via the streamable HTTP transport and return text content.

    Uses anyio.fail_after for timeout protection — prevents tests from
    hanging indefinitely if the server accepts the connection but stalls.
    """
    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with anyio.fail_after(MCP_CALL_TIMEOUT):
                result = await session.call_tool(tool_name, arguments)
            # Check for MCP-level errors before extracting content
            if result.isError:
                error_texts = [
                    item.text for item in result.content if hasattr(item, 'text')
                ]
                raise AssertionError(
                    f"MCP tool '{tool_name}' returned error: {' '.join(error_texts)}"
                )
            # result is CallToolResult; extract text from content list
            texts = [
                item.text
                for item in result.content
                if hasattr(item, 'text')
            ]
            return '\n'.join(texts)


def mcp_call(server_status: dict, tool_name: str, arguments: dict) -> str:
    """Synchronous wrapper around _mcp_call for use in pytest test methods."""
    url = f"http://{server_status['host']}:{server_status['port']}/mcp"
    return anyio.run(_mcp_call, url, tool_name, arguments)
