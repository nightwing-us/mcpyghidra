"""Port-spec parsing and first-free-port binding for MCP servers.

Pure stdlib — no Ghidra/JPype or FastMCP dependency, so it is unit-testable
with real sockets and shared by both the headless launcher and the GUI plugin.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Set as AbstractSet

DEFAULT_PORT_SPEC = '6050-6059'


def _port_int(token: str) -> int:
    token = token.strip()
    if not token.isdigit():  # rejects '', signs, non-numeric
        raise ValueError(f'invalid port: {token!r}')
    value = int(token)
    if value != 0 and not (1 <= value <= 65535):
        raise ValueError(f'port out of range (0 or 1-65535): {value}')
    return value


def parse_port_spec(spec: str | int) -> list[int]:
    """Parse a --port spec into an ordered candidate list.

    "6050-6059" -> [6050, ..., 6059] (inclusive); "6050" -> [6050];
    "0" / 0 -> [0] (OS auto-assign sentinel).
    Raises ValueError on malformed input, end < start, or out-of-range ports.
    """
    text = str(spec).strip()
    if '-' in text:
        lo_s, _, hi_s = text.partition('-')
        lo, hi = _port_int(lo_s), _port_int(hi_s)
        if hi < lo:
            raise ValueError(f'port range end {hi} < start {lo}')
        return list(range(lo, hi + 1))
    return [_port_int(text)]


def bind_listen_socket(
    host: str,
    candidates: list[int],
    *,
    exclude: AbstractSet[int] = frozenset(),
) -> tuple[socket.socket, int]:
    """Create a listening socket bound to the first candidate that binds.

    Sets SO_REUSEADDR + SO_LINGER(1,0); skips any non-zero port in `exclude`;
    candidates == [0] means OS auto-assign. Does bind + listen(100) +
    setblocking(False) and returns (socket, actual_port). Raises OSError if no
    candidate binds.
    """
    last_err: OSError | None = None
    for port in candidates:
        if port != 0 and port in exclude:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        try:
            sock.bind((host, port))
        except OSError as e:
            last_err = e
            sock.close()
            continue
        sock.listen(100)
        sock.setblocking(False)
        return sock, sock.getsockname()[1]
    raise OSError(f'no free port among {candidates} on {host}: {last_err}')
