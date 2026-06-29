"""Unit tests for portspec (pure, real sockets, no JVM)."""
from __future__ import annotations

import socket

import pytest

from mcpyghidra.portspec import DEFAULT_PORT_SPEC, bind_listen_socket, parse_port_spec


def test_default_spec_constant():
    assert DEFAULT_PORT_SPEC == '6050-6059'
    assert parse_port_spec(DEFAULT_PORT_SPEC) == list(range(6050, 6060))


def test_parse_range():
    assert parse_port_spec('6050-6052') == [6050, 6051, 6052]


def test_parse_single():
    assert parse_port_spec('6050') == [6050]
    assert parse_port_spec(6050) == [6050]


def test_parse_zero_auto_assign():
    assert parse_port_spec('0') == [0]
    assert parse_port_spec(0) == [0]


def test_parse_whitespace_tolerated():
    assert parse_port_spec(' 6050 - 6051 ') == [6050, 6051]


@pytest.mark.parametrize('bad', ['abc', '6051-6050', '0-70000', '', '-5', '70000'])
def test_parse_invalid_raises(bad):
    with pytest.raises(ValueError):
        parse_port_spec(bad)


def test_bind_first_candidate_when_free():
    sock, port = bind_listen_socket('127.0.0.1', [0])  # OS auto-assign
    try:
        assert port > 0
    finally:
        sock.close()


def test_bind_skips_busy_port():
    # Occupy a port, then ask the helper to start there — it must skip to the next.
    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    busy.bind(('127.0.0.1', 0))
    busy.listen(1)
    taken = busy.getsockname()[1]
    try:
        sock, port = bind_listen_socket('127.0.0.1', [taken, taken + 1, taken + 2])
        try:
            assert port != taken and port in (taken + 1, taken + 2)
        finally:
            sock.close()
    finally:
        busy.close()


def test_bind_honours_exclude():
    sock, port = bind_listen_socket('127.0.0.1', [0])
    try:
        free = port
    finally:
        sock.close()
    # exclude the only candidate -> nothing to bind -> OSError
    with pytest.raises(OSError):
        bind_listen_socket('127.0.0.1', [free], exclude={free})


def test_bind_raises_when_all_busy():
    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    busy.bind(('127.0.0.1', 0))
    busy.listen(1)
    taken = busy.getsockname()[1]
    try:
        with pytest.raises(OSError):
            bind_listen_socket('127.0.0.1', [taken])
    finally:
        busy.close()
