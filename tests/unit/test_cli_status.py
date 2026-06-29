"""Unit tests for cli_status (pure, no JVM)."""
from __future__ import annotations

import json

from mcpyghidra.cli_status import EXIT_CODES, StartupError, emit_error, emit_ready


def test_exit_codes_taxonomy():
    assert EXIT_CODES == {
        'binary_not_found': 3, 'missing_install_dir': 4, 'bad_port': 5,
        'port_unavailable': 6, 'open_failed': 7, 'jvm_not_found': 8, 'internal': 1,
    }


def test_emit_ready_shape(capsys):
    emit_ready('127.0.0.1', 6051, '/x/crackme.elf')
    out = json.loads(capsys.readouterr().out)
    assert out == {'status': 'ready', 'host': '127.0.0.1', 'port': 6051,
                   'binary': '/x/crackme.elf'}


def test_emit_error_json_to_stdout_and_code(capsys):
    code = emit_error('bad_port', 'invalid --port', remediation='use N, N-M, or 0')
    cap = capsys.readouterr()
    assert json.loads(cap.out) == {'status': 'error', 'reason': 'bad_port',
                                   'detail': 'invalid --port'}
    assert 'use N, N-M, or 0' in cap.err
    assert code == 5


def test_emit_error_unknown_reason_is_one(capsys):
    assert emit_error('weird', 'x') == 1
    capsys.readouterr()


def test_emit_error_no_remediation_no_stderr(capsys):
    emit_error('internal', 'boom')
    assert capsys.readouterr().err == ''


def test_startup_error_carries_fields():
    e = StartupError('binary_not_found', 'binary not found: /x', 'binary not found: /x')
    assert (e.reason, e.detail, e.remediation) == (
        'binary_not_found', 'binary not found: /x', 'binary not found: /x')
    assert isinstance(e, Exception)
