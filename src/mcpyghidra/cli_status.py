"""Structured stdout status contract for the headless launcher.

Pure stdlib. Every terminal pre-ready outcome prints one JSON line to stdout so a
background/polling launcher diagnoses the first failure without a foreground
re-run. Mirrors MCPyIDA's cli_status.py (parity); EXIT_CODES adds 'jvm_not_found'
(Ghidra-only; reserved in MCPyIDA).
"""

from __future__ import annotations

import json
import sys

# reason -> exit code (the JSON `reason` is the primary contract; codes secondary)
EXIT_CODES = {
    'binary_not_found': 3,
    'missing_install_dir': 4,
    'bad_port': 5,
    'port_unavailable': 6,
    'open_failed': 7,
    'jvm_not_found': 8,
    'internal': 1,
}


class StartupError(Exception):
    """A pre-ready startup failure carrying a structured reason for emit_error."""

    def __init__(
        self, reason: str, detail: str, remediation: str | None = None
    ) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.remediation = remediation


def emit_ready(host: str, port: int, binary: str) -> None:
    """Print the readiness JSON to stdout (flushed)."""
    print(
        json.dumps({'status': 'ready', 'host': host, 'port': port, 'binary': binary}),
        flush=True,
    )


def emit_error(reason: str, detail: str, *, remediation: str | None = None) -> int:
    """Print {'status':'error','reason':..,'detail':..} to stdout, a human
    remediation line to stderr, and return the mapped exit code. Caller exits."""
    print(
        json.dumps({'status': 'error', 'reason': reason, 'detail': detail}),
        flush=True,
    )
    if remediation is not None:
        print(remediation, file=sys.stderr, flush=True)
    return EXIT_CODES.get(reason, 1)
