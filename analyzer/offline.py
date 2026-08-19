"""Process-local network denial for explicitly offline analysis."""

from __future__ import annotations

import socket
from contextlib import contextmanager
from unittest.mock import patch


class OfflineViolationError(RuntimeError):
    """Raised when analysis attempts a network operation in offline mode."""


def _deny_network(*_args, **_kwargs):
    raise OfflineViolationError(
        "Network access was attempted while --offline enforcement was active."
    )


@contextmanager
def enforce_offline(enabled: bool = True):
    """Deny common socket connection and name-resolution entry points."""
    if not enabled:
        yield
        return

    with (
        patch.object(socket, "create_connection", _deny_network),
        patch.object(socket, "getaddrinfo", _deny_network),
        patch.object(socket.socket, "connect", _deny_network),
        patch.object(socket.socket, "connect_ex", _deny_network),
    ):
        yield
