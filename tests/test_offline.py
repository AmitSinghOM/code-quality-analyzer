"""Explicit offline-enforcement behavior."""

import socket

import pytest

from analyzer.offline import OfflineViolationError, enforce_offline


def test_offline_guard_blocks_socket_entry_points_without_network_access():
    with enforce_offline():
        with pytest.raises(OfflineViolationError):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(OfflineViolationError):
            socket.getaddrinfo("localhost", 80)
        with socket.socket() as client:
            with pytest.raises(OfflineViolationError):
                client.connect(("127.0.0.1", 9))
            with pytest.raises(OfflineViolationError):
                client.connect_ex(("127.0.0.1", 9))


def test_disabled_offline_guard_does_not_patch_name_resolution():
    with enforce_offline(False):
        results = socket.getaddrinfo("localhost", 80)

    assert results
