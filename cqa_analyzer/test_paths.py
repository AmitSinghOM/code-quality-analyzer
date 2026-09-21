"""Test-path classification shared by every language adapter and rule pack.

This module is a leaf on purpose: it imports nothing from the package so any
module -- including ``python_security``, which ``python_rules`` imports
before the ``languages`` package is initialised -- can use it without
executing ``languages/__init__`` (which imports every adapter, and the
Python adapter imports ``python_rules`` back). Importing
``languages._parity`` from ``python_security`` closed exactly that cycle in
3.2.0; it was latent because the full test run initialised ``languages``
first, and surfaced whenever ``python_rules`` was the first import.
"""

from __future__ import annotations

import re

_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|e2e|integration|testdata)(?:/|$)|"
    r"(?:_test\.go|\.(?:test|spec)\.[cm]?[jt]sx?|Tests?\.(?:kt|cs|java)|"
    r"(?:^|/)test_[^/]*\.py)$",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    """True for paths that conventionally hold tests (Go ``_test.go``, TS
    ``*.spec.ts``, JVM ``*Test.kt``, ``tests/`` and ``__tests__/`` trees)."""
    return _TEST_PATH.search(path.replace("\\", "/")) is not None
