"""Shared bounded manifest discovery and hardened XML parsing.

Used by language pilots whose package intelligence reads build
manifests in nested directories (Maven/Gradle modules, .NET projects).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterable, Mapping
from pathlib import Path

MAX_MANIFESTS = 100
MAX_MANIFEST_BYTES = 1024 * 1024

_XML_UNSAFE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def discover_manifest_dirs(
    root: Path,
    parsed_files: Mapping[str, object],
    filenames: Iterable[str],
) -> tuple[list[str], bool]:
    """Return sorted project-relative directories holding any manifest.

    Candidates are the scan root and every directory enclosing an
    analyzed file, so excluded trees are never probed.
    """
    names = tuple(filenames)
    found = discover_manifests(
        root,
        parsed_files,
        lambda directory: next(
            (name for name in names if (directory / name).is_file()),
            None,
        ),
    )
    return [directory for directory, _ in found[0]], found[1]


def discover_manifests(
    root: Path,
    parsed_files: Mapping[str, object],
    locate,
) -> tuple[list[tuple[str, str]], bool]:
    """Return sorted (directory, filename) pairs chosen by ``locate``.

    ``locate`` receives an absolute candidate directory and returns the
    manifest filename found there, or ``None``. Candidates are the scan
    root and every directory enclosing an analyzed file.
    """
    candidates = {""}
    for identity_path in parsed_files:
        parts = identity_path.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            candidates.add("/".join(parts[:depth]))
    present = []
    for directory in sorted(candidates):
        if ".." in directory.split("/"):
            continue
        filename = locate(root / directory)
        if filename is not None:
            present.append((directory, filename))
    return present[:MAX_MANIFESTS], len(present) > MAX_MANIFESTS


def locate_glob(pattern: str):
    """Build a ``locate`` callable that picks the first file matching a glob."""

    def _locate(directory: Path) -> str | None:
        matches = sorted(path.name for path in directory.glob(pattern) if path.is_file())
        return matches[0] if matches else None

    return _locate


def nearest_manifest_dir(
    identity_path: str,
    manifest_dirs: Iterable[str],
) -> str | None:
    """Return the closest enclosing manifest directory for a file."""
    known = set(manifest_dirs)
    parts = identity_path.split("/")[:-1]
    for depth in range(len(parts), -1, -1):
        prefix = "/".join(parts[:depth])
        if prefix in known:
            return prefix
    return None


def manifest_chain(directory: str, manifest_dirs: Iterable[str]) -> list[str]:
    """Return manifest directories from ``directory`` to the root."""
    known = set(manifest_dirs)
    parts = directory.split("/") if directory else []
    return [
        "/".join(parts[:depth])
        for depth in range(len(parts), -1, -1)
        if "/".join(parts[:depth]) in known
    ]


def manifest_report_path(
    directory: str,
    filename: str,
    redact_paths: bool,
) -> tuple[str, str]:
    """Return (report path, identity path) for a manifest file."""
    identity = f"{directory}/{filename}" if directory else filename
    return (filename if redact_paths else identity), identity


def parse_xml_hardened(text: str) -> ElementTree.Element:
    """Parse XML from an untrusted repository, failing closed.

    Documents declaring a DOCTYPE or entities are rejected outright so
    entity expansion and external-entity resolution can never occur;
    the standard library parser is otherwise used unchanged.
    """
    if _XML_UNSAFE.search(text):
        raise ValueError("XML declares a DOCTYPE or entity")
    try:
        # S314: every known XML attack on the stdlib parser (billion laughs,
        # quadratic blowup, external entities, DTD retrieval) requires a
        # DOCTYPE or ENTITY declaration, which the check above rejects
        # before parsing; the input is also size-bounded by the caller.
        return ElementTree.fromstring(text)  # noqa: S314
    except ElementTree.ParseError as error:
        raise ValueError(f"invalid XML: {error}") from error


def local_name(tag: str) -> str:
    """Strip an XML namespace from an element tag."""
    return tag.rpartition("}")[2]
