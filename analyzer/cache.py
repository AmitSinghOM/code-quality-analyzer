"""Bounded local cache for language-adapter parse artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path

from .protocols import (
    PLUGIN_API_VERSION,
    ParsedArtifactCodec,
    ParsedFile,
    SourceFile,
)

CACHE_SCHEMA_VERSION = "1.0.0"
CACHE_NAMESPACE = "parsed-v1"
MAX_CACHE_ENTRY_SIZE = 16 * 1024 * 1024


class CacheError(ValueError):
    """Raised when an explicitly requested cache cannot be used safely."""


def _reject_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate cache key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str):
    raise ValueError(f"Invalid JSON constant: {value}")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _codec_metadata(codec: ParsedArtifactCodec, source: SourceFile) -> dict:
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "plugin_api_version": PLUGIN_API_VERSION,
        "language_id": codec.language_id,
        "adapter_version": codec.adapter_version,
        "codec_version": codec.cache_codec_version,
        "runtime_version": codec.cache_runtime_version,
        "identity_path": source.identity_path,
        "content_sha256": hashlib.sha256(
            source.content.encode("utf-8")
        ).hexdigest(),
    }


def _cache_key(metadata: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_json(metadata)).hexdigest()


class CacheStore:
    """Best-effort cache whose failures always fall back to parsing."""

    def __init__(self, directory: str | Path) -> None:
        requested = Path(directory).expanduser()
        if requested.is_symlink():
            raise CacheError("Cache directory must not be a symbolic link")
        try:
            requested.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise CacheError("Cache directory could not be created") from error
        if not requested.is_dir():
            raise CacheError("Cache path must be a directory")

        self.directory = requested / CACHE_NAMESPACE
        if self.directory.is_symlink():
            raise CacheError("Cache namespace must not be a symbolic link")
        try:
            self.directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(self.directory, 0o700)
        except OSError as error:
            raise CacheError("Cache namespace could not be secured") from error

    def load(self, adapter: object, source: SourceFile) -> ParsedFile | None:
        """Return a validated cached parse artifact, or a cache miss."""
        if not isinstance(adapter, ParsedArtifactCodec):
            return None
        metadata = _codec_metadata(adapter, source)
        key = _cache_key(metadata)
        path = self.directory / f"{key}.json"
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_size > MAX_CACHE_ENTRY_SIZE
                ):
                    return None
                chunks = []
                remaining = MAX_CACHE_ENTRY_SIZE + 1
                while remaining:
                    chunk = os.read(descriptor, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
            finally:
                os.close(descriptor)
            if len(raw) > MAX_CACHE_ENTRY_SIZE:
                return None
            entry = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
            if not isinstance(entry, dict) or set(entry) != {
                "schema_version", "key", "metadata", "payload"
            }:
                return None
            if (
                entry["schema_version"] != CACHE_SCHEMA_VERSION
                or entry["key"] != key
                or entry["metadata"] != metadata
                or not isinstance(entry["payload"], dict)
            ):
                return None
            parsed = adapter.deserialize_parsed(source, entry["payload"])
            if (
                parsed.source is not source
                or isinstance(parsed.line_count, bool)
                or not isinstance(parsed.line_count, int)
                or parsed.line_count < 0
                or not isinstance(parsed.complete, bool)
            ):
                return None
            return parsed
        except (
            AttributeError,
            json.JSONDecodeError,
            OSError,
            RecursionError,
            TypeError,
            UnicodeError,
            ValueError,
        ):
            return None

    def store(
        self,
        adapter: object,
        source: SourceFile,
        parsed: ParsedFile,
    ) -> None:
        """Atomically store one artifact; cache write failures are non-fatal."""
        if not isinstance(adapter, ParsedArtifactCodec):
            return
        temporary: str | None = None
        descriptor: int | None = None
        try:
            metadata = _codec_metadata(adapter, source)
            key = _cache_key(metadata)
            entry = {
                "schema_version": CACHE_SCHEMA_VERSION,
                "key": key,
                "metadata": metadata,
                "payload": dict(adapter.serialize_parsed(parsed)),
            }
            encoded = _canonical_json(entry)
            if len(encoded) > MAX_CACHE_ENTRY_SIZE:
                return
            descriptor, temporary = tempfile.mkstemp(
                prefix=".cache-",
                dir=self.directory,
            )
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.directory / f"{key}.json")
            temporary = None
        except (OSError, RecursionError, TypeError, ValueError):
            return
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary is not None:
                try:
                    Path(temporary).unlink()
                except OSError:
                    pass
