"""Bounded changed-line finding selection for CI workflows."""

from __future__ import annotations

import bisect
import json
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .findings import Finding

CHANGED_LINES_SCHEMA_VERSION = "1.0.0"
MAX_MANIFEST_SIZE = 5 * 1024 * 1024
MAX_FILES = 20_000
MAX_RANGES = 100_000
MAX_PATH_LENGTH = 4_096
MAX_LINE = 2_147_483_647
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


class ChangedLinesError(ValueError):
    """Raised when changed-line selection input is unsafe or invalid."""


@dataclass(frozen=True, slots=True, order=True)
class LineRange:
    """One inclusive changed-line interval."""

    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class ChangedLineSelection:
    """Canonical project-relative changed-line intervals."""

    files: Mapping[str, tuple[LineRange, ...]]

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def range_count(self) -> int:
        return sum(len(ranges) for ranges in self.files.values())

    def select(self, findings: Iterable[Finding]) -> tuple[Finding, ...]:
        """Return findings whose inclusive spans overlap changed lines."""
        selected = []
        for finding in findings:
            location = finding.location
            identity = location.identity_path or location.path
            path = _validate_path(identity, internal=True)
            start_line = _finding_line(location.line)
            raw_end_line = (
                location.end_line
                if location.end_line is not None
                else start_line
            )
            end_line = _finding_line(raw_end_line)
            if end_line < start_line:
                raise ChangedLinesError(
                    "A finding contains an invalid source span."
                )
            ranges = self.files.get(path)
            if ranges and _overlaps(ranges, start_line, end_line):
                selected.append(finding)
        return tuple(selected)

    def summary(self, input_findings: int, selected_findings: int) -> dict:
        """Return aggregate-only report metadata."""
        return {
            "schema_version": CHANGED_LINES_SCHEMA_VERSION,
            "file_count": self.file_count,
            "range_count": self.range_count,
            "input_findings": input_findings,
            "selected_findings": selected_findings,
        }


def load_changed_lines(path: Path) -> ChangedLineSelection:
    """Load and strictly validate one bounded changed-lines manifest."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ChangedLinesError(
                "Changed-lines manifest must be a regular file."
            )
        if metadata.st_size > MAX_MANIFEST_SIZE:
            raise ChangedLinesError(
                "Changed-lines manifest exceeds the 5 MB safety limit."
            )
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
        )
    except ChangedLinesError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ChangedLinesError(
            "Changed-lines manifest is not readable valid UTF-8 JSON."
        ) from error

    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "files",
    }:
        raise ChangedLinesError(
            "Changed-lines manifest has an invalid top-level structure."
        )
    if payload["schema_version"] != CHANGED_LINES_SCHEMA_VERSION:
        raise ChangedLinesError(
            "Unsupported changed-lines schema; expected 1.0.0."
        )

    file_entries = payload["files"]
    if not isinstance(file_entries, list):
        raise ChangedLinesError(
            "Changed-lines files must be a JSON array."
        )
    if len(file_entries) > MAX_FILES:
        raise ChangedLinesError(
            "Changed-lines manifest contains too many files."
        )

    canonical: dict[str, tuple[LineRange, ...]] = {}
    total_ranges = 0
    for entry in file_entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "ranges"}:
            raise ChangedLinesError(
                "Changed-lines manifest contains an invalid file entry."
            )
        path_value = entry["path"]
        if not isinstance(path_value, str):
            raise ChangedLinesError(
                "Changed-lines manifest contains an invalid path."
            )
        source_path = _validate_path(path_value)
        if source_path in canonical:
            raise ChangedLinesError(
                "Changed-lines manifest contains a duplicate path."
            )
        ranges = entry["ranges"]
        if not isinstance(ranges, list) or not ranges:
            raise ChangedLinesError(
                "Each changed-lines file must contain at least one range."
            )
        total_ranges += len(ranges)
        if total_ranges > MAX_RANGES:
            raise ChangedLinesError(
                "Changed-lines manifest contains too many ranges."
            )
        canonical[source_path] = _canonical_ranges(ranges)

    ordered = {
        path_key: canonical[path_key]
        for path_key in sorted(canonical)
    }
    return ChangedLineSelection(MappingProxyType(ordered))


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ChangedLinesError(
                "Changed-lines manifest contains a duplicate JSON key."
            )
        result[key] = value
    return result


def _canonical_ranges(values: list[object]) -> tuple[LineRange, ...]:
    parsed = []
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "start_line",
            "end_line",
        }:
            raise ChangedLinesError(
                "Changed-lines manifest contains an invalid range."
            )
        start_line = _manifest_line(value["start_line"])
        end_line = _manifest_line(value["end_line"])
        if end_line < start_line:
            raise ChangedLinesError(
                "Changed-lines range end must not precede its start."
            )
        parsed.append(LineRange(start_line, end_line))

    merged = []
    for current in sorted(parsed):
        if merged and current.start_line <= merged[-1].end_line + 1:
            previous = merged[-1]
            merged[-1] = LineRange(
                previous.start_line,
                max(previous.end_line, current.end_line),
            )
        else:
            merged.append(current)
    return tuple(merged)


def _validate_path(value: str, *, internal: bool = False) -> str:
    invalid = (
        not value
        or len(value) > MAX_PATH_LENGTH
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or _SCHEME.match(value) is not None
    )
    parts = value.split("/")
    if invalid or any(part in {"", ".", ".."} for part in parts):
        if internal:
            raise ChangedLinesError(
                "A finding contains an invalid project-relative path."
            )
        raise ChangedLinesError(
            "Changed-lines manifest contains an invalid path."
        )
    return value


def _manifest_line(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_LINE:
        raise ChangedLinesError(
            "Changed-lines range values must be positive 32-bit line numbers."
        )
    return value


def _finding_line(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_LINE:
        raise ChangedLinesError(
            "A finding contains an invalid source span."
        )
    return value


def _overlaps(
    ranges: tuple[LineRange, ...],
    start_line: int,
    end_line: int,
) -> bool:
    index = bisect.bisect_right(
        ranges,
        LineRange(end_line, MAX_LINE),
    ) - 1
    return index >= 0 and ranges[index].end_line >= start_line
