"""Bounded changed-line finding selection for CI workflows."""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .findings import Finding
from .safe_io import SafeReadError, read_bounded_text, read_failure_message

CHANGED_LINES_SCHEMA_VERSION = "1.0.0"
NOT_ANALYZED_EXAMPLE_LIMIT = 10
"""Bound on manifest paths named in files_not_analyzed_examples."""
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
            raw_end_line = location.end_line if location.end_line is not None else start_line
            end_line = _finding_line(raw_end_line)
            if end_line < start_line:
                raise ChangedLinesError("A finding contains an invalid source span.")
            ranges = self.files.get(path)
            if ranges and _overlaps(ranges, start_line, end_line):
                selected.append(finding)
        return tuple(selected)

    def not_analyzed(self, analyzed_paths: Iterable[str]) -> tuple[str, ...]:
        """Manifest files no analyzer saw (review 5, A7).

        A changed file that discovery dropped (unsupported extension, size or
        file limit, minified/bundled, failed to parse) produced no findings, so
        a changed-lines gate passed it silently. Naming them lets the gate say
        "not checked" instead of "clean"; under --strict they are a coverage
        gap."""
        analyzed = set(analyzed_paths)
        return tuple(sorted(path for path in self.files if path not in analyzed))

    def summary(
        self,
        input_findings: int,
        selected_findings: int,
        not_analyzed: tuple[str, ...] = (),
    ) -> dict:
        """Return aggregate-only report metadata (plus bounded examples of
        manifest files that were not analyzed)."""
        return {
            "schema_version": CHANGED_LINES_SCHEMA_VERSION,
            "file_count": self.file_count,
            "range_count": self.range_count,
            "input_findings": input_findings,
            "selected_findings": selected_findings,
            "files_not_analyzed": len(not_analyzed),
            "files_not_analyzed_examples": list(not_analyzed[:NOT_ANALYZED_EXAMPLE_LIMIT]),
        }


def load_changed_lines(path: Path) -> ChangedLineSelection:
    """Load and strictly validate one bounded changed-lines manifest."""
    try:
        payload = json.loads(
            read_bounded_text(path, MAX_MANIFEST_SIZE),
            object_pairs_hook=_strict_object,
        )
    except SafeReadError as error:
        raise ChangedLinesError(
            read_failure_message(error, "Changed-lines manifest", "5 MB")
        ) from error
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise ChangedLinesError(
            "Changed-lines manifest is not readable valid UTF-8 JSON."
        ) from error
    return parse_changed_lines(payload)


def _file_entries(payload: object) -> list:
    """Validate the manifest envelope and return its ``files`` array."""
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "files",
    }:
        raise ChangedLinesError("Changed-lines manifest has an invalid top-level structure.")
    if payload["schema_version"] != CHANGED_LINES_SCHEMA_VERSION:
        raise ChangedLinesError("Unsupported changed-lines schema; expected 1.0.0.")
    file_entries = payload["files"]
    if not isinstance(file_entries, list):
        raise ChangedLinesError("Changed-lines files must be a JSON array.")
    if len(file_entries) > MAX_FILES:
        raise ChangedLinesError("Changed-lines manifest contains too many files.")
    return file_entries


def _file_entry(entry: object) -> tuple[str, list]:
    """Validate one ``{path, ranges}`` entry and return its parts."""
    if not isinstance(entry, dict) or set(entry) != {"path", "ranges"}:
        raise ChangedLinesError("Changed-lines manifest contains an invalid file entry.")
    path_value = entry["path"]
    if not isinstance(path_value, str):
        raise ChangedLinesError("Changed-lines manifest contains an invalid path.")
    ranges = entry["ranges"]
    return _validate_path(path_value), ranges


def parse_changed_lines(payload: object) -> ChangedLineSelection:
    """Strictly validate an already-decoded changed-lines manifest payload.

    Shared by :func:`load_changed_lines` and by producers (delegate mode's
    ``diff_to_manifest``) so anything emitted is guaranteed to be accepted.
    """
    canonical: dict[str, tuple[LineRange, ...]] = {}
    total_ranges = 0
    for entry in _file_entries(payload):
        source_path, ranges = _file_entry(entry)
        if source_path in canonical:
            raise ChangedLinesError("Changed-lines manifest contains a duplicate path.")
        if not isinstance(ranges, list) or not ranges:
            raise ChangedLinesError("Each changed-lines file must contain at least one range.")
        total_ranges += len(ranges)
        if total_ranges > MAX_RANGES:
            raise ChangedLinesError("Changed-lines manifest contains too many ranges.")
        canonical[source_path] = _canonical_ranges(ranges)

    ordered = {path_key: canonical[path_key] for path_key in sorted(canonical)}
    return ChangedLineSelection(MappingProxyType(ordered))


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ChangedLinesError("Changed-lines manifest contains a duplicate JSON key.")
        result[key] = value
    return result


def _canonical_ranges(values: list[object]) -> tuple[LineRange, ...]:
    parsed = []
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "start_line",
            "end_line",
        }:
            raise ChangedLinesError("Changed-lines manifest contains an invalid range.")
        start_line = _manifest_line(value["start_line"])
        end_line = _manifest_line(value["end_line"])
        if end_line < start_line:
            raise ChangedLinesError("Changed-lines range end must not precede its start.")
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
            raise ChangedLinesError("A finding contains an invalid project-relative path.")
        raise ChangedLinesError("Changed-lines manifest contains an invalid path.")
    return value


def _manifest_line(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_LINE:
        raise ChangedLinesError("Changed-lines range values must be positive 32-bit line numbers.")
    return value


def _finding_line(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_LINE:
        raise ChangedLinesError("A finding contains an invalid source span.")
    return value


def _overlaps(
    ranges: tuple[LineRange, ...],
    start_line: int,
    end_line: int,
) -> bool:
    index = (
        bisect.bisect_right(
            ranges,
            LineRange(end_line, MAX_LINE),
        )
        - 1
    )
    return index >= 0 and ranges[index].end_line >= start_line


# --- diff_to_manifest: unified diff text -> changed-lines manifest -----------------
#
# The analyzer never runs git (see docs/CHANGED_LINES.md). A host agent already
# holds `git diff` output, so this converts that text into the manifest schema
# the analyzer consumes. Pure parsing: hunk counts drive the state machine, so a
# content line that happens to start with "+++" or "---" is never mistaken for a
# header.

MAX_DIFF_BYTES = 5 * 1024 * 1024  # matches the manifest safety limit

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_C_ESCAPE = re.compile(r"\\([abfnrtv\\\"]|[0-7]{1,3})")
_C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
}


def _unquote_git_path(raw: str) -> str:
    """Undo git's C-style quoting of unusual paths (``"a\\303\\251.py"``)."""
    if not (raw.startswith('"') and raw.endswith('"') and len(raw) >= 2):
        return raw
    body = raw[1:-1]

    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token in _C_ESCAPES:
            return _C_ESCAPES[token]
        return bytes([int(token, 8)]).decode("latin-1")

    decoded = _C_ESCAPE.sub(replace, body)
    try:
        return decoded.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return decoded


def _header_path(line: str, marker: str) -> str | None:
    """Path named by a ``--- ``/``+++ `` header, or None for /dev/null.

    Strips the conventional ``a/``/``b/`` prefix and any trailing tab-separated
    timestamp that non-git diffs append.
    """
    value = line[len(marker) :].rstrip("\r\n")
    value = value.split("\t", 1)[0]
    if value == "/dev/null":
        return None
    value = _unquote_git_path(value)
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return value


def diff_to_manifest(diff_text: str, *, include_deletions: bool = True) -> dict:
    """Convert unified diff text to a changed-lines manifest (schema 1.0.0).

    Line numbers refer to the post-change (``+++``) side, which is the tree the
    analyzer scans. Added and modified lines become ranges. A pure deletion has
    no post-change line; with ``include_deletions`` it is anchored to the line
    that now follows the removed block so a finding there still counts as
    touched. Deleted files and binary files contribute nothing.

    Raises :class:`ChangedLinesError` when the text is not a unified diff the
    converter can follow, or when the result would not pass the manifest
    validator (over-size, too many files or ranges).
    """
    if not isinstance(diff_text, str):
        raise ChangedLinesError("Diff text must be a string.")
    if len(diff_text.encode("utf-8", "surrogatepass")) > MAX_DIFF_BYTES:
        raise ChangedLinesError("Diff text exceeds the 5 MB safety limit.")

    parser = _DiffWalker(include_deletions)
    for raw_line in diff_text.splitlines():
        parser.feed(raw_line)
    return _manifest_payload(parser.finish())


class _DiffWalker:
    """Line-at-a-time unified diff reader tracking post-change line numbers.

    Hunk counts from the ``@@`` header drive the state: while a hunk still has
    lines outstanding every line is content, so ``+++``/``---`` inside content
    can never be mistaken for a header.
    """

    def __init__(self, include_deletions: bool) -> None:
        self.include_deletions = include_deletions
        self.files: dict[str, list[tuple[int, int]]] = {}
        self.current: str | None = None
        self.old_remaining = 0
        self.new_remaining = 0
        self.new_line = 0
        self.hunks_seen = 0

    @property
    def in_hunk(self) -> bool:
        return self.old_remaining > 0 or self.new_remaining > 0

    def feed(self, line: str) -> None:
        if self.in_hunk:
            self._content(line)
        else:
            self._header(line)

    def finish(self) -> dict[str, list[tuple[int, int]]]:
        if self.in_hunk:
            raise ChangedLinesError("Unified diff ends inside a hunk.")
        if self.hunks_seen == 0:
            raise ChangedLinesError("No unified diff hunks found.")
        return self.files

    # -- headers -------------------------------------------------------------------

    def _header(self, line: str) -> None:
        if line.startswith("+++ "):
            self.current = _header_path(line, "+++ ")
        elif line.startswith(("Binary files ", "GIT binary patch")):
            self.current = None
        else:
            match = _HUNK_HEADER.match(line)
            if match:
                self._open_hunk(match)
        # "--- ", "diff --git", "index", mode/rename lines and commit text are ignored.

    def _open_hunk(self, match: re.Match[str]) -> None:
        self.hunks_seen += 1
        self.old_remaining = int(match.group(2)) if match.group(2) is not None else 1
        self.new_remaining = int(match.group(4)) if match.group(4) is not None else 1
        self.new_line = int(match.group(3))
        if self.new_remaining == 0:
            # Pure deletion hunk: git reports the line *before* the gap.
            self.new_line += 1

    # -- hunk content -------------------------------------------------------------

    def _content(self, line: str) -> None:
        if line.startswith("\\"):
            return  # "\ No newline at end of file"
        tag = line[:1]
        if tag == "+":
            self.new_remaining -= 1
            self._touch(self.new_line)
            self.new_line += 1
        elif tag == "-":
            self.old_remaining -= 1
            if self.include_deletions:
                self._touch(max(self.new_line, 1))
        elif tag in (" ", ""):
            self.old_remaining -= 1
            self.new_remaining -= 1
            self.new_line += 1
        else:
            raise ChangedLinesError("Unified diff hunk contains an unexpected line.")
        if self.old_remaining < 0 or self.new_remaining < 0:
            raise ChangedLinesError("Unified diff hunk is longer than its header declares.")

    def _touch(self, line_number: int) -> None:
        if self.current is not None:
            self.files.setdefault(self.current, []).append((line_number, line_number))


def _manifest_payload(files: dict[str, list[tuple[int, int]]]) -> dict:
    """Canonicalise raw ranges through the shared validator and re-emit them."""
    payload = {
        "schema_version": CHANGED_LINES_SCHEMA_VERSION,
        "files": [
            {
                "path": path,
                "ranges": [{"start_line": start, "end_line": end} for start, end in ranges],
            }
            for path, ranges in sorted(files.items())
        ],
    }
    selection = parse_changed_lines(payload)  # fail closed on anything the analyzer rejects
    return {
        "schema_version": CHANGED_LINES_SCHEMA_VERSION,
        "files": [
            {
                "path": path,
                "ranges": [
                    {"start_line": item.start_line, "end_line": item.end_line}
                    for item in selection.files[path]
                ],
            }
            for path in selection.files
        ],
    }
