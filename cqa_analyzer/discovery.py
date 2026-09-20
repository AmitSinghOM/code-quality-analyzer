"""Safe source-file discovery.

Shared by the pattern scanner and the complexity analyzer so both apply the
same limits and report the same skip reasons.

Guarantees:
  - Never reads a path that resolves outside the project root (symlink escape).
  - Never reads a non-regular file (FIFO, device, socket) — those can block
    forever on read.
  - Never reads a file larger than ``max_file_size``.
  - Caps the total number of files considered.
  - Records *why* a file was skipped instead of silently dropping it.
  - Leaves minified/bundled assets out (``generated_reason``) and records
    them separately from skips, so a vendored bundle neither produces
    unactionable findings nor marks the analysis non-authoritative.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .config import AnalysisConfig, path_is_selected
from .safe_io import SafeReadError, read_bounded_text

# Directories that never contain first-party source worth rating.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        ".eggs",
        "site-packages",
        "node_modules",
        "dist",
        "build",
        ".idea",
        ".vscode",
        ".next",
        ".nuxt",
        ".turbo",
        ".svelte-kit",
        "out",
        "coverage",
        "bower_components",
        ".yarn",
        ".pnpm-store",
        "target",
        "obj",
        ".gradle",
        ".mvn",
        "TestResults",
        # Vendored third-party code is not the project's own quality signal
        # (staff review C4): Go `vendor/`, C/C++ `third_party/`, CocoaPods,
        # Terraform providers, Bazel output symlinks.
        "vendor",
        "third_party",
        "thirdparty",
        "external",
        "Pods",
        ".terraform",
        "bazel-bin",
        "bazel-out",
        "bazel-testlogs",
        ".kotlin",
        "cmake-build-debug",
        "cmake-build-release",
    }
)

# 2 MB. Anything bigger is generated, vendored, or a data blob.
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024

# Refuse to walk unbounded trees.
DEFAULT_MAX_FILES = 20_000

# Total bytes read across a scan. 20,000 files x 2 MB would be 40 GB held in
# memory as facts; a hostile tree must not be able to OOM the scanner
# (staff review round 2, A3). Reported as truncation, never silently.
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024


@dataclass
class DiscoveryReport:
    """Accounting for a discovery pass with privacy-safe example paths."""

    root: Path | None = field(default=None, repr=False)
    redact_paths: bool = field(default=False, repr=False)
    source_candidates: int = 0
    files_found: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    skipped_examples: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False
    truncated_reasons: list[str] = field(default_factory=list)
    bytes_read: int = 0
    pruned_directories: int = 0
    pruned_examples: list[str] = field(default_factory=list)
    excluded_generated: dict[str, int] = field(default_factory=dict)
    excluded_generated_examples: dict[str, list[str]] = field(default_factory=dict)

    def prune(self, name: str) -> None:
        self.pruned_directories += 1
        if len(self.pruned_examples) < 5 and name not in self.pruned_examples:
            self.pruned_examples.append(name)

    def exclude_generated(self, reason: str, path: Path) -> None:
        """Record a minified/bundled file left out on purpose.

        Deliberate exclusions are accounted like pruned directories, not like
        skips: they do not make the analysis non-authoritative, because a
        vendored bundle is not a coverage gap in the project's own code.
        """
        self.excluded_generated[reason] = self.excluded_generated.get(reason, 0) + 1
        examples = self.excluded_generated_examples.setdefault(reason, [])
        if len(examples) < 3:
            examples.append(self._safe_path(path))

    def truncate(self, reason: str) -> None:
        self.truncated = True
        if reason not in self.truncated_reasons:
            self.truncated_reasons.append(reason)

    def skip(self, reason: str, path: Path) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        examples = self.skipped_examples.setdefault(reason, [])
        if len(examples) < 3:
            examples.append(self._safe_path(path))

    def _safe_path(self, path: Path) -> str:
        return (
            display_path(path, self.root, self.redact_paths)
            if self.root is not None
            else Path(path).name
        )

    @property
    def total_skipped(self) -> int:
        return sum(self.skipped.values())

    def as_dict(self) -> dict:
        return {
            "source_candidates": self.source_candidates,
            "files_found": self.files_found,
            "total_skipped": self.total_skipped,
            "skipped_by_reason": dict(sorted(self.skipped.items())),
            "skipped_examples": self.skipped_examples,
            "truncated": self.truncated,
            "truncated_reasons": list(self.truncated_reasons),
            "bytes_read": self.bytes_read,
            "pruned_directories": self.pruned_directories,
            "pruned_examples": list(self.pruned_examples),
            "excluded_generated": dict(sorted(self.excluded_generated.items())),
            "excluded_generated_examples": self.excluded_generated_examples,
        }


# Minified or bundled assets are not source anyone will fix in place: their
# findings are real shapes but unactionable, and a 40 KB line makes column
# numbers meaningless. Name and content are both consulted, because the
# case that motivated this (a typedoc bundle under ``docs/assets/``) has a
# plain ``.js`` name.
MINIFIED_NAME = re.compile(r"(?:[.-]min|\.bundle|\.pack|\.umd)\.[cm]?[jt]sx?$", re.IGNORECASE)
MINIFIED_LINE_LENGTH = 5_000
"""A line at least this long marks a file as a minification candidate."""
MINIFIED_AVERAGE_LINE_LENGTH = 500
"""...and the file's average line must also be this long (or the file has at
most ten lines), so one generated data table inside ordinary code does not
disqualify the whole file."""
MINIFIED_FEW_LINES = 10
MINIFIED_CONTENT_SUFFIX = re.compile(r"\.[cm]?[jt]sx?$", re.IGNORECASE)
"""Only the JavaScript/TypeScript ecosystem ships minified source, so the
content heuristic is consulted for those extensions alone. A three-line
``constants.py`` holding one 6 KB base64 literal, or a ``schema.go`` with one
long DDL string, is hand-written code that every rule (including the security
family) must still see (review 5, A4)."""


def generated_reason(name: str, text: str) -> str | None:
    """``"minified_name"`` / ``"minified_content"`` when ``text`` should not be
    analyzed as hand-written source, else ``None``."""
    if MINIFIED_NAME.search(name):
        return "minified_name"
    if not MINIFIED_CONTENT_SUFFIX.search(name):
        return None
    lines = text.splitlines() or [""]
    if max(map(len, lines)) < MINIFIED_LINE_LENGTH:
        return None
    if len(lines) <= MINIFIED_FEW_LINES or len(text) / len(lines) >= MINIFIED_AVERAGE_LINE_LENGTH:
        return "minified_content"
    return None


def iter_source_files(
    root: Path,
    extensions: tuple[str, ...],
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    report: DiscoveryReport | None = None,
    analysis: AnalysisConfig | None = None,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> Iterator[tuple[Path, str]]:
    """Yield safe UTF-8 source files matching registered extensions."""
    root = Path(root).resolve()
    report = report if report is not None else DiscoveryReport()
    analysis = analysis or AnalysisConfig()
    if report.root is None:
        report.root = root

    normalized = tuple(
        extension.lower() if extension.startswith(".") else f".{extension.lower()}"
        for extension in extensions
    )
    for path in _candidate_paths(
        root,
        normalized,
        max_files,
        report,
        analysis,
    ):
        text = read_source(path, root, max_file_size, report)
        if text is None:
            continue
        generated = generated_reason(path.name, text)
        if generated is not None:
            report.exclude_generated(generated, path)
            continue
        encoded = len(text.encode("utf-8", "surrogatepass"))
        if report.bytes_read + encoded > max_total_bytes:
            report.truncate("byte_budget")
            return
        report.bytes_read += encoded
        report.files_found += 1
        yield path, text


def iter_python_files(
    root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    report: DiscoveryReport | None = None,
    analysis: AnalysisConfig | None = None,
) -> Iterator[tuple[Path, str]]:
    """Compatibility wrapper for bounded Python-only discovery."""
    yield from iter_source_files(
        root,
        (".py",),
        max_file_size=max_file_size,
        max_files=max_files,
        report=report,
        analysis=analysis,
    )


def _candidate_paths(
    root: Path,
    extensions: tuple[str, ...],
    max_files: int,
    report: DiscoveryReport,
    analysis: AnalysisConfig,
) -> Iterator[Path]:
    seen = 0
    skip = SKIP_DIRS - set(analysis.keep_directories)
    # followlinks=False: symlinked directories are not descended into.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(dirnames):
            if name in skip:
                report.prune(name)
            else:
                kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            if not name.lower().endswith(extensions):
                continue
            path = Path(dirpath) / name
            relative_path = path.relative_to(root).as_posix()
            if not path_is_selected(relative_path, analysis):
                continue
            if seen >= max_files:
                report.truncate("file_limit")
                return
            seen += 1
            report.source_candidates += 1
            yield path


def read_source(
    path: Path,
    root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    report: DiscoveryReport | None = None,
) -> str | None:
    """Read a safe source path or record why it was skipped."""
    report = report if report is not None else DiscoveryReport()
    try:
        return read_bounded_text(path, max_file_size, root=root)
    except FileNotFoundError:
        report.skip("read_failed", path)
    except SafeReadError as error:
        report.skip(error.reason, path)
    return None


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        return candidate == root or candidate.is_relative_to(root)
    except AttributeError:  # pragma: no cover - Python < 3.9
        return str(candidate).startswith(str(root) + os.sep)


def display_path(path: Path, root: Path, redact: bool = False) -> str:
    """Return a project-relative POSIX report path, never an absolute one."""
    try:
        rel = Path(path).relative_to(root).as_posix()
    except ValueError:
        rel = Path(path).name
    if redact:
        parts = Path(rel).parts
        return parts[-1] if parts else rel
    return rel
