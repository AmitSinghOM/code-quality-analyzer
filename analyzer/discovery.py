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
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Iterator

# Directories that never contain first-party source worth rating.
SKIP_DIRS = frozenset({
    '.git', '.hg', '.svn',
    '__pycache__', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.tox',
    '.venv', 'venv', 'env', '.eggs', 'site-packages', 'node_modules',
    'dist', 'build', '.idea', '.vscode',
})

# 2 MB. Anything bigger is generated, vendored, or a data blob.
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024

# Refuse to walk unbounded trees.
DEFAULT_MAX_FILES = 20_000


@dataclass
class DiscoveryReport:
    """Accounting for a discovery pass."""

    files_found: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    skipped_examples: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False

    def skip(self, reason: str, path: Path) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        examples = self.skipped_examples.setdefault(reason, [])
        if len(examples) < 3:
            examples.append(str(path))

    @property
    def total_skipped(self) -> int:
        return sum(self.skipped.values())

    def as_dict(self) -> dict:
        return {
            "files_found": self.files_found,
            "total_skipped": self.total_skipped,
            "skipped_by_reason": dict(sorted(self.skipped.items())),
            "skipped_examples": self.skipped_examples,
            "truncated": self.truncated,
        }


def iter_python_files(
    root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_files: int = DEFAULT_MAX_FILES,
    report: DiscoveryReport | None = None,
) -> Iterator[tuple[Path, str]]:
    """Yield ``(path, source_text)`` for each safe-to-read Python file.

    ``path`` is the on-disk path as walked (so it stays relative-able to
    ``root``); decoding and size checks have already passed.
    """
    root = Path(root).resolve()
    report = report if report is not None else DiscoveryReport()

    for path in _candidate_paths(root, max_files, report):
        text = read_source(path, root, max_file_size, report)
        if text is None:
            continue
        report.files_found += 1
        yield path, text


def _candidate_paths(
    root: Path, max_files: int, report: DiscoveryReport
) -> Iterator[Path]:
    seen = 0
    # followlinks=False: symlinked directories are not descended into.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith('.py'):
                continue
            if seen >= max_files:
                report.truncated = True
                return
            seen += 1
            yield Path(dirpath) / name


def read_source(
    path: Path,
    root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    report: DiscoveryReport | None = None,
) -> str | None:
    """Read ``path`` if it is safe to do so, else record a skip and return None."""
    report = report if report is not None else DiscoveryReport()

    # Symlink escape: a link inside the tree pointing at, say,
    # ~/.aws/credentials must not be read.
    try:
        resolved = path.resolve()
    except OSError:
        report.skip('unresolvable', path)
        return None
    if not _is_within(resolved, root):
        report.skip('outside_project_root', path)
        return None

    try:
        info = resolved.stat()
    except OSError:
        report.skip('stat_failed', path)
        return None

    # FIFOs and character devices block forever on read.
    if not stat.S_ISREG(info.st_mode):
        report.skip('not_regular_file', path)
        return None

    if info.st_size > max_file_size:
        report.skip('too_large', path)
        return None

    try:
        return resolved.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        report.skip('undecodable', path)
    except OSError:
        report.skip('read_failed', path)
    return None


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        return candidate == root or candidate.is_relative_to(root)
    except AttributeError:  # pragma: no cover - Python < 3.9
        return str(candidate).startswith(str(root) + os.sep)


def display_path(path: Path, root: Path, redact: bool = False) -> str:
    """Path for reports: project-relative when possible, never absolute."""
    try:
        rel = str(Path(path).relative_to(root))
    except ValueError:
        rel = Path(path).name
    if redact:
        parts = Path(rel).parts
        return parts[-1] if parts else rel
    return rel
