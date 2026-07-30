"""File scanner and pattern detector."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from .discovery import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    DiscoveryReport,
    display_path,
    iter_python_files,
)
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from .signals import extract_signals, pattern_is_present


@dataclass
class PatternHit:
    """One file's evidence for one pattern."""

    file: str
    signals: List[str] = field(default_factory=list)


class CodeScanner:
    """Scans Python files for DSA and System Design patterns.

    Signals are collected per file. Nothing carries over between files, so a
    single ``import heapq`` cannot make the rest of the project look like it
    uses heaps.
    """

    def __init__(
        self,
        project_path: str | Path,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
        redact_paths: bool = False,
    ):
        self.project_path = Path(project_path).resolve()
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.redact_paths = redact_paths

        self.files_scanned = 0
        self.total_lines = 0
        self.unparsed_files = 0
        self.discovery = DiscoveryReport()

        # pattern -> [file, ...] (kept for backwards compatibility)
        self.dsa_found: Dict[str, List[str]] = {}
        self.design_found: Dict[str, List[str]] = {}
        # pattern -> [PatternHit, ...] with the evidence behind each match
        self.dsa_evidence: Dict[str, List[PatternHit]] = {}
        self.design_evidence: Dict[str, List[PatternHit]] = {}

    def scan(self) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """Scan all Python files in the project."""
        for path, source in iter_python_files(
            self.project_path,
            max_file_size=self.max_file_size,
            max_files=self.max_files,
            report=self.discovery,
        ):
            self._scan_file(path, source)
        return self.dsa_found, self.design_found

    def _scan_file(self, path: Path, source: str) -> None:
        signals = extract_signals(path, source)
        self.files_scanned += 1
        self.total_lines += signals.line_count
        if not signals.parsed:
            self.unparsed_files += 1

        rel = display_path(path, self.project_path, self.redact_paths)

        for name, definition in DSA_PATTERNS.items():
            present, matched = pattern_is_present(signals, definition)
            if present:
                self._record(self.dsa_found, self.dsa_evidence, name, rel, matched)

        for name, definition in SYSTEM_DESIGN_PATTERNS.items():
            present, matched = pattern_is_present(signals, definition)
            if present:
                self._record(self.design_found, self.design_evidence, name, rel, matched)

    @staticmethod
    def _record(
        found: Dict[str, List[str]],
        evidence: Dict[str, List[PatternHit]],
        pattern: str,
        rel_path: str,
        matched,
    ) -> None:
        found.setdefault(pattern, []).append(rel_path)
        evidence.setdefault(pattern, []).append(
            PatternHit(file=rel_path, signals=list(matched))
        )

    def evidence_for(self, pattern: str) -> List[PatternHit]:
        """Evidence rows for a pattern, from either category."""
        return self.dsa_evidence.get(pattern) or self.design_evidence.get(pattern) or []

    def scan_health(self) -> Dict:
        """What was and was not actually analyzed."""
        health = self.discovery.as_dict()
        health["files_scanned"] = self.files_scanned
        health["unparsed_files"] = self.unparsed_files
        return health

    @property
    def has_coverage_gaps(self) -> bool:
        """True when some files could not be analyzed, or the walk was capped."""
        return (
            self.discovery.total_skipped > 0
            or self.discovery.truncated
            or self.unparsed_files > 0
        )
