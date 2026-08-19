"""Python project scanner assembled from language-neutral plugins."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .discovery import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    DiscoveryReport,
    display_path,
    iter_python_files,
)
from .findings import Finding
from .package_intelligence import PackageIntelligence, PythonPackageAnalyzer
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from .plugins import create_default_registry
from .protocols import LanguageAdapter, RulePack, SourceFile
from .registry import PluginRegistry
from .signals import FileSignals, pattern_is_present


@dataclass
class PatternHit:
    """One file's evidence for one pattern."""

    file: str
    signals: list[str] = field(default_factory=list)


class CodeScanner:
    """Scan Python through a registered adapter and normalized rule packs."""

    def __init__(
        self,
        project_path: str | Path,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_files: int = DEFAULT_MAX_FILES,
        redact_paths: bool = False,
        registry: PluginRegistry | None = None,
    ):
        self.project_path = Path(project_path).resolve()
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.redact_paths = redact_paths
        self.registry = registry or create_default_registry()
        self.language_adapter: LanguageAdapter = self.registry.language(
            "python"
        )
        self.rule_packs: tuple[RulePack, ...] = self.registry.rule_packs_for(
            "python"
        )

        self.files_scanned = 0
        self.total_lines = 0
        self.unparsed_files = 0
        self.discovery = DiscoveryReport(
            root=self.project_path,
            redact_paths=redact_paths,
        )

        self.dsa_found: dict[str, list[str]] = {}
        self.design_found: dict[str, list[str]] = {}
        self.dsa_evidence: dict[str, list[PatternHit]] = {}
        self.design_evidence: dict[str, list[PatternHit]] = {}
        self.findings: list[Finding] = []
        self.parsed_files: dict[str, object] = {}
        self.package_intelligence = PackageIntelligence()
        self.package_health = {"errors": 0, "complete": True}

    def scan(self) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Scan all bounded Python files in the project."""
        for path, content in iter_python_files(
            self.project_path,
            max_file_size=self.max_file_size,
            max_files=self.max_files,
            report=self.discovery,
        ):
            self._scan_file(path, content)
        self._analyze_package()
        return self.dsa_found, self.design_found

    def _analyze_package(self) -> None:
        analyzer = PythonPackageAnalyzer(
            self.project_path,
            self.parsed_files,
            redact_paths=self.redact_paths,
        )
        self.package_intelligence = analyzer.analyze()
        self.package_health = analyzer.analysis_health()
        self.findings.extend(analyzer.findings)
        self.findings.sort(
            key=lambda item: (
                item.location.path,
                item.location.line,
                item.location.column,
                item.rule_id,
            )
        )

    def _scan_file(self, path: Path, content: str) -> None:
        internal_path = display_path(path, self.project_path, redact=False)
        report_path = display_path(
            path,
            self.project_path,
            self.redact_paths,
        )
        source = SourceFile(
            path=path,
            display_path=report_path,
            identity_path=internal_path,
            content=content,
        )
        parsed = self.language_adapter.parse(source)
        self.files_scanned += 1
        self.total_lines += parsed.line_count
        if not parsed.complete:
            self.unparsed_files += 1
            return
        if not isinstance(parsed.facts, FileSignals):
            raise TypeError("Python adapter must provide FileSignals facts")

        if parsed.artifact is not None:
            self.parsed_files[internal_path] = parsed.artifact
            for rule_pack in self.rule_packs:
                self.findings.extend(rule_pack.evaluate(parsed))

        signals = parsed.facts
        for name, definition in DSA_PATTERNS.items():
            present, matched = pattern_is_present(signals, definition)
            if present:
                self._record(
                    self.dsa_found,
                    self.dsa_evidence,
                    name,
                    report_path,
                    matched,
                )

        for name, definition in SYSTEM_DESIGN_PATTERNS.items():
            present, matched = pattern_is_present(signals, definition)
            if present:
                self._record(
                    self.design_found,
                    self.design_evidence,
                    name,
                    report_path,
                    matched,
                )

    @staticmethod
    def _record(
        found: dict[str, list[str]],
        evidence: dict[str, list[PatternHit]],
        pattern: str,
        relative_path: str,
        matched,
    ) -> None:
        found.setdefault(pattern, []).append(relative_path)
        evidence.setdefault(pattern, []).append(
            PatternHit(file=relative_path, signals=list(matched))
        )

    def evidence_for(self, pattern: str) -> list[PatternHit]:
        """Return evidence rows for a pattern from either category."""
        return (
            self.dsa_evidence.get(pattern)
            or self.design_evidence.get(pattern)
            or []
        )

    def scan_health(self) -> dict:
        """Describe what was and was not analyzed."""
        health = self.discovery.as_dict()
        health["files_scanned"] = self.files_scanned
        health["unparsed_files"] = self.unparsed_files
        health["package_analysis"] = self.package_health
        return health

    @property
    def has_coverage_gaps(self) -> bool:
        """Return whether any requested Python analysis was incomplete."""
        return (
            self.discovery.total_skipped > 0
            or self.discovery.truncated
            or self.unparsed_files > 0
            or self.package_health.get("errors", 0) > 0
        )
