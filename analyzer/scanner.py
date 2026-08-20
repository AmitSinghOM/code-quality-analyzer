"""Python project scanner assembled from language-neutral plugins."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .discovery import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_FILES,
    DiscoveryReport,
    display_path,
    iter_source_files,
)
from .findings import Finding
from .package_intelligence import PackageIntelligence
from .patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from .plugins import create_default_registry
from .protocols import ParsedFile, ProjectContext, ProviderResult, SourceFile
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
        self.language_counts: dict[str, int] = {}

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
        self.parsed_files: dict[str, dict[str, ParsedFile]] = {}
        self.project_results: dict[tuple[str, str], ProviderResult] = {}
        self.package_intelligence = PackageIntelligence()
        self.package_health = {"errors": 0, "complete": True}

    def scan(self) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Scan all bounded files supported by the active registry."""
        for path, content in iter_source_files(
            self.project_path,
            self.registry.source_extensions(),
            max_file_size=self.max_file_size,
            max_files=self.max_files,
            report=self.discovery,
        ):
            self._scan_file(path, content)
        self._run_default_project_providers()
        return self.dsa_found, self.design_found

    def _project_context(self, language_id: str) -> ProjectContext:
        return ProjectContext(
            root=self.project_path,
            parsed_files=self.parsed_files.get(language_id, {}),
            max_file_size=self.max_file_size,
            max_files=self.max_files,
            redact_paths=self.redact_paths,
        )

    def _run_default_project_providers(self) -> None:
        for provider in self.registry.default_project_providers():
            self._run_project_provider(
                provider.language_id,
                provider.capability,
            )
        self._sort_findings()

    def run_project_provider(
        self,
        language_id: str,
        capability: str,
    ) -> ProviderResult | None:
        """Run one registered optional project provider once."""
        result = self.project_results.get((language_id, capability))
        if result is not None:
            return result
        result = self._run_project_provider(language_id, capability)
        self._sort_findings()
        return result

    def _run_project_provider(
        self,
        language_id: str,
        capability: str,
    ) -> ProviderResult | None:
        provider = self.registry.negotiate_project_provider(
            language_id,
            capability,
            optional=True,
        )
        if provider is None:
            return None
        result = provider.analyze(self._project_context(language_id))
        self.project_results[(language_id, capability)] = result
        self.findings.extend(result.findings)
        if capability == "package" and isinstance(
            result.payload,
            PackageIntelligence,
        ):
            self.package_intelligence = result.payload
            self.package_health = dict(result.health)
        return result

    def _sort_findings(self) -> None:
        self.findings.sort(
            key=lambda item: (
                item.location.path,
                item.location.line,
                item.location.column,
                item.rule_id,
            )
        )

    def _scan_file(self, path: Path, content: str) -> None:
        adapter = self.registry.adapter_for_path(path)
        if adapter is None:  # Discovery only yields registered extensions.
            return

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
        parsed = adapter.parse(source)
        self.files_scanned += 1
        self.total_lines += parsed.line_count
        self.language_counts[adapter.language_id] = (
            self.language_counts.get(adapter.language_id, 0) + 1
        )
        if not parsed.complete:
            self.unparsed_files += 1
            return

        self.parsed_files.setdefault(adapter.language_id, {})[
            internal_path
        ] = parsed
        for rule_pack in self.registry.rule_packs_for(adapter.language_id):
            self.findings.extend(rule_pack.evaluate(parsed))

        if adapter.language_id != "python":
            return
        if not isinstance(parsed.facts, FileSignals):
            raise TypeError("Python adapter must provide FileSignals facts")

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
        health["languages"] = dict(sorted(self.language_counts.items()))
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
