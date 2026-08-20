"""Python plugins behind the language-neutral extension contracts."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from ..complexity import ProjectComplexityAnalyzer
from ..findings import Finding
from ..package_intelligence import PythonPackageAnalyzer
from ..patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from ..protocols import (
    DEFAULT_CAPABILITY_VERSION,
    PLUGIN_API_VERSION,
    ParsedFile,
    ProjectContext,
    ProviderResult,
    SignalObservation,
    SourceFile,
)
from ..python_rules import PythonRuleAnalyzer
from ..python_suppressions import suppression_lines
from ..registry import PluginRegistry
from ..signals import FileSignals, extract_signals, pattern_is_present

PYTHON_ADAPTER_VERSION = "1.0.0"
PYTHON_RULE_PACK_ID = "python-core"


class PythonLanguageAdapter:
    """Parse Python once and expose its existing facts as an opaque payload."""

    language_id = "python"
    adapter_version = PYTHON_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".py",)

    def parse(self, source: SourceFile) -> ParsedFile:
        signals = extract_signals(source.path, source.content)
        complete = signals.parsed and signals.literals_stripped
        return ParsedFile(
            source=source,
            artifact=signals.tree,
            facts=signals,
            line_count=signals.line_count,
            complete=complete,
        )


class PythonRulePack:
    """Adapt the existing deterministic Python rules to the common contract."""

    rule_pack_id = PYTHON_RULE_PACK_ID
    language_id = "python"
    ruleset_version = "2.12.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self, analyzer: PythonRuleAnalyzer | None = None) -> None:
        self.analyzer = analyzer or PythonRuleAnalyzer()

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not parsed.complete or parsed.artifact is None:
            return ()
        if not isinstance(parsed.artifact, ast.AST):
            raise TypeError("Python rule pack requires a Python AST artifact")
        findings = self.analyzer.analyze(
            parsed.artifact,
            parsed.source.display_path,
            identity_path=parsed.source.identity_path,
        )
        suppressed = suppression_lines(parsed.source.content)
        return tuple(
            finding
            for finding in findings
            if (finding.location.line, finding.rule_id) not in suppressed
        )


class PythonArchitectureSignalProvider:
    """Extract the compatibility DSA and design signal inventory."""

    provider_id = "python-architecture-signals"
    language_id = "python"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        if not isinstance(parsed.facts, FileSignals):
            raise TypeError("Python signal provider requires FileSignals facts")
        for category, definitions in (
            ("architecture.dsa", DSA_PATTERNS),
            ("architecture.design", SYSTEM_DESIGN_PATTERNS),
        ):
            for signal_id, definition in definitions.items():
                present, matched = pattern_is_present(parsed.facts, definition)
                if present:
                    yield SignalObservation(
                        category=category,
                        signal_id=signal_id,
                        description=definition["description"],
                        path=parsed.source.display_path,
                        evidence=tuple(matched),
                    )


class PythonPackageProvider:
    """Provide passive Python package intelligence from shared parse data."""

    provider_id = "python-package"
    language_id = "python"
    capability = "package"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True

    def analyze(self, project: ProjectContext) -> ProviderResult:
        artifacts = {
            path: parsed.artifact
            for path, parsed in project.parsed_files.items()
            if isinstance(parsed.artifact, ast.AST)
        }
        suppressions = {
            path: suppression_lines(parsed.source.content)
            for path, parsed in project.parsed_files.items()
            if isinstance(parsed.artifact, ast.AST)
        }
        analyzer = PythonPackageAnalyzer(
            project.root,
            artifacts,
            redact_paths=project.redact_paths,
            suppressions_by_path=suppressions,
        )
        payload = analyzer.analyze()
        return ProviderResult(
            payload=payload,
            health=analyzer.analysis_health(),
            findings=tuple(analyzer.findings),
        )


class PythonComplexityProvider:
    """Provide optional legacy Python complexity estimates via the registry."""

    provider_id = "python-complexity"
    language_id = "python"
    capability = "complexity"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = False

    def analyze(self, project: ProjectContext) -> ProviderResult:
        analyzer = ProjectComplexityAnalyzer(
            project.root,
            max_file_size=project.max_file_size,
            max_files=project.max_files,
            redact_paths=project.redact_paths,
        )
        analyzer.analyze_trees(
            (
                parsed.source.path,
                parsed.source.display_path,
                parsed.artifact,
            )
            for _, parsed in sorted(project.parsed_files.items())
            if isinstance(parsed.artifact, ast.AST)
        )
        health = analyzer.analysis_health()
        health["complete"] = not bool(
            health.get("total_skipped", 0)
            or health.get("truncated", False)
            or health.get("failed_functions", 0)
        )
        return ProviderResult(
            payload=analyzer.get_summary(),
            health=health,
        )


def register_python_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Python adapter and analysis providers."""
    registry.register_language(PythonLanguageAdapter())
    registry.register_rule_pack(PythonRulePack())
    registry.register_signal_provider(PythonArchitectureSignalProvider())
    registry.register_project_provider(PythonPackageProvider())
    registry.register_project_provider(PythonComplexityProvider())
    return registry
