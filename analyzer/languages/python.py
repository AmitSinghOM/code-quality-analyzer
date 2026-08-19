"""Python plugins behind the language-neutral extension contracts."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from ..complexity import ProjectComplexityAnalyzer
from ..findings import Finding
from ..package_intelligence import PythonPackageAnalyzer
from ..protocols import (
    ParsedFile,
    ProjectContext,
    ProviderResult,
    SourceFile,
)
from ..python_rules import PythonRuleAnalyzer
from ..registry import PluginRegistry
from ..signals import extract_signals

PYTHON_ADAPTER_VERSION = "1.0.0"
PYTHON_RULE_PACK_ID = "python-core"


class PythonLanguageAdapter:
    """Parse Python once and expose its existing facts as an opaque payload."""

    language_id = "python"
    adapter_version = PYTHON_ADAPTER_VERSION
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
    ruleset_version = "2.2.0"

    def __init__(self, analyzer: PythonRuleAnalyzer | None = None) -> None:
        self.analyzer = analyzer or PythonRuleAnalyzer()

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not parsed.complete or parsed.artifact is None:
            return ()
        if not isinstance(parsed.artifact, ast.AST):
            raise TypeError("Python rule pack requires a Python AST artifact")
        return self.analyzer.analyze(
            parsed.artifact,
            parsed.source.display_path,
            identity_path=parsed.source.identity_path,
        )


class PythonPackageProvider:
    """Provide passive Python package intelligence from shared parse data."""

    provider_id = "python-package"
    language_id = "python"
    capability = "package"
    enabled_by_default = True

    def analyze(self, project: ProjectContext) -> ProviderResult:
        artifacts = {
            path: parsed.artifact
            for path, parsed in project.parsed_files.items()
            if isinstance(parsed.artifact, ast.AST)
        }
        analyzer = PythonPackageAnalyzer(
            project.root,
            artifacts,
            redact_paths=project.redact_paths,
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
    enabled_by_default = False

    def analyze(self, project: ProjectContext) -> ProviderResult:
        analyzer = ProjectComplexityAnalyzer(
            project.root,
            max_file_size=project.max_file_size,
            max_files=project.max_files,
            redact_paths=project.redact_paths,
        )
        analyzer.analyze()
        return ProviderResult(
            payload=analyzer.get_summary(),
            health=analyzer.analysis_health(),
        )


def register_python_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Python adapter and analysis providers."""
    registry.register_language(PythonLanguageAdapter())
    registry.register_rule_pack(PythonRulePack())
    registry.register_project_provider(PythonPackageProvider())
    registry.register_project_provider(PythonComplexityProvider())
    return registry
