"""Python plugins behind the language-neutral extension contracts."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from ..findings import Finding
from ..protocols import ParsedFile, SourceFile
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


def register_python_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Python adapter and rule pack."""
    registry.register_language(PythonLanguageAdapter())
    registry.register_rule_pack(PythonRulePack())
    return registry
