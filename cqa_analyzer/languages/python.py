"""Python plugins behind the language-neutral extension contracts."""

from __future__ import annotations

import ast
import base64
import sys
from collections.abc import Iterable, Mapping

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
PYTHON_CACHE_CODEC_VERSION = "1.0.0"
PYTHON_RULE_PACK_ID = "python-core"
_MAX_AST_NODES = 200_000
_MAX_AST_ITEMS = 400_000
_MAX_CACHED_STRING = 4 * 1024 * 1024
_AST_TYPES = {
    name: value
    for name, value in vars(ast).items()
    if isinstance(value, type) and issubclass(value, ast.AST)
}


class _DecodeBudget:
    def __init__(self) -> None:
        self.nodes = 0
        self.items = 0

    def consume(self, *, node: bool = False) -> None:
        self.items += 1
        self.nodes += int(node)
        if self.items > _MAX_AST_ITEMS or self.nodes > _MAX_AST_NODES:
            raise ValueError("Cached Python artifact exceeds structural limits")


class PythonLanguageAdapter:
    """Parse Python once and expose its existing facts as an opaque payload."""

    language_id = "python"
    adapter_version = PYTHON_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".py",)
    cache_codec_version = PYTHON_CACHE_CODEC_VERSION
    cache_runtime_version = (
        f"{sys.implementation.name}-{sys.version_info.major}."
        f"{sys.version_info.minor}"
    )

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

    def serialize_parsed(self, parsed: ParsedFile) -> Mapping[str, object]:
        if not isinstance(parsed.facts, FileSignals):
            raise TypeError("Python cache codec requires FileSignals facts")
        signals = parsed.facts
        return {
            "line_count": parsed.line_count,
            "complete": parsed.complete,
            "tree": _encode_ast_value(parsed.artifact),
            "signals": {
                "line_count": signals.line_count,
                "code_text": signals.code_text,
                "identifiers": sorted(signals.identifiers),
                "imports": sorted(signals.imports),
                "parsed": signals.parsed,
                "literals_stripped": signals.literals_stripped,
            },
        }

    def deserialize_parsed(
        self,
        source: SourceFile,
        payload: Mapping[str, object],
    ) -> ParsedFile:
        data = _exact_mapping(
            payload,
            {"line_count", "complete", "tree", "signals"},
        )
        line_count = _bounded_int(data["line_count"])
        complete = _boolean(data["complete"])
        budget = _DecodeBudget()
        tree = _decode_ast_value(data["tree"], budget)
        if tree is not None and not isinstance(tree, ast.AST):
            raise ValueError("Cached Python tree is not an AST")
        encoded_signals = _exact_mapping(
            data["signals"],
            {
                "line_count", "code_text", "identifiers", "imports",
                "parsed", "literals_stripped",
            },
        )
        signals = FileSignals(
            path=source.path,
            line_count=_bounded_int(encoded_signals["line_count"]),
            code_text=_bounded_string(encoded_signals["code_text"]),
            identifiers=set(_string_list(encoded_signals["identifiers"])),
            imports=set(_string_list(encoded_signals["imports"])),
            tree=tree,
            parsed=_boolean(encoded_signals["parsed"]),
            literals_stripped=_boolean(
                encoded_signals["literals_stripped"]
            ),
        )
        if signals.line_count != line_count:
            raise ValueError("Cached Python line counts do not match")
        return ParsedFile(source, tree, signals, line_count, complete)


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


def _encode_ast_value(value: object) -> object:
    if isinstance(value, ast.AST):
        return {
            "kind": "ast",
            "type": type(value).__name__,
            "fields": {
                field: _encode_ast_value(getattr(value, field, None))
                for field in value._fields
            },
            "attributes": {
                attribute: _encode_ast_value(getattr(value, attribute))
                for attribute in value._attributes
                if hasattr(value, attribute)
            },
        }
    if isinstance(value, list):
        return [_encode_ast_value(item) for item in value]
    if isinstance(value, tuple):
        return {
            "kind": "tuple",
            "items": [_encode_ast_value(item) for item in value],
        }
    if isinstance(value, bytes):
        return {
            "kind": "bytes",
            "data": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, complex):
        return {"kind": "complex", "real": value.real, "imag": value.imag}
    if value is Ellipsis:
        return {"kind": "ellipsis"}
    if value is None or isinstance(value, bool | int | float | str):
        return value
    raise TypeError(f"Unsupported Python AST value: {type(value).__name__}")


def _decode_ast_value(value: object, budget: _DecodeBudget) -> object:
    budget.consume()
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _bounded_string(value)
    if isinstance(value, list):
        if len(value) > _MAX_AST_ITEMS:
            raise ValueError("Cached Python list exceeds item limit")
        return [_decode_ast_value(item, budget) for item in value]
    if not isinstance(value, dict):
        raise ValueError("Cached Python artifact has an invalid value")
    kind = value.get("kind")
    if kind == "ast":
        data = _exact_mapping(
            value,
            {"kind", "type", "fields", "attributes"},
        )
        node_type = _bounded_string(data["type"])
        cls = _AST_TYPES.get(node_type)
        if cls is None:
            raise ValueError("Cached Python artifact has an unknown AST type")
        fields = _exact_mapping(data["fields"], set(cls._fields))
        attributes = _mapping(data["attributes"])
        if not set(attributes) <= set(cls._attributes):
            raise ValueError("Cached Python AST has unknown attributes")
        budget.consume(node=True)
        node = cls(**{
            field: _decode_ast_value(fields[field], budget)
            for field in cls._fields
        })
        for name, item in attributes.items():
            setattr(node, name, _decode_ast_value(item, budget))
        return node
    if kind == "tuple":
        data = _exact_mapping(value, {"kind", "items"})
        items = data["items"]
        if not isinstance(items, list) or len(items) > _MAX_AST_ITEMS:
            raise ValueError("Cached Python tuple is invalid")
        return tuple(_decode_ast_value(item, budget) for item in items)
    if kind == "bytes":
        data = _exact_mapping(value, {"kind", "data"})
        encoded = _bounded_string(data["data"])
        return base64.b64decode(encoded, validate=True)
    if kind == "complex":
        data = _exact_mapping(value, {"kind", "real", "imag"})
        real, imaginary = data["real"], data["imag"]
        if isinstance(real, bool) or not isinstance(real, int | float):
            raise ValueError("Cached complex real part is invalid")
        if isinstance(imaginary, bool) or not isinstance(
            imaginary,
            int | float,
        ):
            raise ValueError("Cached complex imaginary part is invalid")
        return complex(real, imaginary)
    if kind == "ellipsis" and set(value) == {"kind"}:
        return Ellipsis
    raise ValueError("Cached Python artifact has an unknown value kind")


def _mapping(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Cached Python value must be an object")
    return value


def _exact_mapping(value: object, keys: set[str]) -> dict:
    result = _mapping(value)
    if set(result) != keys:
        raise ValueError("Cached Python object has unexpected fields")
    return result


def _bounded_string(value: object) -> str:
    if not isinstance(value, str) or len(value) > _MAX_CACHED_STRING:
        raise ValueError("Cached Python string is invalid")
    return value


def _bounded_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Cached Python integer is invalid")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("Cached Python boolean is invalid")
    return value


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_AST_ITEMS:
        raise ValueError("Cached Python string list is invalid")
    return [_bounded_string(item) for item in value]


def register_python_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Python adapter and analysis providers."""
    registry.register_language(PythonLanguageAdapter())
    registry.register_rule_pack(PythonRulePack())
    registry.register_signal_provider(PythonArchitectureSignalProvider())
    registry.register_project_provider(PythonPackageProvider())
    registry.register_project_provider(PythonComplexityProvider())
    return registry
