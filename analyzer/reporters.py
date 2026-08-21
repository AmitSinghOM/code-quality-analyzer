"""Built-in language-neutral report renderers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import quote

from .protocols import DEFAULT_CAPABILITY_VERSION, PLUGIN_API_VERSION
from .registry import PluginRegistry
from .rule_metadata import RuleMetadata, rule_metadata

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "cs01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_LEVELS = {
    "error": "error",
    "warning": "warning",
    "note": "note",
    "none": "none",
}


@dataclass(frozen=True, slots=True)
class SarifRun:
    """Privacy-projected inputs for one deterministic SARIF run."""

    analyzer_version: str
    configuration_fingerprint: str
    analysis_health: Mapping[str, object]
    privacy: Mapping[str, object]
    baseline_selection: Mapping[str, object]
    changed_line_selection: Mapping[str, object] | None = None
    findings: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Immutable presentation envelope consumed by standard reporters."""

    structured: Mapping[str, object] | None = None
    text: str | None = None
    sarif: SarifRun | None = None


class JsonReporter:
    """Render the versioned structured report as deterministic JSON."""

    format_name = "json"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def render(self, report: object) -> bytes:
        if not isinstance(report, AnalysisReport) or report.structured is None:
            raise TypeError("JSON reporter requires structured report data")
        return json.dumps(report.structured, indent=2).encode("utf-8")


class SarifReporter:
    """Render normalized findings as deterministic, privacy-bounded SARIF."""

    format_name = "sarif"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def render(self, report: object) -> bytes:
        if not isinstance(report, AnalysisReport) or report.sarif is None:
            raise TypeError("SARIF reporter requires a SARIF run")
        payload = _sarif_payload(report.sarif)
        return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


class TextReporter:
    """Render the compatibility terminal report."""

    format_name = "text"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def render(self, report: object) -> bytes:
        if not isinstance(report, AnalysisReport) or report.text is None:
            raise TypeError("Text reporter requires rendered terminal text")
        return report.text.encode("utf-8")


def register_standard_reporters(registry: PluginRegistry) -> PluginRegistry:
    """Register deterministic built-in report formats."""
    registry.register_reporter(JsonReporter())
    registry.register_reporter(SarifReporter())
    registry.register_reporter(TextReporter())
    return registry


def _sarif_payload(run: SarifRun) -> dict:
    findings = sorted(run.findings, key=_finding_sort_key)
    rule_ids = sorted({_finding_string(item, "rule_id") for item in findings})
    catalog = [rule_metadata(rule_id) for rule_id in rule_ids]
    indexes = {metadata.rule_id: index for index, metadata in enumerate(catalog)}
    return {
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Code Quality Analyzer",
                    "rules": [_rule_descriptor(item) for item in catalog],
                    "semanticVersion": run.analyzer_version,
                },
            },
            "results": [_result(item, indexes) for item in findings],
            "properties": _sarif_properties(run),
        }],
        "version": SARIF_VERSION,
    }


def _sarif_properties(run: SarifRun) -> dict:
    properties = {
        "analysisHealth": dict(run.analysis_health),
        "baselineSelection": dict(run.baseline_selection),
        "configurationFingerprint": run.configuration_fingerprint,
        "privacy": dict(run.privacy),
    }
    if run.changed_line_selection is not None:
        properties["changedLineSelection"] = dict(
            run.changed_line_selection
        )
    return properties


def _rule_descriptor(metadata: RuleMetadata) -> dict:
    return {
        "defaultConfiguration": {
            "level": _sarif_level(metadata.default_severity),
        },
        "fullDescription": {"text": metadata.description},
        "help": {"text": metadata.remediation},
        "id": metadata.rule_id,
        "name": metadata.name,
        "properties": {
            "category": metadata.category,
            "confidence": metadata.confidence,
            "defaultSeverity": metadata.default_severity,
            "language": metadata.language,
        },
        "shortDescription": {"text": metadata.title},
    }


def _result(finding: Mapping[str, object], indexes: dict[str, int]) -> dict:
    rule_id = _finding_string(finding, "rule_id")
    location = finding.get("location")
    if not isinstance(location, Mapping):
        raise ValueError(f"Finding {rule_id} has no valid location")
    region = {
        "startColumn": _positive_integer(location, "column", rule_id),
        "startLine": _positive_integer(location, "line", rule_id),
    }
    end_line = location.get("end_line")
    end_column = location.get("end_column")
    if end_line is not None:
        region["endLine"] = _positive_integer(location, "end_line", rule_id)
    if end_column is not None:
        region["endColumn"] = _positive_integer(
            location,
            "end_column",
            rule_id,
        )
    return {
        "level": _sarif_level(_finding_string(finding, "severity")),
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _artifact_uri(_finding_string(location, "path")),
                },
                "region": region,
            },
        }],
        "message": {"text": _finding_string(finding, "message")},
        "properties": {
            "category": _finding_string(finding, "category"),
            "confidence": _finding_string(finding, "confidence"),
            "remediation": _finding_string(finding, "remediation"),
        },
        "ruleId": rule_id,
        "ruleIndex": indexes[rule_id],
    }


def _finding_sort_key(finding: Mapping[str, object]) -> tuple:
    rule_id = _finding_string(finding, "rule_id")
    location = finding.get("location")
    if not isinstance(location, Mapping):
        raise ValueError(f"Finding {rule_id} has no valid location")
    return (
        _artifact_uri(_finding_string(location, "path")),
        _positive_integer(location, "line", rule_id),
        _positive_integer(location, "column", rule_id),
        rule_id,
        _finding_string(finding, "message"),
        _finding_string(finding, "remediation"),
    )


def _artifact_uri(path: str) -> str:
    if not path or "\x00" in path:
        raise ValueError("SARIF artifact paths must be nonempty and contain no NUL")
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or _SCHEME.match(normalized):
        raise ValueError("SARIF artifact paths must be project-relative")
    parts = normalized.split("/")
    if ".." in parts:
        raise ValueError("SARIF artifact paths cannot traverse parent directories")
    safe_parts = [part for part in parts if part not in {"", "."}]
    if not safe_parts:
        raise ValueError("SARIF artifact paths must identify a file")
    return quote("/".join(safe_parts), safe="/-._~")


def _sarif_level(severity: str) -> str:
    try:
        return _LEVELS[severity]
    except KeyError as error:
        raise ValueError(f"Unsupported SARIF severity {severity!r}") from error


def _finding_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or (not value and key != "path"):
        raise ValueError(f"Finding field {key!r} must be a nonempty string")
    return value


def _positive_integer(
    mapping: Mapping[str, object],
    key: str,
    rule_id: str,
) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(
            f"Finding {rule_id} location {key!r} must be a positive integer"
        )
    return value
