"""Built-in language-neutral report renderers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from .protocols import DEFAULT_CAPABILITY_VERSION, PLUGIN_API_VERSION
from .registry import PluginRegistry


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Immutable presentation envelope consumed by standard reporters."""

    structured: Mapping[str, object] | None = None
    text: str | None = None


class JsonReporter:
    """Render the versioned structured report as deterministic JSON."""

    format_name = "json"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def render(self, report: object) -> bytes:
        if not isinstance(report, AnalysisReport) or report.structured is None:
            raise TypeError("JSON reporter requires structured report data")
        return json.dumps(report.structured, indent=2).encode("utf-8")


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
    registry.register_reporter(TextReporter())
    return registry
