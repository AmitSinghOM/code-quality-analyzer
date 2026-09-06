"""Language-neutral extension contracts for analyzer plugins."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .findings import Finding

PLUGIN_API_VERSION = "1.0.0"
DEFAULT_CAPABILITY_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One bounded source file supplied to a language adapter."""

    path: Path
    display_path: str
    identity_path: str
    content: str


@dataclass(frozen=True, slots=True)
class ParsedFile:
    """Opaque parse artifact and normalized metadata returned by an adapter."""

    source: SourceFile
    artifact: object | None
    facts: object | None
    line_count: int
    complete: bool


@runtime_checkable
class LanguageAdapter(Protocol):
    """Parse source without exposing language-specific ASTs to the core."""

    language_id: str
    adapter_version: str
    plugin_api_version: str
    extensions: tuple[str, ...]

    def parse(self, source: SourceFile) -> ParsedFile: ...


@runtime_checkable
class ParsedArtifactCodec(Protocol):
    """Optional safe cache codec implemented by a language adapter."""

    language_id: str
    adapter_version: str
    cache_codec_version: str
    cache_runtime_version: str

    def serialize_parsed(self, parsed: ParsedFile) -> Mapping[str, object]: ...

    def deserialize_parsed(
        self,
        source: SourceFile,
        payload: Mapping[str, object],
    ) -> ParsedFile: ...


@runtime_checkable
class RulePack(Protocol):
    """Evaluate one adapter artifact and emit normalized findings."""

    rule_pack_id: str
    language_id: str
    ruleset_version: str
    plugin_api_version: str

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]: ...


@dataclass(frozen=True, slots=True)
class SignalObservation:
    """One descriptive, non-finding observation emitted by a language."""

    category: str
    signal_id: str
    description: str
    path: str
    evidence: tuple[str, ...] = ()


@runtime_checkable
class SignalProvider(Protocol):
    """Extract descriptive observations from one parsed source file."""

    provider_id: str
    language_id: str
    plugin_api_version: str
    capability_version: str

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]: ...


@runtime_checkable
class MetricProvider(Protocol):
    """Measure language-specific facts without changing the report model."""

    provider_id: str
    language_id: str
    plugin_api_version: str
    capability_version: str

    def measure(self, parsed: ParsedFile) -> Mapping[str, int | float]: ...


@runtime_checkable
class Reporter(Protocol):
    """Render a language-neutral report representation."""

    format_name: str
    plugin_api_version: str
    capability_version: str

    def render(self, report: object) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ProjectContext:
    """Bounded project data supplied to a language project provider."""

    root: Path
    parsed_files: Mapping[str, ParsedFile]
    max_file_size: int
    max_files: int
    redact_paths: bool


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """Language-neutral result envelope for project-level analysis."""

    payload: object
    health: Mapping[str, object]
    findings: tuple[Finding, ...] = ()


@runtime_checkable
class ProjectProvider(Protocol):
    """Produce package, graph, or complexity data for one language."""

    provider_id: str
    language_id: str
    capability: str
    capability_version: str
    plugin_api_version: str
    enabled_by_default: bool

    def analyze(self, project: ProjectContext) -> ProviderResult: ...
