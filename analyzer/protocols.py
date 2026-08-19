"""Language-neutral extension contracts for analyzer plugins."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .findings import Finding


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
    extensions: tuple[str, ...]

    def parse(self, source: SourceFile) -> ParsedFile: ...


@runtime_checkable
class RulePack(Protocol):
    """Evaluate one adapter artifact and emit normalized findings."""

    rule_pack_id: str
    language_id: str
    ruleset_version: str

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]: ...


@runtime_checkable
class MetricProvider(Protocol):
    """Measure language-specific facts without changing the report model."""

    provider_id: str
    language_id: str

    def measure(self, parsed: ParsedFile) -> Mapping[str, int | float]: ...


@runtime_checkable
class Reporter(Protocol):
    """Render a language-neutral report representation."""

    format_name: str

    def render(self, report: object) -> bytes: ...
