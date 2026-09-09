"""Helpers shared by the regex-based language pilots."""

from __future__ import annotations

from collections.abc import Iterable

from ..findings import Finding
from ..protocols import ParsedFile, SignalObservation
from ..signals import FileSignals, pattern_is_present


def line_column(source: str, offset: int) -> tuple[int, int]:
    """Return the one-based (line, column) of ``offset`` in ``source``."""
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def signal_observations(
    parsed: ParsedFile,
    identifiers: Iterable[str],
    imports: Iterable[str],
    code_text: str,
    catalogs: Iterable[tuple[str, dict]],
) -> Iterable[SignalObservation]:
    """Match a pilot's blanked facts against (category, patterns) catalogs."""
    signals = FileSignals(
        path=parsed.source.path,
        line_count=parsed.line_count,
        code_text=code_text.lower(),
        identifiers={name.lower() for name in identifiers},
        imports={imported.lower() for imported in imports},
    )
    for category, definitions in catalogs:
        for signal_id, definition in definitions.items():
            present, matched = pattern_is_present(signals, definition)
            if present:
                yield SignalObservation(
                    category=category,
                    signal_id=signal_id,
                    description=definition["description"],
                    path=parsed.source.display_path,
                    evidence=tuple(matched),
                )


class RegexRulePackBase:
    """Run bounded regex rules over a complete parsed file.

    Subclasses set the plugin metadata attributes and ``rules``.
    """

    rules: tuple = ()

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not parsed.complete:
            return ()
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(parsed))
        return findings
