"""Helpers shared by the regex-based language pilots."""

from __future__ import annotations

from collections.abc import Iterable

from ..findings import Finding
from ..protocols import ParsedFile


def line_column(source: str, offset: int) -> tuple[int, int]:
    """Return the one-based (line, column) of ``offset`` in ``source``."""
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


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
