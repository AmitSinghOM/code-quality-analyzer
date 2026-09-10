"""Helpers shared by the regex-based language pilots."""

from __future__ import annotations

from collections.abc import Iterable

from ..findings import Finding, Location
from ..protocols import ParsedFile, SignalObservation
from ..signals import FileSignals, pattern_is_present


def line_column(source: str, offset: int) -> tuple[int, int]:
    """Return the one-based (line, column) of ``offset`` in ``source``."""
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def empty_catch_finding(
    rule_id: str,
    parsed: ParsedFile,
    match,
    *,
    rethrow_word: str = "exception",
) -> Finding:
    """Build the shared empty-catch finding for a regex match on blanked text.

    The blanked match spans the braces. If the *original* text inside them
    holds a comment, the author documented the swallow (``catch (e) {
    // best effort }``); that is reported as an informational
    ``note``-severity finding rather than a warning — the
    behaviour of ErrorProne and SonarQube (staff review C3).
    """
    code_text = parsed.facts.code_text
    line, column = line_column(code_text, match.start())
    open_brace = code_text.index("{", match.start())
    close_brace = match.end() - 1
    original_body = parsed.source.content[open_brace + 1 : close_brace]
    documented = "//" in original_body or "/*" in original_body or "#" in original_body
    return Finding(
        rule_id=rule_id,
        category="correctness",
        severity="note" if documented else "warning",
        confidence="high",
        message=(
            "An empty catch block is documented with a comment; confirm the "
            "swallow is intentional."
            if documented
            else "An empty catch block silently discards the failure."
        ),
        location=Location(
            path=parsed.source.display_path,
            line=line,
            column=column,
            identity_path=parsed.source.identity_path,
        ),
        remediation=(f"Handle the failure, log actionable context, or rethrow the {rethrow_word}."),
    )


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
