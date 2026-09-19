"""Reason-required, same-line suppressions for the regex-language packs.

Python has had ``# cqa: ignore=PY-COR-003 reason="cleanup"`` since 2.x
(:mod:`cqa_analyzer.python_suppressions`, token based). The other seven
languages had no escape hatch at all, which is survivable for a handful of
correctness rules and not for a security family: a rule that cannot be
silenced *with a reason* gets silenced by uninstalling the tool.

The directive is the same text in a ``//``, ``#``, ``/* */`` or ``--``
comment on the line the finding is reported on::

    tls.Config{InsecureSkipVerify: true} // cqa: ignore=GO-SEC-001 reason="local test proxy"

A directive without a non-empty reason is not a directive. The scan is over
the raw source (the adapters blank comments in ``code_text``), so the
directive is matched by shape wherever it appears on the line.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..findings import Finding
from ..protocols import ParsedFile

_DIRECTIVE = re.compile(
    r"(?://|#|/\*|--)\s*cqa:\s*ignore="
    r"(?P<rules>[A-Z][A-Z0-9-]*(?:\s*,\s*[A-Z][A-Z0-9-]*)*)"
    r"\s+reason=(?:\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)')"
)

MAX_DIRECTIVES = 10_000
"""Bound on directives read per file; beyond it the rest are ignored."""


def comment_suppression_lines(source: str) -> frozenset[tuple[int, str]]:
    """Return ``(line, rule_id)`` pairs carrying a non-empty reason."""
    suppressions: set[tuple[int, str]] = set()
    for count, match in enumerate(_DIRECTIVE.finditer(source)):
        if count >= MAX_DIRECTIVES:
            break
        reason = match.group("double") or match.group("single") or ""
        if not reason.strip():
            continue
        line = source.count("\n", 0, match.start()) + 1
        for rule_id in match.group("rules").split(","):
            suppressions.add((line, rule_id.strip()))
    return frozenset(suppressions)


def apply_comment_suppressions(
    parsed: ParsedFile, findings: Iterable[Finding]
) -> tuple[Finding, ...]:
    """Drop findings whose line carries a valid directive naming their rule."""
    suppressed = comment_suppression_lines(parsed.source.content)
    if not suppressed:
        return tuple(findings)
    return tuple(
        finding
        for finding in findings
        if (finding.location.line, finding.rule_id) not in suppressed
    )
