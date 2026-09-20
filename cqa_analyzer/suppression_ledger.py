"""Per-scan ledger of findings dropped by an in-source suppression directive.

Review 5, A6. A ``# cqa: ignore=PY-SEC-002 reason="..."`` directive used to
make a finding vanish from JSON, SARIF and the summary with no trace, so a
reviewer could not tell a clean file from a silenced one. bandit counts its
``nosec`` hits and gosec emits SARIF ``suppressions[]`` with the justification;
cqa has the richer, reason-required directive and now reports it too.

Every place that drops a finding because of a directive calls
:func:`record`. The scanner opens a fresh ledger per scan and reads it into
``scan_health.suppressed`` (counts) and ``report.suppressed_findings`` (the
findings themselves with their justification), which the SARIF reporter
emits as results carrying ``suppressions: [{kind: "inSource", ...}]`` so
GitHub code scanning shows them as suppressed rather than absent. Neither
the exit code nor the score ever counts a suppressed finding.

The ledger is a :class:`contextvars.ContextVar` rather than a parameter
threaded through four provider/pack return types, because those signatures
are part of the plugin API (``plugin_api_version``) and widening them would
break third-party packs for a bookkeeping concern.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from collections.abc import Iterable

from .findings import Finding


@dataclass
class SuppressedFinding:
    finding: Finding
    reason: str


@dataclass
class SuppressionLedger:
    entries: list[SuppressedFinding] = field(default_factory=list)

    def record(self, finding: Finding, reason: str) -> None:
        self.entries.append(SuppressedFinding(finding, reason))

    def by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.finding.rule_id] = counts.get(entry.finding.rule_id, 0) + 1
        return dict(sorted(counts.items()))

    def health(self) -> dict:
        return {"count": len(self.entries), "by_rule": self.by_rule()}


_LEDGER: ContextVar[SuppressionLedger | None] = ContextVar("cqa_suppression_ledger", default=None)


def open_ledger() -> SuppressionLedger:
    """Start a fresh ledger for the current scan and return it."""
    ledger = SuppressionLedger()
    _LEDGER.set(ledger)
    return ledger


def record(finding: Finding, reason: str) -> None:
    """Record ``finding`` as suppressed with the directive's ``reason``.

    A no-op when no scan has opened a ledger (rule packs evaluated directly in
    tests keep their existing behaviour)."""
    ledger = _LEDGER.get()
    if ledger is not None:
        ledger.record(finding, reason)


def drop_suppressed(
    findings: Iterable[Finding], suppressions: dict[tuple[int, str], str]
) -> tuple[Finding, ...]:
    """Return ``findings`` minus those a directive names, recording each drop."""
    kept: list[Finding] = []
    for finding in findings:
        reason = suppressions.get((finding.location.line, finding.rule_id))
        if reason is None:
            kept.append(finding)
        else:
            record(finding, reason)
    return tuple(kept)
