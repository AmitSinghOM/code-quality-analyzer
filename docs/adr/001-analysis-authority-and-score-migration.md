# ADR 001: Analysis authority and score migration

- Status: Accepted
- Date: 2026-08-20

## Context

The analyzer previously reported a `rating` even when every source candidate
was skipped or failed to parse. The value measures architecture-signal breadth,
not general code quality, and reports did not version its scoring policy.
Consumers could therefore treat an incomplete heuristic result as authoritative.

## Decision

Reports distinguish source candidates, readable files, and successfully parsed
files. They expose deterministic completeness and authority fields with stable
reason codes. Zero candidates exit with code 2; candidates with zero successful
analysis exit with code 3 regardless of strict mode. Partial analysis remains
available in non-strict mode but is explicitly non-authoritative.

The primary score name is `architecture_signal_score`, versioned by
`scoring_policy_version`. `rating` remains an equal-valued compatibility alias
for the 2.x line. Text output uses **Architecture Signal Score**.

## Privacy

Authority metadata contains only counts, booleans, ratios, and reason codes.
Normal and anonymized reports expose identical authority metadata.

## Consequences

Consumers should migrate from `rating` to `architecture_signal_score` and must
check `analysis_health.authoritative` before treating the score as complete.
Removing the compatibility alias requires a future report-schema major version.
