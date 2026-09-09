# ADR 002: Scoring policy 2.0.0 — production-systems catalog

**Status:** Accepted (2.32.0)

## Context

Scoring policy 1.0.0 measured architecture breadth against a 38-pattern
catalog (24 DSA, 14 design) designed around interview-style algorithms
and web-application design in Python. A staff-level review against the
maintainer's own production codebases showed the catalog systematically
under-measured the engineering that distinguishes senior code:

- Resilience (circuit breakers, retry/backoff), rate limiting,
  idempotency, dead-letter/outbox, event sourcing/CQRS, observability,
  concurrency, and pagination had **no catalog ID at all**. A codebase
  containing `CircuitBreaker`, `RetryPolicy`, `DeadLetteringProjectionStore`,
  and `EventStore` classes scored on API/DI/testing breadth while its
  most sophisticated engineering was invisible.
- GoF coverage was three patterns (factory, singleton, repository).
- Raw database drivers (`sqlite3`, `psycopg`, `asyncpg`) did not count as
  data access; only ORMs did.
- DSA lacked bit manipulation, prefix sums, string matching, consistent
  hashing, and LFU caches.

Adding patterns changes the score for every project, because the rating
curves map *total matched weight* to a 1–10 score.

## Decision

1. **Catalog 2.0**: add 5 DSA and 13 design pattern IDs to the shared
   Python catalog (56 total). Pilot languages mirror the IDs with their
   own idioms; the rater keeps resolving weights from the Python catalog.
2. **Detection stays conservative.** New patterns rely on specific
   naming conventions (`identifier_contains` on `circuitbreaker`,
   `deadletter`, `eventstore`, …) and library imports (tenacity,
   resilience4j, Polly, OpenTelemetry, …). Patterns whose tokens are
   common words in other contexts (`projection`, `aggregate`, `cursor`,
   `subscribe`) require two corroborating signals.
3. **Curves scaled partially, not proportionally.** Catalog weight grew
   by roughly 60% (design) and 25% (DSA), but the new patterns are rarer
   than the originals, so ceilings are scaled ×1.5 (design) and ×1.2
   (DSA). Proportional scaling would have lowered the score of every
   project that does not use the new patterns; no scaling would have
   inflated every project that does.
4. **Maturity breadth target** rises from 20 to 28 distinct patterns.
5. `SCORING_POLICY_VERSION` becomes `2.0.0`. Reports carry the version,
   so consumers can distinguish policy-1 from policy-2 scores.

## Consequences

- Scores under policy 2.0.0 are **not comparable** to policy 1.0.0
  scores. Projects rich in production-systems patterns score higher;
  projects that only use the original catalog score slightly lower
  because curve ceilings moved. Both directions are intended.
- Baseline files are unaffected (they fingerprint findings, not
  scores). `--fail-under` thresholds should be re-derived once after
  upgrading.
- The cross-language fairness review (roadmap item 5) remains open; this
  ADR expands the vocabulary but does not re-tune per-language signal
  density.
