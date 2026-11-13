# Documentation index

One line per document. The [README](../README.md) is the entry point; these
pages hold the contracts it points at.

## Reference

- [CONFIGURATION.md](CONFIGURATION.md) — `.code-quality.toml` reference: include/exclude, rule overrides, fingerprinting.
- [RULES.md](RULES.md) — every rule ID across the eight languages, with what it does and does not flag.
- [BASELINES.md](BASELINES.md) — finding baselines: schema, fingerprints, `--new-findings-only`.
- [CHANGED_LINES.md](CHANGED_LINES.md) — changed-line selection from unified diffs and manifests.
- [SARIF.md](SARIF.md) — SARIF 2.1.0 output, `security-severity`, code-scanning upload.
- [CACHING.md](CACHING.md) — the incremental parse cache and its safety bounds.
- [PRE_COMMIT.md](PRE_COMMIT.md) — the published pre-commit hook and how to gate with it.
- [PRIVACY.md](PRIVACY.md) — privacy and threat model: what never leaves the machine, `--offline`, `--anonymize`.

## Scoring

- [CALIBRATION.md](CALIBRATION.md) — cross-language scoring fairness calibration and its corpus.
- [AACR_BENCH.md](AACR_BENCH.md) — AACR-Bench as an external calibration corpus.
- `calibration-latest.json` — the latest calibration run the tests pin.
- `report-schema-<version>.json` — JSON report schemas; the newest matches `REPORT_SCHEMA_VERSION`.

## Project

- [ROADMAP.md](ROADMAP.md) — language support today and the forward plan.
- [MAINTENANCE.md](MAINTENANCE.md) — what rots, what does not, and the response cadence.
- [RELEASING.md](RELEASING.md) — cutting a release to PyPI.

## Architecture decision records

- [adr/001-analysis-authority-and-score-migration.md](adr/001-analysis-authority-and-score-migration.md) — analysis authority and the score migration.
- [adr/002-scoring-policy-2-production-systems-catalog.md](adr/002-scoring-policy-2-production-systems-catalog.md) — scoring policy 2.0.0: production-systems catalog.
- [adr/003-scoring-policy-2-1-locking-hardening-labuladong.md](adr/003-scoring-policy-2-1-locking-hardening-labuladong.md) — scoring policy 2.1.0: locking, concurrency, hardening, scheduling.
- [adr/004-positioning-and-longevity.md](adr/004-positioning-and-longevity.md) — positioning and longevity structure for the model era.

## Reviews and history

- [reviews/2026-09-14-staff-review-3.1.0.md](reviews/2026-09-14-staff-review-3.1.0.md) — staff review of 3.1.0.
- [reviews/2026-09-19-security-family-calibration.md](reviews/2026-09-19-security-family-calibration.md) — security rule family calibration.
- [reviews/2026-09-20-four-seat-review-3.2.1.md](reviews/2026-09-20-four-seat-review-3.2.1.md) — four-seat review of 3.2.1.
- [reviews/2026-09-21-four-seat-review-6.md](reviews/2026-09-21-four-seat-review-6.md) — four-seat review 6 (3.4.0/3.4.1).
- [history/2026-08-action-plan.md](history/2026-08-action-plan.md) — the original August 2026 action plan (historical, Python-only scope).
