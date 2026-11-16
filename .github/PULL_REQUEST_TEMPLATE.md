<!-- Title: type(scope): Summary  (feat | fix | docs | test | ci | build | chore) -->

## What and why

<!-- One change per PR. What changes for a user, and why now. Link the issue. -->

## How it was proven

<!-- A behaviour change ships with a test proven to FAIL on the unchanged code.
     Say how: e.g. "stashed the fix, ran tests/test_x.py::test_y, 1 failed; restored, 1 passed". -->

## CHANGELOG

<!-- The bullet you added under `## Unreleased` in CHANGELOG.md, or, when the
     maintainer asked for it here instead, the bullet itself. Name old -> new
     values for any contract version you bumped. -->

## Checklist

- [ ] One change; unrelated refactors are a separate PR.
- [ ] CHANGELOG bullet written (above or under `## Unreleased`).
- [ ] New or changed behaviour has a test proven to fail before the change; new exemptions have a negative test.
- [ ] Contract versions bumped if the contract changed: `RULESET_VERSION` (+ the pack's `ruleset_version`) for rule behaviour; `REPORT_SCHEMA_VERSION` (+ new `docs/report-schema-<new>.json`) for a JSON report key; `SCORING_POLICY_VERSION` for score changes. Or: no contract changed.
- [ ] `.code-quality-baseline.json` not regenerated. If it was, the PR says why and the maintainer agreed first.
- [ ] Docs updated with the code (`docs/`, `README.md`, `docs/RULES.md` for rules) and `tests/test_docs_drift.py` passes.
- [ ] Privacy contract honoured: no network or project execution at analysis time; every new path, identifier or source text in any output goes through `--anonymize` / `--redact-paths` with a test; SARIF, baselines and reports gained nothing `docs/PRIVACY.md` says they omit.
- [ ] Fixtures and test inputs are synthetic; no proprietary code, real paths or identifiers.
- [ ] Gates green locally: `ruff check .`, `pytest`, `code-quality-analyzer . --fail-under 4.5 --strict -c`, `code-quality-analyzer . --offline --strict --baseline .code-quality-baseline.json --new-findings-only --fail-on warning`.
