# Contributing to cqa-analyzer

Thank you for helping. The most valuable contribution today is a
**false-positive report**: every confirmed one becomes a fixture, and the
fixture keeps the rule honest for everyone (see
[`docs/ROADMAP.md`](docs/ROADMAP.md), Phase 1). Use the
*False positive* issue form; it asks for exactly what a fixture needs.

Bug reports, feature requests and pull requests are welcome too. This page
tells you what the maintainer will check, so your change lands in one round.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems go through [`SECURITY.md`](SECURITY.md), never a public
issue.

## What this project will not accept

- Anything that makes the analyzer execute, import, build or fetch the
  project it analyzes. Default analysis is passive and stays that way
  ([`SECURITY.md`](SECURITY.md), [`docs/PRIVACY.md`](docs/PRIVACY.md)).
- A runtime dependency. `dependencies = []` in `pyproject.toml` is a
  contract (`docs/adr/004`); the optional `[deep]` extra is the only
  third-party code the package may load, and `tests/test_stdlib_core.py`
  fails on any other import.
- Proprietary source, real file paths, identifiers, credentials or
  customer names in an issue, a fixture or a test. Synthetic
  reproductions only. If your reproduction needs real code, do not file
  it; rewrite it first.
- A ninth language or a new architecture pattern without corpus evidence
  of a false negative (`docs/ROADMAP.md`, "breadth freeze").

## Development setup

Python 3.11 or newer (`requires-python` in `pyproject.toml`; CI tests
3.11 through 3.15).

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev,deep]"
```

`[dev]` pins the gate tooling (`pytest`, `ruff`, `pip-audit`, `build`,
`jsonschema`). `[deep]` adds the tree-sitter grammars; without it
`tests/test_deep.py` and the Rust pilot skip, which is fine for most
changes but not for a change to Go, C/C++ or Rust analysis.

## Gates

These are the commands `.github/workflows/ci.yml` runs. Run them from the
repository root before you push; a PR is reviewed only when all of them
are green.

| CI job | Command | Must |
|---|---|---|
| `test` → Lint | `ruff check .` | pass with no output |
| `test` → Test | `pytest` | 0 failed on every Python in the matrix |
| `deep-test` | `pytest tests/test_deep.py tests/test_rust.py -rs` | run, not skip (one expected skip: the "without the grammar" Rust test) |
| `self-check` | `code-quality-analyzer . --fail-under 4.5 --strict -c` | exit 0 |
| `gate-action` | `code-quality-analyzer . --offline --strict --baseline .code-quality-baseline.json --new-findings-only --fail-on warning` | 0 new findings |
| `audit` | `pip-audit --local --skip-editable` | no known vulnerability |
| `distribution` | `python -m build --no-isolation` | builds a wheel and an sdist |

Notes:

- The `gate-action` row is the local equivalent of the published GitHub
  Action run CI performs (`AmitSinghOM/cqa-action` with
  `baseline: .code-quality-baseline.json`, `fail-on: warning`,
  `strict: "true"`). The baseline is a ratchet. **Do not regenerate it**
  to make a red gate green; fix the finding. If a regeneration is really
  needed (a rule changed and the maintainer agreed), the PR says why and
  uses `code-quality-analyzer . --write-baseline .code-quality-baseline.json`.
- The `self-check` threshold (`--fail-under 4.5`) is also a ratchet: it
  may go up, never down.
- `ruff check` is the style gate. `ruff format --check` is deliberately
  not ([`docs/MAINTENANCE.md`](docs/MAINTENANCE.md), "Style gate
  decision"): format new files and files you substantially rewrite, do
  not reformat existing ones wholesale.
- Do not break the contract tests: `tests/test_sarif_schema.py` (SARIF
  validates against the vendored OASIS 2.1.0 schema, which has
  `additionalProperties: false`), `tests/test_report_contract.py`,
  `tests/test_not_when_claims.py`, `tests/test_release_metadata.py`,
  `tests/test_ci_contracts.py`, `tests/test_import_order.py`,
  `tests/test_docs_drift.py`.

## Pull requests

**One change per PR.** A fix and an unrelated refactor are two PRs. Small
PRs merge; large ones wait.

**A behaviour change ships with a test proven to fail on the previous
release.** Write the test first and watch it fail on the unchanged code
(`git stash` your fix, run the test, `git stash pop`), then make it pass.
Say in the PR body how you proved it. A test that cannot fail on the old
code proves nothing. Every new exemption, allowlist or `not_when` clause
also gets a negative test (one input the rule must still flag).

**CHANGELOG.** Add a bullet under `## Unreleased` at the top of
[`CHANGELOG.md`](CHANGELOG.md) (create the heading if it is missing). Say
what changed for the user, not what you edited. The maintainer dates the
heading at release time ([`docs/RELEASING.md`](docs/RELEASING.md)).

**Commit and PR titles** follow the existing log: `type(scope): Summary`,
where `type` is one of `feat`, `fix`, `docs`, `test`, `ci`, `build`,
`chore`. Example: `fix(sarif): Encode artifact URIs as project-relative`.

**Docs track code.** If you change a flag, an exit code, a rule, a config
key or an output key, update the matching page under `docs/` and the
README in the same PR. `tests/test_docs_drift.py` and
`tests/test_not_when_claims.py` fail when prose and code disagree.

The [pull request template](.github/PULL_REQUEST_TEMPLATE.md) is the
checklist; fill it in rather than deleting it.

## Version rules

Versions live in `cqa_analyzer/__init__.py`. Each one changes only when
its own contract changes
([`docs/RELEASING.md`](docs/RELEASING.md), [`docs/ROADMAP.md`](docs/ROADMAP.md)
"Compatibility promise"). A contributor does **not** bump `__version__`;
the maintainer does at release time (versions are not pre-bumped). A
contributor **does** bump the contract version the change touches, in
the same PR, and names the old and new value in the CHANGELOG bullet:

| Constant | Bump when | What else must move |
|---|---|---|
| `RULESET_VERSION` | a rule is added, removed, or changes what it reports (a precision fix counts) | the language pack's own `ruleset_version` in `cqa_analyzer/languages/<lang>.py`; the rule's `RuleMetadata` in `cqa_analyzer/rule_metadata.py`; its section in `docs/RULES.md`; a should-fire and a should-stay-silent fixture in `tests/test_not_when_claims.py` |
| `REPORT_SCHEMA_VERSION` | the JSON report gains, renames or retypes a key (additive-only within a major version) | a new `docs/report-schema-<new>.json` beside the old ones (they stay; every archived schema must keep validating), `tests/test_report_contract.py`, and the `docs/README.md` index line |
| `SCORING_POLICY_VERSION` | a score for the same input changes | the calibration record (`docs/CALIBRATION.md`, `docs/calibration-latest.json`) and an ADR under `docs/adr/` |
| `BASELINE_SCHEMA_VERSION` (`cqa_analyzer/baseline.py`) | the fingerprint algorithm changes | older baselines must still load; say so in a test |

Exit codes (0-6), rule IDs and CLI flags carry a twelve-month deprecation
window announced in the CHANGELOG before removal.

## Fixtures and test data

- **Synthetic only.** Fixtures under `tests/fixtures/` and inline test
  sources are invented code written to trigger or not trigger a rule.
  Never paste code, paths, package names or identifiers from a real
  project, yours or anyone else's.
- Keep a fixture minimal: the smallest input that shows the behaviour.
- Fixtures run through the real CLI where the rule's whole pipeline
  matters (adapter, blanking, path selection, severity policy), as
  `tests/test_not_when_claims.py` does.
- A false-positive fix adds the reported snippet (rewritten
  synthetically) as the should-stay-silent fixture and keeps a
  should-fire twin so the rule is not simply disabled.

## Privacy invariants a PR may not break

[`docs/PRIVACY.md`](docs/PRIVACY.md) is a contract users rely on. A PR
that weakens any of these is declined even if every test passes:

1. **Nothing leaves the machine.** No network call, telemetry, account,
   API key or hosted model at analysis time. `--offline` denies sockets
   and name resolution for the whole run; new code must work under it
   (`tests/test_offline.py`).
2. **Nothing of the analyzed project runs.** No import, build hook,
   subprocess or code execution of the project under analysis.
3. **Every new path, identifier or source text in any output honours
   `--anonymize` and `--redact-paths` exactly like existing output.** If
   you add a key to the JSON report, a SARIF property or a text line that
   carries a path, a name or a snippet, route it through
   `cqa_analyzer/anonymize.py` and add a test that the anonymized report
   does not contain the raw value (`tests/test_anonymize.py`,
   `tests/test_anonymize_provider_health.py`).
4. **SARIF stays minimal.** No source snippets, absolute or `file://`
   URIs, command lines, environment variables, timestamps or repository
   metadata; fingerprints are omitted under `--anonymize`
   (`tests/test_sarif.py`).
5. **Baselines hold only fingerprints.** No paths, messages, snippets or
   identifiers in plain text (`tests/test_baseline.py`).
6. **The parse cache never reaches a report.** Reports expose only the
   aggregate `cache_enabled` boolean (`tests/test_cache.py`).
7. **Stdlib core.** No third-party import outside the `[deep]` extra
   (`tests/test_stdlib_core.py`).

## Reporting

- Bug: the *Bug report* issue form (version from
  `code-quality-analyzer --version`, Python, OS, exact command, expected
  vs observed, synthetic reproduction).
- A rule flagged something safe: the *False positive* form.
- A missing capability: the *Feature request* form. Read
  [`docs/ROADMAP.md`](docs/ROADMAP.md) first; it lists what is planned
  and what was deliberately cut.
- A vulnerability: [`SECURITY.md`](SECURITY.md).

How decisions are made and who merges is in
[`GOVERNANCE.md`](GOVERNANCE.md).
