# Four-seat review 6 -- cqa-analyzer 3.3.0 (`26be993`)

Date: 2026-09-21. Seats: Staff development engineer, Product engineer,
Security engineer, CTO. Branch `review6/four-seat-2026-09-21`, 17 commits on
`26be993` (= v3.3.0), none pushed. This pass targeted only surfaces reviews
3-5 did not reach: baseline identity, cache invalidation across upgrades,
import-order robustness, repo-controlled file containment, anonymizer
completeness, SARIF spec validity, and rule precision on real projects
(`psf/requests`, `pallets/click`).

## Accepted and fixed

| Id | Seat | Sev | Finding | Fix / lock | Commit |
|----|------|-----|---------|------------|--------|
| B1 | Staff+CTO | HIGH | Baseline fingerprint hashed `(rule, path, line, column, message)`; one inserted line above a baselined finding, a re-indent, or a reworded message re-failed the PR under `--new-findings-only`. | Schema 2.0.0: rule + redaction-independent path + whitespace-collapsed line text + ordinal among identical lines. 1.0.0 baselines still load and compare with the legacy hash. `tests/test_baseline_stability.py`. | `ba60c75` |
| C1 | CTO | MEDIUM | SARIF carried no `partialFingerprints`, so GitHub code-scanning alerts churned on every line shift. | `fingerprint` on JSON findings, `partialFingerprints["cqaFingerprint/v2"]` in SARIF; report schema 1.13.0 -> 1.14.0. Omitted under `--anonymize` (see dismissed). | `bb18be2` |
| B2 | Product | LOW | Every non-size `SafeReadError` collapsed to "not readable valid JSON" for baselines and manifests. | `read_failure_message` names the boundary (symlink, outside root, undecodable, ...). `tests/test_read_failure_messages.py`. | `83c7bf0` |
| B3 | Staff+CTO | MEDIUM | Parsed-artifact cache keyed on hand-maintained `adapter_version`; three 3.3.0 lexer fixes bumped none of the fourteen constants, so a 2.36.0 cache served pre-fix `code_text` on 3.3.0. | Cache metadata folds `analyzer_version` and a digest of the adapter module's source. `tests/test_cache.py`. | `203dfed` |
| C2 | CTO | -- | SARIF validity was asserted by shape, never against the spec. | Vendored OASIS 2.1.0 schema (byte-identical to schemastore), `jsonschema` pinned in `[dev]`, `tests/test_sarif_schema.py` incl. a guard-against-the-guard case. | `0fb8851` |
| B4 | Staff | MEDIUM | Latent circular import since 3.2.0 (`python_rules -> python_security -> languages.* -> languages.python -> python_rules`), hidden by test-module order. | Leaf modules `test_paths.py`, `secret_names.py`; `tests/test_import_order.py` imports each of 58 modules first in its own subprocess. | `d7f4dba` |
| P3 | Product | HIGH (precision) | `PY-SEC-001` fired on `pickle.loads(pickle.dumps(x))` (7/7 hits on requests). | Silent when the payload is a literal `dumps` call; name-bound payloads still fire. | `4fa1a82`, `c08b180` |
| P5 | Product | MEDIUM (precision) | `PY-COR-002` fired on `except BaseException: cleanup(); raise`. | Exempt when the final statement is a bare `raise` / `raise <bound name>`; wrapping or logging stays reported (ruff `BLE001` parity). `not_when` rewritten with the reason. | `4fa1a82`, `c08b180` |
| P4 | Product | HIGH (precision) | `PY-PKG-001` reported an 8-module cycle on requests closed only by `if TYPE_CHECKING:` imports. | `_runtime_import_nodes` skips guard bodies, walks `else` and nested scopes. `_types.py` verified to have zero runtime sibling imports. | `766a549` |
| P6 | Product | MEDIUM (precision) | `PY-COR-003` warned on `except ImportError: pass` / `except StopIteration: pass`. | Note tier when every caught type is expected control flow; mixed tuples stay warnings. | `eeec038` |
| P7 | Product | MEDIUM | `PY-COR-002` and `PY-COR-003` both fired on `except Exception: pass` (7/20 on click) -- one handler scored twice. | Swallow rule owns silent handlers; broad rule skips them. | `d00f01b` |
| R1 | Staff (reviewer) | MEDIUM | *Introduced by B1:* context-less provider findings shared one ordinal counter per (rule, path); fixing the first renumbered survivors as new. | Ordinal keyed on (rule, path, line, column) for context-less findings. Lock fails on pre-fix code. | `f0c81dd` |
| R3 | Staff (reviewer) | MEDIUM | *Introduced by B4:* import-order children ran with `-P` and would pass against a stale site-packages install. | Child prints `cqa_analyzer.__file__`; test asserts it is the tree under test. | `e92bee0` |
| R4 | Staff (reviewer) | LOW | *Introduced by C2:* redacted-SARIF case validated without asserting results exist. | Asserts non-empty results. | `e92bee0` |

## Checked and cleared (declined, with evidence)

- S4 ReDoS on 3.3.0's new regexes (`is_secret_name`, `_constant_definition`,
  `_rebinding`, `_define_directive`): 1-11 ms on 32k-char identifiers and 200k-char
  lines; kept as regression tests in `tests/test_lexer_fuzz.py`.
- X1 Path containment on a hostile checkout (file/dir symlinks out of root,
  `/etc/hosts`, symlinked config/manifest/baseline, 6 MB manifest): all refused
  or skipped and counted; marker string never reaches the report. Config symlink
  is a hard fail-closed error (correct for a repo-controlled file).
- X2 Anonymizer completeness: sixteen seeded tokens across every source-derived
  surface (paths, identifiers, messages, suppression reasons, dropped manifest
  paths, pyproject names); zero survivors in anonymized JSON, SARIF, text.
- C2 probe: three real SARIF outputs (fingerprints, suppressions, anonymized,
  empty) validate against the official schema with zero errors.
- P2 `PY-DUP-001` on click: 10/10 true positives (identical
  `get_completion_args` across three shells, duplicated test doubles).
- `PY-PKG-001` on click: cycles closed by `if WIN:` module-level and
  function-local imports are real runtime edges; documented `not_when` holds.
- `PY-SEC-004` `verify=False` under `tests/` on requests: rule is correct;
  test-path severity is policy.
- Remaining `PY-COR-002` on click's `_compat.py` (`except Exception: return False`
  capability probes): broad by design, pylint `W0718` parity; kept.
- Tokenised fingerprint in anonymized reports: rejected by the Security seat --
  the v2 hash is over real path + line text and would be a confirmation oracle.
- Manual `adapter_version` bump discipline as the B3 fix: rejected; it already
  failed three times in one release.
- R2 `_attach_fingerprints` keyed on `id(finding)`: correct for the live objects
  the CLI passes; accepted as a documented invariant, not changed.
- S2 TOML config parsing edges: descoped -- X1 and B2 exercised the loader's
  boundaries; review 5 already holds 38 `not_when` fixtures for config.

## Real-project precision ledger

| Project | Rule | Before | After |
|---------|------|--------|-------|
| psf/requests (37 files, authoritative) | PY-SEC-001 | 7 | 0 |
| | PY-COR-002 | 1 | 0 |
| | PY-PKG-001 | 1 (8-module group) | 0 |
| | PY-COR-003 | 7 warn | 4 warn + 3 note |
| | all other rules | -- | byte-identical |
| pallets/click | PY-COR-002 | 20 | 13 |
| | PY-COR-003 | 16 | 16 |
| | PY-DUP-001 | 10 | 10 (all true) |

## Closing gate

- `ruff check .` clean; full `pytest`: 955 passed, 12 skipped (all `[deep]`
  extra), 0 failed (`26be993` release commit collected 857).
- Self-CQA paired by (path, rule, line-stripped message): 149 -> 148 findings,
  architecture score unchanged, one visible suppression unchanged. The only
  movement is two pre-existing maintainability findings re-measured
  (`_build_json_report` 97 -> 101 lines; `_build_import_graph` cognitive
  25 -> 22 and its cyclomatic finding gone). Zero new findings from the
  review-6 code.
- Code-reviewer skill (`review_manifest.py manifest --from 26be993 --to HEAD`):
  35 files, 9 risk-ordered bundles, all read; produced R1-R4 above. As in
  reviews 4 and 5, the pass over the fixer's own commits found defects the
  fixer introduced.
- Every fix is locked by a test shown to fail on the pre-fix code (stash or
  `HEAD~1` checkout), and every exemption has a paired "still fires" case.

## Process slips owned

- Cycle 36: a `;` after `git stash pop` let a commit fire past a red pytest;
  the failing assertions were the author's own off-by-one slices. Amended before
  any push.
- Cycle 46: a heredoc edit and a commit on separate lines let the commit fire
  after the edit's anchor failed, so `b6cb5f3`'s message overclaimed R4. Amended
  to `e92bee0` with matching content.
- Repeated: `pytest -k` / bad globs silently deselecting a gate (exit 4 is a
  usage error); a helper appended below the `__main__` guard (lint-clean,
  `NameError` at runtime); a non-editable install shadowing branch code.
