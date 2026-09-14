# Staff review: 3.1.0 delegate mode

Reviewer: agent, acting as staff development engineer. Date: 2026-09-14.
Scope: commits `67d5489` and `c623fb7` on `dev/v3.1.0-delegate-mode`
against `main` at `07551f2`. Every claim below is backed by a command that
was run; nothing is asserted from reading alone.

## Verdict

**Approve.** The release adds surface without touching analysis output, the
new code meets the analyzer's own bar, and the one class of defect the
review found (metadata prose that did not match detector behaviour) is
fixed and locked by test.

## Is the analyzer upgraded, not degraded?

| Check | main `07551f2` | branch `c623fb7` | Evidence |
|-------|----------------|------------------|----------|
| Test suite | 656 collected | 705 collected, 704 passed, 1 skipped | `pytest -p no:cacheprovider` |
| ruff check / format | clean | clean | `ruff check .` |
| Ruleset / policy / schema | 2.24.0 / 2.1.0 / 1.12.0 | unchanged | `cqa_analyzer/__init__.py` |
| Self-scan findings on this tree | 150 | 146 | `python -m cqa_analyzer . --output-format json` |
| Self-scan score | 7.4 | 7.4 | same |
| New findings in files this release added | — | 0 | filtered self-scan |

The self-scan is the honest metric: the first pass of the new code added
10 findings (functions over the complexity and length limits, one
swallowed exception). All were fixed by refactoring rather than by
suppression, and the branch ends four findings below `main`.

## Are the results positive results, not false positives?

### `not_when` metadata (68 rules)

Method: for each clause that can be expressed as code, one fixture the rule
must flag and one the clause says it must ignore, run through the real CLI
(`tests/test_not_when_claims.py`, 38 cases).

Result: 32 of 35 original claims held. **Three were false** and would have
told a host agent to discard real findings or expect silence that does not
happen:

1. PY-COR-001 flags `list()`/`dict()`/`set()`/`bytearray()` calls and
   comprehensions, not only displays.
2. PY-PKG-001 builds its import graph with `ast.walk`; a function-local
   import still closes a cycle.
3. The test-path downgrade (`downgrade_in_tests`) is applied only by
   GO-COR-003, TS-COR-005, KT-COR-005 and RS-COR-001. It had been attached
   to six other rules.

All three are corrected in `c623fb7`; a guard test asserts the downgrade
clause appears on exactly those four rules.

### `preview`

Claim: planned set equals what discovery scans. Verified on this repo
(100 = 100) and on cloudscale-backend (109 = 109, 33 pruned directories),
plus a fixture project exercising every exclusion reason.

### `rules_for_files`

Claim: hostile paths rejected, skip reasons match discovery, grouping keys
on the exact enabled rule set with config policy applied. Verified by unit
tests and on cloudscale-backend (20 changed paths → one 19-rule Python group
of 11 files, 9 non-source files `unsupported_extension`).

### `diff_to_manifest`

Claim: every post-change added or modified line is covered, nothing else
is. Oracle: `git diff -U0` hunk headers parsed independently. This repo's
working diff: 771 lines, 0 uncovered. cloudscale-backend commit `21d4f17`:
91 lines, 0 uncovered. Emitted manifests were consumed by the real CLI
gate, and the CLI's selection matched an independent overlap computation
exactly.

## Findings that changed the code

- Dead no-op branch in the first `diff_to_manifest` draft — removed.
- `except OSError: pass` in temp-file cleanup — the analyzer flagged it
  (PY-COR-003); replaced with `contextlib.suppress`.
- A `ruff format cqa_analyzer/` run reformatted 26 unrelated files; all 26
  verified AST-identical and restored so the commit stays scoped.

## Findings that changed the docs, not the code

- Nested-repository paths: when the project sits inside a parent git repo,
  `git show --name-only` returns toplevel-relative paths and
  `rules_for_files` reports them `missing` rather than guessing. Correct
  usage (`git … --relative`) is now in the README.

## Deliberately not done

- Glob-scoped rule policies and a wall-clock scan deadline with partial
  results: checked against `config.py` and the MCP timeout path, recorded
  as ROADMAP item 13. Both are scanner-level changes.
- An AACR-Bench harness: feasibility in `docs/AACR_BENCH.md`; the 17.3%
  keyword slice is an upper bound and must not be cited until measured.

## Residual risk

- `not_when` clauses that cannot be fixtured (e.g. "confirm before acting"
  guidance on medium-confidence dependency rules) are still prose. They
  are advisory and phrased as such.
- The remaining self-scan findings (`handle_message` complexity, `_rule`
  parameter count, one broad handler at the JSON-RPC boundary) predate this
  release and are unchanged.
