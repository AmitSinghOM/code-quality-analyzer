# Four-seat review of 3.2.1 (Staff / Product / Security / CTO)

Date: 2026-09-20. Base: `df8eb08` (v3.2.1, ruleset 2.25.0, schema 1.12.0).
Before-state: self-scan 149 findings (all warnings, no SEC hits), recorded
before any change so the after-diff is mechanical.

## Scope

Earlier passes (2026-09-10 rounds 1-2, 2026-09-14 staff review, 2026-09-19
security-family calibration) covered lexers, ReDoS, config trust, the
report schema, and corpus precision of the rules that *had* corpus hits.
This pass deliberately targets what none of them reached:

- the 3.0 argparse CLI edge behaviour,
- the MCP server's subprocess boundary and cqa-action's heredoc steps,
- the same-line suppression directive and its visibility in reports,
- the 3.2.1 discovery heuristic for minified files,
- the fourteen SEC rules that had zero corpus hits (precision proven only
  on fixtures), probed with benign look-alikes.

Every finding below was reproduced with the released 3.2.1 binary or read
from the exact source line before it was accepted. Candidates that did not
survive that check are listed under *Dismissed* so false positives in the
review itself are visible as declined, not silently dropped.

## Comparators (fetched live from the GitHub API on 2026-09-20)

| repo | stars | license | latest release |
|---|---|---|---|
| astral-sh/ruff | 49,706 | MIT | 0.16.8 (2026-09-16) |
| semgrep/semgrep | 16,704 | LGPL-2.1 | v1.177.0 (2026-09-10) |
| securego/gosec | 8,948 | Apache-2.0 | v2.29.0 (2026-08-26) |
| PyCQA/bandit | 8,276 | Apache-2.0 | 1.9.4 (2026-02-25) |
| cqa-analyzer | 0 | MIT | v3.2.1 |

Read from their source, not from memory: bandit counts `nosec` in its
metrics (`bandit/core/metrics.py`); gosec counts `NumNosec` **and** emits
SARIF `suppressions[]` with kind and justification per result
(`report/sarif/formatter.go`). bandit's `ArgumentParser()` also leaves
`allow_abbrev` on, so prefix matching is not unusual in this class of tool.

## Accepted findings

| # | Seat | Sev | Finding | Evidence | Fix |
|---|---|---|---|---|---|
| A1 | Security | HIGH | `mcp_server._run_cli` runs `python -m cqa_analyzer` with the server's inherited cwd; `-m` puts cwd first on `sys.path`; MCP hosts start servers with cwd = the open workspace, so an untrusted repo containing `cqa_analyzer/__main__.py` executes with the user's privileges when the agent calls `scan`/`gate`/`preview`. `--offline` cannot help: the hijack runs before the analyzer exists. | Reproduced with the pipx interpreter (3.14.7): planted file printed `HIJACKED`; `-P` and `-I` both restored `version 3.2.1`. | Add `-P` (Python >= 3.11, already required). Test: fixture repo with a hijacking `cqa_analyzer/__main__.py`, run with `cwd=fixture`, assert `analyzer_version == __version__`. |
| A2 | Security+Staff | HIGH | `_security.SECRET_NAME` allows any letter before the keyword and has no trailing boundary, so it matches substrings: `max_tokens`, `footprint` and `hotplug_delay` (via `otp`), `token_index`, `salt_rounds`, `maxTokens`, `tokenIndex`. | Fixture of LLM-sampling code: 10 PY-SEC-005/GO-SEC-003 findings, 8 false, 2 true (20% precision). Zero corpus hits had hidden it. | Match whole identifier segments (snake and camel split) and skip names carrying a quantity/position word (`max`, `num`, `count`, `len`, `index`, `idx`, `rounds`, `rate`, `limit`, `delay`, `timeout`, ...). Lock: exactly 2 findings on the fixture. |
| A3 | Staff+Security | MED-HIGH | Dynamic-argument rules treat a bare identifier as dynamic even when it is a top-level constant bound to a literal, in every language probed (`CMD = "ls -la"`, `const template = "<b>hi</b>"`, `const script = "echo hi"`). Python also flags `shlex.join(...)` and f-strings whose every hole is `shlex.quote(...)`. | Fixture across PY/TS/GO/JAVA: 9 findings, 4 true, 5 false (44%). Strings, comments, `enum { eval }`, `model.eval()`, `DOMPurify.sanitize`, `textContent`, list-form `run`, commented-out `ObjectInputStream` all correctly silent. | Same-file, top-level, single-binding literal-constant resolution before classification; `shlex` not_when for Python. Lock: exactly 4 findings on the fixture. |
| A4 | Security+Product | MED | Suppressions leave no trace: `scan_health` has no suppressed count and neither suppression module records what it dropped. A `// cqa: ignore=GO-SEC-001 reason="x"` silences a security finding invisibly in JSON, SARIF and the summary. | `scan_health` keys enumerated from the before-state report; both modules read. gosec emits SARIF suppressions; bandit counts nosec. | Additive `scan_health.suppressions` (count, by rule, examples with reason); SARIF `suppressions[]` with `justification` (SARIF 2.1.0 supports this); `-v` line. Schema minor bump. |
| A5 | Staff | MED | `discovery.generated_reason` applies the minified-content heuristic to every language. A 3-line `constants.py` with one 6k literal and a 12-line `schema.go` with one 6k DDL string are both excluded from every rule, including SEC, with no toggle and no effect on `authoritative`. | Direct probes of `generated_reason`. | Gate the content heuristic on JS/TS/CSS extensions (only those ecosystems minify); keep the name rule. Lock: both probes analysed, an ioredis-style bundle still excluded. |
| A6 | Product | MED | A file named in `--changed-lines-manifest` that discovery drops as generated is never mentioned by the gate: a silent "your changed file was not checked" hole in a PR gate. | `changed_lines.py`/gate code contain no reference to generated exclusions. | Gate summary line and additive report field listing changed files excluded; cqa-action job summary shows it. |
| A7 | Security | MED | cqa-action `action.yml` lines 177 and 203 run `python - <<'PY'` with cwd = the PR checkout; `python -` puts cwd ahead of the stdlib, so a PR committing `json/__init__.py` executes inside the gate job. The analyzer itself is invoked via the console script and is not affected. | Reproduced: `SHADOWED` vs stdlib `json` with `python -P -`. Impact bounded (fork PRs hold a read-only token). | `python -P -` on both heredocs (action defaults to 3.12); cqa-action v1.2.0, move `v1`. |
| A8 | Staff | MED | `build_parser()` leaves argparse `allow_abbrev` on while its docstring promises "flags unchanged from 2.x" and the project promises a 12-month flag deprecation window. click never matched prefixes, so 3.0 silently widened the accepted flag set; the next flag sharing a prefix turns today's working `--off` into an error. | Live: `--off` and `--output-form json` accepted; `--fail 5` errors as ambiguous; `--output FILE` misparsed as `--output-format`. | `allow_abbrev=False` plus a test that `--off` exits 2 with `unrecognized arguments`. |
| A9 | Staff | LOW | `_suppressions.comment_suppression_lines` computes each directive's line with `source.count("\n", 0, match.start())`, quadratic in directives x file size (bounded by `MAX_DIRECTIVES` and max-file-size). | Read. | Precompute newline offsets once and `bisect`. |
| A10 | Staff | LOW | GO-SEC-003 anchors the first statement after `{` one line early (lines 6 and 13 reported as 5 and 12; lines 7 and 8 correct). | Observed in the A2 fixture; cause not yet read. | Anchor at `group("name")` start. Verify in `go.py` before fixing. |
| A11 | Docs | NOTE | README recommends `python3 -m cqa_analyzer` for PATH problems (lines 202, 247, 252). | Read. | Suggest `python3 -P -m cqa_analyzer` with one sentence why. |

## Dismissed candidates (with reasons)

| Candidate | Why it is not a finding |
|---|---|
| `_cli_args` flag injection through option values | Values are separate argv elements with no shell; a value beginning with `--` makes argparse fail with "expected one argument" rather than being consumed; the positional path is checked `is_dir()` so it cannot be a flag. |
| Agent-supplied `baseline`/`config`/`changed_lines_manifest` paths read arbitrary files | The CLI parses them and returns findings, not file contents; an MCP agent already holds the same filesystem access as the user. Not an escalation. |
| `MINIFIED_NAME` regex over-matching | `admin.js`, `min.js`, `vitamin.js`, `webpack.config.js` do not match (a separator is required). `types-min.d.ts` is not matched, which is acceptable. |
| Empty-reason directive parity between `_suppressions` (`[^"]*` then strip) and `python_suppressions` (`[^"]+`) | Both reject a blank reason; behaviour is identical. |
| Minified heuristic evasion with 4,999-character lines | By-design threshold; an author deliberately evading a lint gate has cheaper options, and A4 makes the remaining silent path (suppression) visible. |
| argparse prefix matching as a competitive gap | bandit has the same default. A8 stands only on cqa's own compatibility promise, so it is MEDIUM, not a comparator finding. |
| `tokens_per_second = random.gauss(...)` silent in the A2 fixture | `gauss` is not in the rule's random-call set; the rule is scoped to token-shaped draws. Not a miss worth widening for. |
| cqa-action console-script invocation | `code-quality-analyzer` is a console script whose `sys.path[0]` is the bin directory; `python "$ACTION_PATH/scripts/changed_lines.py"` has `sys.path[0]` = the trusted scripts directory. Neither is hijackable. |

## Seat positions

- **Staff**: A2 and A3 are the ones that decide whether the SEC family
  survives contact with real code; ship them before anything else and make
  the fixtures permanent. A8 is cheap and closes a contract gap. A5 is a
  false-negative class, which is worse than a false positive for a gate.
- **Product**: A4 and A6 are what make the gate *auditable*: a reviewer
  must be able to see what was silenced and what was not checked. Without
  them "zero findings" is not a statement about the code.
- **Security**: A1 is the only finding that turns a read-only tool into a
  code-execution vector; it ships first, with A7 as the same class in the
  action. A4's SARIF suppressions with justification is the shape gosec
  already uses and GitHub renders.
- **CTO**: with zero stars the package competes on trust, not features.
  Every item here is a trust item: nothing runs from the scanned tree,
  every silenced finding is visible, every security rule has a measured
  precision on adversarial fixtures. Bandit-class precision on `random`
  would end adoption before it starts. No new rules or languages this
  release.

## Plan

Fix order: A1, A2, A3, A5, A8, A4, A6, A9, A10, A11 in this repo (3.3.0:
additive schema minor for A4/A6, ruleset minor for A2/A3/A5 behaviour);
A7 in cqa-action (v1.2.0). Each fix lands with a test proven to fail on
`df8eb08`. Closing evidence: full suite on 3.12 and the newest interpreter,
ruff, the corpus before/after diff via `scripts/findings_snapshot.py`
(expected: only reductions on the FP classes above, zero new findings),
and an independent code-reviewer pass over the fix commits.


## Outcome (2026-09-21)

Every accepted finding in this repository is fixed on `review5/four-seat-2026-09-20`,
each with a test proven to fail on `df8eb08` before the fix was applied:

| Finding | Commit | Proof of discrimination (test failure on 3.2.1 code) |
|---|---|---|
| A1 MCP `python -m` hijack | `297f5d4` | `'HIJACKED' == '3.2.1'` |
| A2 secret-name substrings + A10 anchor | `476483f` | import failure / `'sessionKey' in 'func RealBug() int64 {'` |
| A3 literal constants treated as dynamic | `4104a6b` | `[8, 10, 12, 17] == [17]`, `[8, 14] == [14]`, `[4, 12] == [12]` |
| A4 minified rule on non-JS files | `1339545` | `'minified_content' is None` x4, `{'minified_content': 1} == {}` |
| A5 flag prefixes accepted | `774396e` | `assert 0 == 2` x4 |
| A6 suppressions invisible + A9 quadratic lines | `45b48e5` | new keys absent on 3.2.1 (schema 1.13.0) |
| A7 unanalyzed manifest files pass silently | `94838cb` | `assert 0 == 3` (strict exit) |
| A11 README `python -m` tip | `bde185e` | doc change |

A8 (cqa-action `python -` heredocs need `-P`) lives in the `cqa-action` repository
and ships as its v1.2.0; not part of this branch.

### Closing gate

- Full suite: 855 collected, 843 passed, 12 skipped (all `tests/test_deep.py`,
  optional `[deep]` extra absent from the local interpreter; CI has that leg).
  52 tests added versus 3.2.1. `ruff check .` clean.
- CQA on the analyzer itself, `df8eb08` vs branch, findings paired by
  (path, rule, function) so line shifts do not count: score 7.5 -> 7.5,
  149 -> 149 findings, NEW: [], GONE: []. Three findings the branch introduced
  (`constant_literal` cyclomatic 12, `module_constants` 13, one test span 63)
  were refactored away, not suppressed (`413a8d2`). The report now shows the
  analyzer's own pre-existing `PY-COR-003` directive under `scan_health.suppressed`
  -- A6 working on day one.
- Independent code-review pass (code-reviewer skill, run inline: manifest of
  25 files in 9 bundles over `df8eb08..HEAD`, risk-ordered, every row REVIEWED).

### Closing-pass findings (against this branch's own commits)

Accepted and fixed:

- **R1 (HIGH)** -- the suppression ledger recorded drops only in the per-file
  rule packs; the Python package analyzer (`PY-PKG-004/005`,
  `package_intelligence.py`) and the duplication analyzer (`PY-DUP-001`,
  `duplication.py`) still filtered with plain `(line, rule)` sets, so those
  suppressions stayed invisible -- contradicting the README sentence written on
  this branch. Both now record with the directive's reason; a legacy set still
  works for external callers. `a28a767`; test fails on the unfixed code with
  `('PY-PKG-004', 'generated at build time') in set()`.
- **R2 (HIGH, privacy)** -- `files_not_analyzed_examples` (A7) carried raw
  manifest paths into `--anonymize` JSON and SARIF output; the existing
  anonymization test had every manifest file analyzed, so the list was empty.
  Reproduced (`private/customer_list.txt` present in both outputs), fixed by
  tokenizing through the anonymizer's `file()`; `3ac6ae2`; test fails on the
  unfixed code with `['private/customer_list.txt'] == ['file-0001']`.
- **R3 (MEDIUM, self-caught while writing docs)** -- the README promised
  "suppression reasons never enter reports", which A6 made false; reasons are
  author free text, so they are now `[redacted]` under `--anonymize` and the
  README states the real contract. `bde185e`.

Dismissed with reasons:

- *ContextVar ledger lost across threads* -- no thread pools, executors or
  asyncio anywhere in the package (grep), and the MCP server scans in a
  subprocess whose context is fresh per scan.
- *`-P` placed after `-m` would be a module argument* -- argv is
  `[python, "-P", "-m", "cqa_analyzer", ...]`; interpreter flag position verified.
- *`_suppressed_result` on a payload lacking `suppression_reason`* -- only
  `_suppressed_payload` produces those payloads and it always sets the key.
- *`reporters.py` diff is large* -- whole-file `ruff format` churn on a file
  that was pre-existing unformatted (49 such files at `df8eb08`; CI enforces
  `ruff check` only). Accepted as noise limited to files this branch edited;
  22 untouched files that a package-wide format had swept in were restored
  before commit.

Known limitations recorded, not fixed (inside the documented "top-level,
single definition" contract of A3; precision over recall):

- A block-local `const local = "<b>x</b>"; el.innerHTML = local` inside a
  function is not resolved and still fires.
- A function-like C macro `system(CMD("-a"))` is classified as a call and fires
  even when the macro expands to adjacent literals.

Both are candidates for a later, separately calibrated widening of
`constant_literal`.
