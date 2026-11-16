# Measured precision

What this page is: every precision number this project has recorded for a
rule, in one place, with the record it comes from. "Precision" here means the
share of reported hits that held up when a reviewer read each one at its
source line. No scan was run to produce this page; every number is copied
from a record in this repository and cited as `RECORD:line`.
Where a record does not state something (a commit, a count), the cell says
so instead of estimating.

## Records cited

| Alias | File | What it is |
|---|---|---|
| `R6` | [reviews/2026-09-21-four-seat-review-6.md](reviews/2026-09-21-four-seat-review-6.md) | Four-seat review 6 of 3.3.0: psf/requests and pallets/click read hit by hit; fixes shipped in 3.4.0. |
| `R5` | [reviews/2026-09-20-four-seat-review-3.2.1.md](reviews/2026-09-20-four-seat-review-3.2.1.md) | Four-seat review of 3.2.1: adversarial fixtures for the security rules that had no corpus hits; fixes shipped in 3.3.0. |
| `SEC` | [reviews/2026-09-19-security-family-calibration.md](reviews/2026-09-19-security-family-calibration.md) | 3.2.0 security family before/after run on the 24-project corpus plus four local repositories and the analyzer itself. |
| `R3` | [reviews/2026-09-14-staff-review-3.1.0.md](reviews/2026-09-14-staff-review-3.1.0.md) | Staff review of 3.1.0: `not_when` metadata claims checked against the detectors. |
| `CL` | [CHANGELOG.md](../CHANGELOG.md) | Release notes; the `### Precision` and `### Calibration` sections carry the shipped counts. |
| `CAL` | [CALIBRATION.md](CALIBRATION.md) | Scoring-fairness corpus (24 projects, eight languages) and the anchor false positives it removed. |
| `CALJ` | [calibration-latest.json](calibration-latest.json) | The 24 corpus rows (repo, sha, files, score) the tests pin. |
| `AB` | [AACR_BENCH.md](AACR_BENCH.md) | AACR-Bench harness: the only external benchmark touched, two PRs so far. |

## How we measure

A rule's precision is measured on real projects, after the fact, by reading.
The 3.2.0 security run took a `findings_snapshot.py` snapshot before and after
the rule change on the same kept clones and diffed per rule; a rule shipped
only if every new hit was traced to source and no project score moved
(`SEC:2-8`). Review 6 read every non-maintainability hit on psf/requests at
source and confirmed all other rule counts were byte-identical before and
after each fix (`CL:158-160`). Review 5 reproduced every candidate with the
released 3.2.1 binary or read the exact source line before accepting it, and
listed the candidates that did not survive under *Dismissed* so a false
positive in the review itself is visible as declined, not silently dropped
(`R5:21-24`); review 6 keeps the same list under *Checked and cleared*
(`R6:30`). Every false-positive fix ships with a test shown to fail on the
pre-fix code, and every new exemption has a paired "still fires" case
(`R6:88-89`, `R5:104-105`). The `not_when` prose each rule carries was itself
checked: 32 of 35 fixturable claims held and the three that did not were
corrected in 3.1.0 (`R3:39-47`).

## Security rules (`*-SEC-*`)

### Corpus hits when the family shipped (3.2.0)

Twenty-seven rules (`CL:316-317`) were run against the 24-project calibration
corpus plus four local repositories and the analyzer itself; 28 of 29 project
scores were unchanged to the decimal (`SEC:4-5`, `SEC:10-11`). Every hit
below is listed by location in `SEC:63-159`. The record does not state the
corpus commit for this run; it used the kept clones of the calibration corpus
(`SEC:2-5`), whose per-round shas are in `CAL:43-56`, `CAL:124-130` and
`CALJ:1-859`.

| Rule | Corpus project | Hits | True positives (as recorded) | False-positive class removed | Release | Record |
|---|---|---|---|---|---|---|
| PY-SEC-001 | fastapi/fastapi | 2 | traced to source: `yaml.unsafe_load` at `scripts/docs.py:105`, `:295` | none | 3.2.0 | `SEC:44`, `SEC:67-68` |
| PY-SEC-004 | httpie/cli | 2 | traced: `verify=False` in `update_warnings.py:44`, `ssl_.py:89` | none | 3.2.0 | `SEC:47`, `SEC:74-75` |
| PY-SEC-004 | redis/redis-py | 2 | traced: `check_hostname = False`, `CERT_NONE` in `http_client.py:276-277` | none | 3.2.0 | `SEC:59`, `SEC:158-159` |
| GO-SEC-001 | gin-gonic/gin | 4 | traced; all `note` (test files) | none | 3.2.0 | `SEC:45`, `SEC:70-73` |
| GO-SEC-001 | redis/go-redis | 20 | traced; `warning` in `example/`, `note` in tests | none | 3.2.0 | `SEC:55`, `SEC:108-127` |
| JAVA-SEC-001 | redis/jedis | 10 | traced; 2 `warning` in `CacheEntry.java`, rest `note` (tests) | none | 3.2.0 | `SEC:58`, `SEC:144-153` |
| JAVA-SEC-003 | jbangdev/jbang | 2 | traced: `BaseCommand.java:122`, `:125` | none | 3.2.0 | `SEC:49`, `SEC:78-79` |
| JAVA-SEC-003 | redis/jedis | 4 | traced; all `note` (tests) | none | 3.2.0 | `SEC:58`, `SEC:154-157` |
| KT-SEC-001 | ktorio/ktor | 2 | traced; `note` (test host) | none | 3.2.0 | `SEC:52`, `SEC:88-89` |
| KT-SEC-003 | javalin/javalin | 4 | traced; all `note` (tests) | none | 3.2.0 | `SEC:48`, `SEC:76-79` |
| KT-SEC-003 | ktorio/ktor | 2 | traced; `note` (test base) | none | 3.2.0 | `SEC:52`, `SEC:90-91` |
| TS-SEC-001 | redis/ioredis | 9 -> 0 | 0: an interface method literally named `eval(script: string, ...)` is a declaration, not a call | declaration named `eval` read as a call | fixed before 3.2.0 shipped | `SEC:15-19`, `CL:378-382`; lock `tests/test_security_rules.py:358` |
| TS-SEC-003 | redis/ioredis | 4 | genuine shape, not actionable: `docs/assets/main.js` is a vendored minified typedoc bundle | none in the rule; discovery excludes minified/bundled files | 3.2.1 | `SEC:25-28`, `SEC:135-138`, `CL:297-300`, `CL:309-310` |
| TS-SEC-003 | fastapi/fastapi | 1 | traced: `docs/en/docs/js/termynal.js:228` | none | 3.2.0 | `SEC:44`, `SEC:69` |
| TS-SEC-003 | private repo (Go+TS) | 1 | traced: JSON-LD script in app layout | none | 3.2.0 | `SEC:34`, `SEC:66` |
| TS-SEC-004 | redis/ioredis | 5 | traced; all `note` (tests) | none | 3.2.0 | `SEC:57`, `SEC:139-143` |
| C-SEC-001 | jqlang/jq | 6 | traced: `strcpy`/`sprintf` without a bound, `src/compile.c`, `src/jv_dtoa.c`, one fuzz test | none | 3.2.0 | `SEC:50`, `SEC:82-87` |
| C-SEC-001 | redis/hiredis | 7 | traced: `sprintf` in `hiredis.c`, `strcpy` in `test.c` | none | 3.2.0 | `SEC:56`, `SEC:128-134` |
| C-SEC-003 | jqlang/jq | 1 -> 0 | 0: adjacent string literals around `#ifdef` inside `fprintf` are one literal | preprocessor line split a literal format string | fixed before 3.2.0 shipped | `SEC:17-19`, `CL:380-382`; lock `tests/test_security_rules.py:370` |
| RS-SEC-001 | redis-rs/redis-rs | 6 | traced: `unsafe` without a `SAFETY` comment in `cmd.rs`, `types.rs` | none | 3.2.0 | `SEC:54`, `SEC:92-97` |
| RS-SEC-003 | redis-rs/redis-rs | 10 | traced; 8 `warning` in `aio/`, `connection.rs`; 2 `note` (tests) | none | 3.2.0 | `SEC:54`, `SEC:98-107` |

Rules with **no** corpus hits in that run, so precision proven on fixtures
only: PY-SEC-002/003/005, GO-SEC-002/003, JAVA-SEC-002, KT-SEC-002,
CS-SEC-001/002/003, TS-SEC-001/002, C-SEC-002, RS-SEC-002 (`SEC:21-23`).

### Fixture-measured false positives (3.3.0)

Review 5 probed the zero-hit rules with benign look-alikes. These are
adversarial fixtures written for the review, not corpus projects.

| Rule | Fixture | Hits | True positives | False-positive class removed | Release | Record |
|---|---|---|---|---|---|---|
| PY-SEC-005, GO-SEC-003 | LLM-sampling code | 10 | 2 (20% precision before the fix) | identifier substrings: `max_tokens`, `footprint`, `hotplug_delay`, `token_index`, `salt_rounds` and camelCase forms; now whole-segment match, quantity/position words skipped; lock: exactly 2 findings | 3.3.0 | `R5:47`, `R5:110`, `CL:251-257` |
| shell, `eval`, `innerHTML`, deserialization rules (PY/TS/GO/JAVA; ids not enumerated in the record) | constants bound once to a literal | 9 | 4 (44%) | bare identifier bound once to a string literal at module/package level treated as dynamic; Python `shlex.join`/`shlex.quote`; lock: exactly 4 findings | 3.3.0 | `R5:48`, `R5:111`, `CL:258-264` |

### Precision on psf/requests (3.4.0)

| Rule | Corpus project (commit) | Hits before | True positives | False-positive class removed | Release | Record |
|---|---|---|---|---|---|---|
| PY-SEC-001 | psf/requests, shallow clone, 37 files (commit not recorded) | 7 | 0 | `pickle.loads(pickle.dumps(x))`: payload produced in the same expression; a name-bound payload still fires | 3.4.0 | `R6:21`, `R6:65`, `CL:162-166` |
| PY-SEC-004 | psf/requests, `tests/` | count not recorded | rule correct on `verify=False`; test-path severity is policy, kept | none | -- | `R6:48-49` |

## Correctness rules (`*-COR-*`)

| Rule | Corpus project (commit) | Hits before | True positives | False-positive class removed | Release | Record |
|---|---|---|---|---|---|---|
| PY-COR-002 | psf/requests (not recorded) | 1 | 0 | `except BaseException: cleanup(); raise`: a bare re-raise as the final statement is a `finally` with access to the exception (ruff `BLE001` parity) | 3.4.0 | `R6:22`, `R6:66`, `CL:167-172` |
| PY-COR-002 | pallets/click (not recorded) | 20 | 13 kept; the `_compat.py` `except Exception: return False` capability probes are broad by design (pylint `W0718` parity) | handler whose body is only `pass`/`...` scored twice, once here and once by PY-COR-003 (7 of 20) | 3.4.0 | `R6:25`, `R6:50-51`, `R6:70`, `CL:179-182` |
| PY-COR-003 | psf/requests (not recorded) | 7 `warning` (R6) / 9 (CL) | all kept; 3 regraded `warning` -> `note` | none removed: `except ImportError: pass` and `except StopIteration: pass` are graded `note` with the idiom named; the two records disagree on the count (7 vs 9) and this page reports both | 3.4.0 | `R6:24`, `R6:68`, `CL:183-188` |
| PY-COR-003 | pallets/click (not recorded) | 16 | 16 | none | -- | `R6:71` |
| CS-COR-004 | StackExchange/StackExchange.Redis (sha not recorded for this run; round-1 corpus sha `7648fc8`, `CAL:44`) | 56 | 26: guarded-but-real `task.Result` reads | `msg.Result` is a plain struct property, not a task; `.Result` now needs a call-shaped or `*task*` receiver | 2.41.0 | `CL:751-753` |
| GO-COR-003 | redis/go-redis (sha not recorded for this run; round-1 corpus sha `8010edc`, `CAL:45`) | 209 | not stated; 167 of 209 were in test files and are graded `note` | none removed (severity grading, not a false-positive fix) | 2.41.0 | `CL:754-756` |
| PY-COR-007, GO/TS/JAVA/KT/CS/C-COR-002 (dynamic SQL) | drogon plus 11 non-SQL calibration repositories (shas not recorded) | 19 in drogon's ORM; 0 across the 11 non-SQL repositories | 19, all genuine | none | 2.41.0 | `CL:716-718` |

## Package rules (`*-PKG-*`)

| Rule | Corpus project (commit) | Hits before | True positives | False-positive class removed | Release | Record |
|---|---|---|---|---|---|---|
| PY-PKG-001 | psf/requests (not recorded) | 1 (an 8-module group) | 0 | cycle closed only by imports under `if TYPE_CHECKING:`; `_types.py` verified to have zero runtime sibling imports | 3.4.0 | `R6:23`, `R6:67`, `CL:173-178` |
| PY-PKG-001 | pallets/click (not recorded) | count not recorded | kept: cycles closed by `if WIN:` module-level and function-local imports are real runtime edges | none | -- | `R6:46-47` |
| RS-PKG-001 | sqlx (sha not recorded) | count not recorded | the remaining hit (`sqlx_rt` in a `#![allow(dead_code)]` file) verified a genuine dead import | `use` paths inside string literals read as crates; `md-5` vs `md5` name mismatch | 2.42.0 | `CL:678-686` |
| C-PKG-001 | not stated | count not recorded | not stated | CMake tokens matched as substrings of the whole file: `"z"` hid zlib, a URL in a comment "declared" curl; tokens are now whole words of 3+ characters with comments removed | 2.37.0 | `CL:920-922` |

## Duplication rules (`*-DUP-*`)

| Rule | Corpus project (commit) | Hits before | True positives | False-positive class removed | Release | Record |
|---|---|---|---|---|---|---|
| PY-DUP-001 | pallets/click (not recorded) | 10 | 10 (identical `get_completion_args` across three shells; duplicated test doubles) | none | -- | `R6:44-45`, `R6:72` |

The two AACR-Bench PRs each carried one duplication annotation and
PY-DUP-001 matched neither: both describe duplicated *logic*, which
normalised-AST identity does not consider identical (`AB:32-41`). That is a
recall observation, not a precision one.

## Maintainability rules (`*-MAINT-*`)

No per-hit precision record exists. Review 6 read every *non-maintainability*
hit on psf/requests (`CL:158`); complexity, length and parameter-count
findings were not read at source in any recorded pass. Their thresholds are
documented in [RULES.md](RULES.md); nothing here says how often they are right.

## Scoring signals (not rules)

The architecture-signal catalog is scored, not reported as findings, so its
false positives move a project's score rather than its finding list. Recorded
removals:

| Signal | Corpus project (commit) | What fired wrongly | Score before -> after | Release | Record |
|---|---|---|---|---|---|
| `bit_manipulation` | redis/hiredis (`33a12fb`, `CAL:43`; the 2.37.0 rerun was on the same commit, `CAL:290`) | `"1 <<"` substring-matched `r1 << shl`, `x1 << 32` | 4.1 -> 3.3 | 2.37.0 | `CAL:305-308` |
| `binary_search` | jqlang/jq (`9d241e2`, `CAL:124`; same commit in the rerun, `CAL:283`) | `">> 1"` matched `>> 16` | 4.6 -> 4.4 | 2.37.0 | `CAL:309-310` |
| import anchors (`hyper`, `cached`) and universal Rust syntax (`dyn`, `new`, `from`, ...) | BurntSushi/ripgrep (sha not recorded for that run; current corpus sha `3fce3b5`, `CALJ:828-829`) | substring import match hit the local `hyperlink` module and `cached_` identifiers; syntax every crate uses counted as evidence; Rust now matches whole `::` segments and those anchors are removed | ripgrep 8.6 -> 6.8 | 2.43.0 | `CAL:323-325`, `CAL:330-341`, `CAL:349` |
| `optimistic_concurrency`, `security_hardening` anchors | javalin, fzf, wallet-transfer-service, HUMM | HTTP constant tables, a keybinding denylist, `import secrets`, an atomic `CompareAndSwap` | four anchors removed before release | 2.44.0 | `CAL:392-403`, `CL:582-585` |

## What is not measured

- **No recall numbers.** Nothing above says what the analyzer misses. The
  only external benchmark touched is AACR-Bench: two PRs so far, which prove
  the pipeline and nothing about recall (`AB:32-41`); precision against its
  annotated set is a floor, because an unannotated real hit scores as false
  (`AB:21-28`, `AB:117-119`). The 17.3% keyword overlap is an upper bound and
  must not be cited as a result (`AB:91`, `AB:110-112`, `R3:96-97`).
- **The corpus is small.** Per-hit reading exists for two Python projects,
  psf/requests and pallets/click (`R6:8-9`), and for the security family's
  first run on the 24-project calibration set plus four local repositories
  and the analyzer itself (`SEC:2-5`, `CALJ:1-859`). For every other rule in
  every other language the recorded evidence is fixtures, score stability on
  that corpus, and the release notes above.
- **Commits are partly unrecorded.** Review 6 names a shallow clone of
  psf/requests with 37 files and no sha (`R6:65`, `CL:156`); the security run
  names no sha of its own (`SEC:2-5`). The calibration tables record shas per
  round (`CAL:43-56`, `CAL:124-130`, `CALJ:1-859`), and those projects have
  moved since.
- **Maintainability rules were never read at source** (see above).
- **Fourteen security rules had zero corpus hits** and are measured only on
  fixtures (`SEC:21-23`, `R5:18-19`).
- **Test-path severity is policy, not precision.** Many security hits above
  are `note` because they sit under a test path; the record calls that a
  policy choice, not a false positive (`R6:48-49`).
- **Nothing was re-run for this page.** Every number is from a record dated
  September 2026; the analyzer is at a later version and the corpus projects
  have new commits.
