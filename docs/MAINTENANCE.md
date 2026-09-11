# Maintenance Policy

This document records what keeps the analyzer trustworthy over years,
what rots without attention, and the minimum cadence that prevents it.
It exists because the project's durability is a design feature: the
same properties that make analysis air-gap-safe (no network, no
toolchain execution, two runtime dependencies, stdlib analysis core)
make an installed copy keep working long after release.

## What does not rot

- **The shipped artifact.** Pure-Python wheels (`py3-none-any`) with
  two pinned runtime dependencies (`click`, `rich`) install and run for
  as long as a supported Python exists. There is no server, telemetry
  endpoint, or external service whose shutdown can break analysis.
- **New Python syntax support.** Parsing uses the host interpreter's
  `ast`, so running under a newer Python parses that Python's syntax
  automatically.
- **Report contracts.** Schema and ruleset versions are explicit;
  consumers built against a schema keep working. Cache entries from
  older versions miss safely by construction.

## What rots, and the response cadence

| Surface | Rots how | Cadence |
|---|---|---|
| Supported Pythons | CPython versions reach end-of-life yearly | Drop an EOL Python in the first release after its EOL date; add the new stable within two releases |
| Architecture patterns | Design patterns name today's frameworks; new frameworks go unrecognized (under-reporting, never breakage) | Review `patterns.py`, `go_patterns.py`, `ts_patterns.py` yearly against current ecosystem defaults |
| Dependency pins | Runtime pins (`click`, `rich`) and dev pins (`pytest`, `ruff`, `build`, `twine`, `pip-audit`) accumulate CVEs and staleness | CI runs `pip-audit` on every push; act on findings immediately, review pins yearly |
| CI infrastructure | Pinned action SHAs and runner images deprecate | Refresh action pins (real SHAs only, fetched from the GitHub API) and runner labels yearly |
| Release pipeline | PyPI/GitHub policy changes (2FA, Trusted Publishing claims) | Verify one end-to-end publish per year at minimum |

**Minimum viable maintenance: one small release per year** covering the
table above. The automated pipeline (green CI matrix, publish-on-release
via Trusted Publishing with attestations, no tokens) is designed to make
that release a sub-hour task.

## Python version policy

`requires-python` tracks CPython's supported window: the floor rises to
exclude a version in the first release after that version's end-of-life.
Dropping a floor is a minor version bump and a CHANGELOG entry; code may
then rely on the new floor's stdlib (as happened when `tomli` was
removed in favor of `tomllib` at the 3.11 floor).

## Security response

Vulnerability reports follow [`SECURITY.md`](../SECURITY.md). A
dependency CVE with a fix ships as a patch release as soon as the gate
is green; the pinned-dependency comments in `pyproject.toml` record the
advisory that forced each floor.

## Continuity notes

- The project is single-maintainer; everything needed to release lives
  in this repository (`docs/RELEASING.md`) and requires only the GitHub
  and PyPI accounts — no local state, keys, or tokens.
- If the project is abandoned: the last release keeps installing and
  scanning correctly; the README's honest-contract sections remain
  accurate; nothing phones home to fail. Pattern staleness degrades
  recall gradually, never correctness.

## Style gate decision

`ruff check` (lint, including import order and bugbear rules) is a CI
gate. `ruff format --check` is deliberately **not**: the codebase
predates the formatter and about 60 files carry hand-wrapped
regex/pattern tables that the formatter would explode into one entry per
line, hurting the readability those tables exist for. New files and
substantially rewritten files are formatted; existing files are not
reformatted wholesale to keep `git blame` useful. Revisit if a second
regular contributor joins.

## Known analysis bounds (documented, not defects)

- **TypeScript regex after `)`**: `if (ok) /re/.test(s)` is read as
  division; the regex body leaks into identifiers. The prev-token
  heuristic cannot distinguish this from `(a) / b` without a parser.
- **Go cyclomatic complexity** counts nested `func` literals into their
  enclosing function, as gocyclo does; a Go file that is one large
  `main()` with closures scores worse than the equivalent Java.
- **Size gate is language-blind**: the maturity component saturates at
  2,000 lines for every language, although C++ and Java are roughly
  twice as verbose per concept as Python. Calibration rounds 1–2 (all
  projects far above saturation) did not observe bias; a round on
  500–3,000-line projects would test it.
- **Documented empty catches** (`catch (e) { /* best effort */ }`) are
  reported at `note` severity, not `warning`; `--fail-on warning` does
  not fail on them.
- **Keyword-glued strings in TypeScript** (`return'x'`) are recognised for
  the JS keyword set; an apostrophe glued to any other identifier is JSX
  text. `x'y'` is not valid JS, so nothing is lost.
- **CMake link lines that expand variables** make no drift claims for
  that manifest chain; Gradle build scripts with unresolvable catalog
  accessors likewise. Both are reported (`variable_bound_links`,
  `unresolved_catalog_refs`) rather than guessed.
- **Broad-catch rethrow grading is asymmetric**: JAVA/KT/CS/C-COR-003 grade a
  handler that rethrows as `note`; PY-COR-002 predates that rule and still
  warns on `except Exception: … raise`. Aligning Python would change every
  recorded Python baseline; do it in a scoring-policy release, not a patch.
- **Dynamic-SQL rules follow the literal, not the data flow**: a query built
  with `StringBuilder.append`, `+=` accumulation, or across statements is not
  reported; a dynamic literal later bound as a parameter *is* reported,
  because the text itself is the hazard. Zero false positives were observed
  on the 11 non-SQL calibration repositories; all 19 hits were in drogon's ORM.
- **Idiom-in-tests rules** (GO-COR-003, TS-COR-005, KT-COR-005) are `note`
  under `is_test_path`; the path conventions are listed in
  `languages/_parity.py`. A test tree with an unconventional name is graded
  as production code.
