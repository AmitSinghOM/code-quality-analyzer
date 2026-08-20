# Code Quality Analyzer

A privacy-first local tool that analyzes Python packages and includes a bounded
Go pilot. It detects:

- **Actionable correctness and package findings** with normalized locations
- **Data Structures & Algorithms (DSA)** patterns in Python
- **System Design** principles implemented in Python
- A compatibility **architecture signal score from 1-10**

## Architecture Signal Score Scale

| Score | Architecture-signal breadth |
|-------|-----------------------------|
| 1-2 | Very few recognized DSA or design signals |
| 3-4 | A small set of recognized signals |
| 5-6 | Moderate signal breadth |
| 7-8 | Broad signal coverage across multiple files |
| 9-10 | Very broad recognized DSA and design signals |

Architecture signal scores from 2.x are **not comparable** to 1.x ratings. Detection got stricter
and project size no longer adds score, so most projects will score lower than
they did before. See [Scoring](#scoring).

## Project Structure

```
code-quality-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── __main__.py      # CLI entry point
│   ├── baseline.py      # Hashed finding baselines and comparison
│   ├── discovery.py     # Safe file discovery (limits, symlink guard)
│   ├── findings.py      # Language-neutral actionable finding model
│   ├── signals.py       # Per-file signal extraction + pattern matching
│   ├── python_rules.py  # Source-located Python correctness rules
│   ├── patterns.py      # DSA & System Design pattern definitions
│   ├── package_intelligence.py # Metadata, modules, imports, cycles
│   ├── protocols.py     # Source, parse, rule, provider, and reporter contracts
│   ├── registry.py      # Versioned plugin and capability negotiation registry
│   ├── plugins.py       # Built-in plugin assembly
│   ├── reporters.py     # Registered text/JSON report renderers
│   ├── languages/       # Built-in language adapters and rule packs
│   ├── scanner.py       # Language-neutral orchestration through plugins
│   ├── complexity.py    # Time/space complexity analyzer
│   └── rater.py         # Rating calculator (1-10)
├── tests/               # Regression tests
├── docs/                # Rule, baseline, and privacy guidance
├── LICENSE
├── SECURITY.md
├── CHANGELOG.md
├── MANIFEST.in
├── pyproject.toml
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

```bash
cd code-quality-analyzer
python3 -m venv .venv
.venv/bin/pip install -e .
```

That installs a `code-quality-analyzer` command. Running as a module works too:

```bash
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m analyzer /path/to/project
```

## Usage

```bash
# Analyze a project
code-quality-analyzer /path/to/project

# Show which signals triggered each match
code-quality-analyzer /path/to/project -v

# Output as JSON
code-quality-analyzer /path/to/project -f json

# Include time/space complexity analysis
code-quality-analyzer /path/to/project -c
```

`PROJECT_PATH` must be a directory. Pointing at a single file is rejected
rather than silently returning an architecture signal score of 1.

## Privacy and offline options

Use `--anonymize` when a report may leave the trusted development environment:

```bash
code-quality-analyzer /path/to/project --anonymize -f json
code-quality-analyzer /path/to/project --anonymize --offline -v -c
```

Anonymized reports replace project, file, and function identities with opaque
report-local tokens; remove package/module/dependency/script names; replace
finding messages and remediation; reduce package intelligence to aggregate
counts; and remove source-derived pattern signals and complexity reasoning.
Rule IDs, locations, counts, scores, pattern names, complexity classes, and
line numbers remain so the report is still useful.

`--offline` adds runtime enforcement by denying socket connection and
name-resolution operations while analysis runs. Normal analysis is already
local and has no network-backed integration; this option makes an accidental
future network call fail the command instead of silently connecting.

See [`docs/PRIVACY.md`](docs/PRIVACY.md) for the exact data boundary and
remaining disclosure considerations.

## Options

| Option | Default | Purpose |
|--------|---------|---------|
| `-v, --verbose` | off | Include matched files and evidence; JSON omits evidence unless enabled |
| `-f, --output-format` | `text` | `text` or versioned `json` |
| `-c, --complexity` | off | Add experimental time/space complexity estimates |
| `--max-file-size` | 2 MB | Skip files larger than this positive byte count |
| `--max-files` | 20000 | Stop after this positive number of registered source files |
| `--redact-paths` | off | Report file names only, no directory structure |
| `--anonymize` | off | Remove project paths, metadata, and source identifiers |
| `--offline` | off | Deny socket operations while analysis runs |
| `--fail-under` | none | Exit non-zero when the compatibility architecture signal score is below 1–10 |
| `--fail-on` | none | Exit 4 for reported findings at `warning` or `error` severity |
| `--baseline` | none | Compare findings with an existing hashed baseline |
| `--write-baseline` | none | Atomically write current finding fingerprints |
| `--new-findings-only` | off | Report and gate only findings absent from `--baseline` |
| `--strict` | off | Exit non-zero when any requested analysis is incomplete |

`--anonymize` is stronger than `--redact-paths` and takes precedence for report
presentation. Baseline fingerprints continue to use hidden project-relative
identities, so changing either presentation option does not change CI identity.

`-f` was `--format` in 1.x. It is now `--output-format` so it no longer shadows
the `format` builtin. JSON reports include schema, analyzer, and ruleset versions
plus explicit privacy state, scoring-policy version, and analysis authority so
consumers can identify the contract, protections, and completeness that
produced a result. `architecture_signal_score` is the primary score field;
`rating` is a transitional equal-valued 2.x compatibility alias.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Analysis completed and any threshold was met |
| 1 | Architecture signal score below `--fail-under` |
| 2 | No registered-language source candidates were discovered |
| 3 | Source candidates produced no successful analysis, or `--strict` found incomplete analysis |
| 4 | A reported finding met the `--fail-on` severity threshold |

## Analysis Authority

Every JSON report includes `analysis_health` with source-candidate, readable,
and successfully analyzed counts; a completeness ratio; stable reason codes;
and `complete`/`authoritative` booleans. Text reports show the same
qualification before the architecture signal score.

No source candidates exit with code 2. If candidates exist but none can be
successfully parsed, analysis exits with code 3 even without `--strict`.
Partial non-strict analysis may exit successfully for inspection, but it is
always marked non-authoritative. See the versioned schema in
[`docs/report-schema-1.7.0.json`](docs/report-schema-1.7.0.json) and the decision
record in
[`docs/adr/001-analysis-authority-and-score-migration.md`](docs/adr/001-analysis-authority-and-score-migration.md).

## Use in CI

Create a baseline once after reviewing existing findings:

```bash
code-quality-analyzer . --write-baseline .code-quality-baseline.json
```

Then gate only newly introduced warning-or-higher findings:

```bash
code-quality-analyzer . \
  --baseline .code-quality-baseline.json \
  --new-findings-only \
  --fail-on warning \
  --strict
```

Baseline files contain only schema metadata and SHA-256 fingerprints. They do
not contain source paths, messages, identifiers, snippets, or report evidence.
Baseline writes are atomic, malformed or oversized baselines are rejected, and
fingerprints remain stable when `--redact-paths` changes report presentation.
See [`docs/BASELINES.md`](docs/BASELINES.md) for workflow and review guidance.

`--fail-under` remains available as an architecture-signal compatibility
ratchet, but actionable finding gates are more explicit. Treat the score as
usable only when `analysis_health.authoritative` is true. `--strict` fails when
files cannot be read or parsed, discovery is truncated, package metadata is invalid, or requested complexity
analysis has a coverage gap. Incomplete analysis therefore cannot silently
pass as a green build.

See `.github/workflows/ci.yml` for a working example that also runs the test
suite, lint, and a dependency vulnerability scan.

## Paths

Absolute paths are never written into reports. The project is identified by its
directory name, and file paths—including skipped-file examples—are reported
relative to the project root. `--redact-paths` reduces file paths to bare names
for reports shared outside your machine.

Relative paths work fine as arguments (`.`, `../my-project`)—they are resolved
internally before discovery, but the resolved absolute path is not reported.

`--redact-paths` is path minimization, not full anonymization: findings,
package metadata, identifiers, and architecture signals can remain sensitive.
Review [`docs/PRIVACY.md`](docs/PRIVACY.md) before sharing reports. Security
issues should follow [`SECURITY.md`](SECURITY.md); do not attach proprietary
source to vulnerability reports.

---

## How Detection Works

Every pattern is defined by signals, all matched case-insensitively:

| Signal type | Matched against |
|-------------|-----------------|
| `identifiers` | An exact identifier from the AST: name, attribute, def, class, argument, import alias |
| `identifier_contains` | A substring of an identifier, for naming conventions like `OrderRepository` |
| `text` | A substring of the source **with comments and string literals blanked out**, for syntax like `dp[` or `@app.route` |
| `imports` | A substring of an imported module path |

Two rules keep the noise down:

**Literals and comments are not evidence.** A docstring saying "we should use
Dijkstra here" no longer reports a shortest-path algorithm. Comments and string
literals are blanked out before any text matching, with layout preserved so
positional patterns still match.

**Bare words match identifiers, not raw text.** `pop` matches `items.pop()` but
not `population`.

Each pattern declares `min_signals` — how many distinct signals a file must
provide before the pattern is reported. Specific patterns like `heappush` need
one. Generic ones need corroboration: a lone `visited` is not a graph
traversal, and `OrderedDict` on its own is not an LRU cache.

Run with `-v` to see exactly which signals fired, so a false positive is
reviewable rather than mysterious.

### Signals are per file

Imports are collected per file. In 1.x the import set accumulated across the
whole project, so a single `import heapq` anywhere made every file scanned
afterwards look like it used heaps — and because results depended on directory
walk order, renaming a file could change the rating.

## Scoring

```
rating = dsa_score × 0.4 + design_score × 0.5 + maturity_score × 0.1
```

**Breadth discount.** A pattern found in one file counts for 60% of its weight;
two files 80%; four or more, full weight. One incidental use is weaker evidence
than a habit.

**Size is not quality.** The 1.x "complexity bonus" grew with file count and
line count, so padding a codebase raised its rating. Size now only gates how
much of the `maturity_score` component is reachable, saturating at 2000 lines.
Past that, more code adds nothing.

**Coverage gaps lower the score.** If more than 10% of discovered files could
not be read or parsed, the rating is scaled down and reported as a lower bound
with an explicit warning.

## Scan Safety

File reads go through `analyzer/discovery.py`, which refuses to:

- read a path that resolves outside the project root, so a symlink pointing at
  `~/.aws/credentials` is skipped rather than parsed
- read a non-regular file such as a FIFO, which would otherwise block forever
- read a file above `--max-file-size`
- walk more than `--max-files` paths

Skips are counted by reason and reported. Nothing is silently dropped, so a
clean project is distinguishable from a project that failed to parse.

Excluded directories: `.git`, `__pycache__`, `.venv`, `venv`, `env`,
`node_modules`, `dist`, `build`, `site-packages`, and the usual tool caches.

## Actionable Findings

Actionable Python findings are separate from descriptive DSA and architecture
signals. Every finding includes a stable rule ID, category, severity,
confidence, message, remediation, and a one-based project-relative source
location. JSON reports include both `findings` and an aggregate
`finding_summary`; terminal reports show an **Actionable Findings** table.

The first rule is `PY-COR-001`, which detects mutable function defaults such as
`items=[]` and `cache=dict()`. See [`docs/RULES.md`](docs/RULES.md) for rule
behavior and remediation examples.

Files are parsed once for signal extraction, actionable Python rules, package
intelligence, and optional complexity analysis. Malformed files emit no
semantic findings and remain visible through analysis health.

## Package Intelligence

Package intelligence is passive: it does not import, build, or execute project
code. Every normal scan now reports:

- Parsed `pyproject.toml` name, Python requirement, build backend, dependencies,
  optional dependency groups, and console scripts
- Detected `src` or flat package layout and source roots
- First-party modules and their local import graph
- Circular import groups
- Console scripts that target missing local modules

Invalid TOML produces `PY-PKG-003` and makes `--strict` fail. Circular imports
produce `PY-PKG-001`; invalid console-script module targets produce
`PY-PKG-002`. Test-only directories without a package initializer are excluded
from flat-layout package modules. See [`docs/RULES.md`](docs/RULES.md).

Python 3.10 uses the pinned `tomli` compatibility parser; Python 3.11 and newer
use the standard-library `tomllib` parser.

## Complexity Analysis

Complexity output is an **experimental static estimate**, not an authoritative
Big-O guarantee. Use its assumptions, reasoning, and confidence to prioritize
manual review; do not use inferred Big-O alone as a CI quality gate.

Use the `-c` flag to include time/space complexity analysis:

```bash
code-quality-analyzer /path/to/project -c
code-quality-analyzer /path/to/project -v -c  # verbose adds reasoning
```

Handled correctly as of 2.0:

- **`async for` counts as a loop.** Async-heavy code used to report `O(1)`.
- **Early exit is scoped to its own loop.** A `break` in an inner loop no
  longer marks the outer loop as having an early exit. A `return` still does,
  from any depth.
- **Nested definitions are separate units.** An inner function's loops no
  longer inflate the enclosing function's depth, and its self-calls no longer
  count as the parent's recursion. Each nested function is analyzed on its own.
- **Recursion inside a loop** is classified as `fan_out` rather than linear.
  The branching factor is data-dependent, so it reports `O(n)` over visited
  nodes with reduced confidence instead of claiming certainty.

### Confidence Score

The confidence score indicates how reliable the complexity estimate is.

**Starting point:** 80%

| Condition | Deduction | Reason |
|-----------|-----------|--------|
| Recursion without memoization | -20% | Hard to tell O(n) from O(2^n) without runtime analysis |
| Recursive call inside a loop | -20% | Branching factor depends on the data |
| Deep nesting (>2 loops) | -10% | Complex control flow makes static analysis less reliable |
| No type hints on parameters | -10% | Can't infer if input is a collection or its size relationship |

**Minimum:** 30%

**Interpreting confidence:**
- 80%+ → High confidence, estimate is likely accurate
- 60-80% → Medium confidence, estimate is reasonable but verify manually
- 30-60% → Low confidence, treat as rough estimate only

---

## What It Detects

### DSA Patterns (24 patterns)

**Data Structures:**
- Hash maps (Counter, defaultdict)
- Sets and set algebra
- Trees (binary, general)
- Linked lists
- Queues and stacks (deque)
- Heaps and priority queues
- Trie/prefix tree
- Segment tree
- Fenwick/Binary Indexed Tree
- Bloom filter

**Algorithms:**
- Sorting
- Binary search
- Graph traversal (BFS/DFS)
- Dynamic programming/memoization
- Union-Find/Disjoint Set
- Topological sort
- Shortest path (Dijkstra/Bellman-Ford/A*)
- Minimum spanning tree (Kruskal/Prim)
- Backtracking

**Techniques:**
- Sliding window
- Two pointers
- Monotonic stack
- Interval operations
- Manual LRU cache

### System Design Patterns (14 patterns)
- API design (FastAPI, Flask, Django, Starlette)
- Database ORM
- Caching layers
- Message queues
- Factory, Singleton, Repository patterns
- Dependency injection
- Error handling
- Logging
- Authentication/Authorization
- Testing
- Microservices/service clients
- Configuration management

Python receives actionable rules, package intelligence, architecture signals,
and experimental complexity analysis. The Go pilot discovers `.go` files,
preserves import aliases, emits `GO-COR-001` for discarded errors from a
narrow set of imported standard-library calls, and passively aggregates
multi-file packages plus local module import edges from `go.mod`. It never
invokes Go tooling. Python and Go findings share the same report, baseline,
privacy, offline, and CI-gate contracts. JSON `project_analyses` entries expose
provider results normally and health-only projections under `--anonymize`.
See [`docs/RULES.md`](docs/RULES.md).

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest        # tests
.venv/bin/python -m ruff check .  # lint
.venv/bin/python -m pip_audit     # dependency vulnerabilities
```

The test suite carries a regression test for each detection and safety bug
fixed in 2.0, including symlink escape, FIFO reads, cross-file import leakage,
and the complexity analyzer's scope handling.

## License

[MIT](LICENSE)
