# Code Quality Analyzer

A Python tool that analyzes codebases to detect:
- **Data Structures & Algorithms (DSA)** patterns used
- **System Design** principles implemented
- Generates a **quality rating from 1-10**

## Rating Scale

| Rating | Description |
|--------|-------------|
| 1-2 | Poor: No meaningful DSA/design, wasteful code |
| 3-4 | Basic: Simple structures, minimal design thought |
| 5-6 | Average: Some DSA usage, basic patterns |
| 7-8 | Good: Strategic DSA, clear design patterns |
| 9-10 | Excellent: Optimal DSA, comprehensive system design |

Ratings from 2.x are **not comparable** to 1.x ratings. Detection got stricter
and project size no longer adds score, so most projects will rate lower than
they did before. See [Scoring](#scoring).

## Project Structure

```
code-quality-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── __main__.py      # CLI entry point
│   ├── discovery.py     # Safe file discovery (limits, symlink guard)
│   ├── signals.py       # Per-file signal extraction + pattern matching
│   ├── patterns.py      # DSA & System Design pattern definitions
│   ├── scanner.py       # File scanner and pattern detector
│   ├── complexity.py    # Time/space complexity analyzer
│   └── rater.py         # Rating calculator (1-10)
├── tests/               # Regression tests
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
rather than silently returning a rating of 1.

## Options

| Option | Default | Purpose |
|--------|---------|---------|
| `-v, --verbose` | off | Show matched files and the signals behind each match |
| `-f, --output-format` | `text` | `text` or `json` |
| `-c, --complexity` | off | Add time/space complexity analysis |
| `--max-file-size` | 2 MB | Skip files larger than this many bytes |
| `--max-files` | 20000 | Stop after discovering this many Python files |
| `--redact-paths` | off | Report file names only, no directory structure |
| `--fail-under` | none | Exit non-zero when the rating is below this value |
| `--strict` | off | Exit non-zero when any discovered file could not be analyzed |

`-f` was `--format` in 1.x. It is now `--output-format` so it no longer shadows
the `format` builtin.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Analysis completed and any threshold was met |
| 1 | Rating below `--fail-under` |
| 2 | No Python files were analyzed |
| 3 | `--strict` and some discovered files could not be analyzed |

## Use in CI

```bash
code-quality-analyzer . --fail-under 5 --strict
```

Set `--fail-under` just below your current rating and raise it over time. Used
as a ratchet it catches regressions; set aspirationally it just fails every
build.

`--strict` is the more valuable half of the gate: it fails when files could not
be read or parsed, so a rating that quietly covers half the project doesn't
pass as a green build.

See `.github/workflows/ci.yml` for a working example that also runs the test
suite, lint, and a dependency vulnerability scan.

## Paths

Absolute paths are never written into reports. File paths are reported relative
to the project root, and `--redact-paths` reduces them to bare file names for
reports that get shared outside your machine.

Relative paths work fine as arguments (`.`, `../my-project`) — they are
resolved before the walk starts.

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

## Complexity Analysis

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

Only Python is analyzed today. Files in other languages are not counted.

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

MIT
