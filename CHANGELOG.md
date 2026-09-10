# Changelog

All notable changes are documented in this file. Versions follow semantic versioning for the analyzer CLI and independent semantic versions for report and ruleset contracts.

## Unreleased

## 2.36.0 - 2026-09-10

### Added

- **Optional `[deep]` extra** (`pip install 'cqa-analyzer[deep]'`):
  tree-sitter depth for Go and C/C++, resolving roadmap item 3. Adds
  `GO-DUP-001`/`C-DUP-001` (cross-file duplicate functions with exactly
  `PY-DUP-001`'s thresholds, nesting rule, grouping, and reporting —
  the duplication analyzer is now language-neutral) and
  `GO-MAINT-001`/`C-MAINT-001` (cyclomatic complexity over the shared
  limit of 10; gocyclo's rule for Go). The default install stays pure
  Python; without the extra the providers report `available: false`
  with the install hint and never affect `authoritative`. Functions
  containing parse errors are excluded from duplication and counted
  (`functions_excluded_for_parse_errors`); `.h` files use the C grammar
  unless the blanked text shows C++ syntax. CI gains a `deep-test` job
  on Python 3.11 and 3.14 that fails if the deep tests skip.
- Calibration round 2 (`docs/CALIBRATION.md`): the most used CLI tool
  in each of the seven languages. Anchor depth does not order the
  languages; roadmap 5's depth question is settled.

### Fixed

- C `hash_map` never fired for C code (anchors were C++ STL names);
  hand-rolled hash tables (`find_bucket`, `hash_lookup`, uthash/khash)
  now count. TypeScript `testing` recognises Node's built-in
  `node:test`/`node:assert` runner, Bun, ava, uvu, and tap.

## 2.35.0 - 2026-09-10

### Added

- `docs/CALIBRATION.md` and `scripts/calibration_corpus.py`: round 1 of
  the cross-language fairness review (roadmap 5) — the same two domains
  (Redis client, web framework) in all seven languages, with pattern
  matrices and root causes for every non-authoritative result.
- `tests/test_fairness.py` locks catalog reach (every language can fire
  every one of the 56 IDs) and the curve-ceiling invariant.
- TypeScript/JavaScript: regular-expression literals are now lexed
  (previous-significant-token rule) and blanked, closing the documented
  minified-bundle bound. Go: `hash_map` anchored on map literal shapes.
  TypeScript: `segment_tree`, `fenwick_tree`, `minimum_spanning_tree`.

### Fixed

- Kotlin lexer: backtick identifiers containing apostrophes
  (``fun `can't …`()``) opened a char literal (javalin: 15 files
  non-authoritative); Kotlin 2.2 multi-dollar interpolation `$$"""`
  treated a literal `${` as a template (ktor). Trailing-lambda calls
  (`items.sortedBy { }`) are now captured as identifiers.
- Calibration effect: javalin 6.7 → 7.1, gin 5.2 → 5.6, 14/14 corpus
  projects authoritative; no project moved down. No weight or curve
  changed (scoring policy remains 2.0.0).

## 2.34.0 - 2026-09-10

### Added

- **C/C++ pilot** (`.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`,
  `.hxx`), resolving roadmap item 8 as a bounded "C-family lite":
  preprocessor directives are blanked (macro bodies are never evidence)
  and `#include` paths become imports; lexer handles `\`-continued
  comments, encoding prefixes, C++11 raw strings, and C++14 digit
  separators; `C-COR-001` empty catch; `C-PKG-001` conservative
  third-party header drift against the governing `CMakeLists.txt`
  chain (medium confidence); full shared catalog scored with
  include-anchored specs. Seven signal-capable languages. Calibrated on
  drogon (7.9) and hiredis (4.1).

### Fixed

- Shared catalog precision: `lfu_cache` matched any identifier containing
  `lfu` — including `redisContextSSLFuncs` (found live in hiredis). The
  substring anchors are now `lfucache`/`lfu_cache`/`lfu_` with `lfu` as
  a whole identifier; applies to every language.

### Changed

- Ruleset 2.16.0 → 2.17.0 (two C rules). `architecture_signal_scope`
  lists `["c_cpp", "csharp", "go", "java", "kotlin", "python",
  "typescript"]`.

## 2.33.0 - 2026-09-10

### Added

- **Kotlin pilot** (`.kt`, `.kts`): shares the JVM ecosystem with Java,
  so it reuses the Maven/Gradle package provider (drift `KT-PKG-001`,
  invalid manifests `KT-PKG-002`) and extends the Java signal catalog
  with Kotlin idioms (`kotlinx.coroutines`, Ktor/http4k, Exposed/Room/
  Ktorm, Koin/Hilt, kotest/MockK, collection builders). Kotlin-specific
  lexer: nested block comments, `$name`/`${expr}` templates lexed as
  code holes, raw `"""` strings terminated by the last quote of a run
  (edge found live in ktor-samples), semicolon-free imports with `as`
  aliases; `KT-COR-001` empty catch. Calibrated on ktor-samples.
- Roadmap: C and C++ recorded as decision-gated (preprocessor defeats
  regex blanking; no manifest standard; design catalog mismatch) with
  the two admissible paths spelled out.

### Changed

- Ruleset 2.15.0 → 2.16.0 (three Kotlin rules). Six signal-capable
  languages; `architecture_signal_scope` lists
  `["csharp", "go", "java", "kotlin", "python", "typescript"]`.
- Java package provider rule IDs are now class attributes so JVM
  languages can share it; the shared `signal_observations` helper
  lives in `languages/_shared.py`.

## 2.32.0 - 2026-09-10

**Scoring policy 2.0.0 — catalog 2.0.** Scores are not comparable to
policy 1.0.0; see
`docs/adr/002-scoring-policy-2-production-systems-catalog.md`.

### Added

- 13 design patterns covering production-systems engineering and GoF:
  `resilience` (retries with backoff, circuit breakers, bulkheads),
  `rate_limiting`, `idempotency`, `event_sourcing_cqrs`,
  `dead_letter_outbox`, `observability` (tracing, metrics, health
  checks), `concurrency`, `pagination`, `strategy_pattern`,
  `observer_pattern`, `adapter_pattern`, `decorator_pattern`,
  `builder_pattern`.
- 5 DSA patterns: `bit_manipulation`, `prefix_sum`, `string_matching`,
  `consistent_hashing`, `lfu_cache`.
- All new patterns are recognised in Python, Go, TypeScript/JavaScript,
  Java, and C# through a shared `production_patterns.py` spec merged with
  each language's idiomatic libraries (tenacity/resilience4j/Polly/
  gobreaker/cockatiel, OpenTelemetry/Micrometer/prom-client, Axon/
  MediatR/NestJS CQRS, errgroup/`java.util.concurrent`/
  `System.Threading.Channels`, …). Pilot catalog parity is
  regression-locked.
- Python `database_orm` now recognises raw drivers: `sqlite3`,
  `psycopg`/`psycopg2`, `asyncpg`, `aiosqlite`, `pymongo`/`motor`,
  `databases`, `duckdb`, `aiomysql`/`pymysql`.

### Changed

- `SCORING_POLICY_VERSION` 1.0.0 → 2.0.0: DSA/design curve ceilings
  scaled ×1.2/×1.5 and the maturity breadth target raised 20 → 28 for
  the 56-pattern catalog (partial scaling; the new patterns are rarer
  than the originals). Re-derive `--fail-under` thresholds once.

## 2.31.1 - 2026-09-10

Precision patch from a staff-level review of the signal catalog.

### Fixed

- Go, TypeScript/JavaScript, Java, and C# `two_pointers` and `union_find`
  definitions used generic tokens (`left`, `right`, `find`, `union`,
  `parent`, `rank`) that fired on any binary-tree or DOM-shaped code.
  They now use the Python catalog's specific tokens (`left_pointer`,
  `tortoise_hare`, `find_root`, `union_by_rank`, …); a cross-language
  regression test asserts tree-shaped code fires no algorithmic pattern.
- Java `config_management` no longer counts the ubiquitous `value`
  identifier; C# `error_handling` anchors `try {` instead of the bare
  substring `try`.
- Java and C# adapters now capture typed field, local, and parameter
  names (`ILogger logger;`, `int[] findParent;`), closing a recall gap
  where declared-but-uncalled names were invisible to signals.

## 2.31.0 - 2026-09-09

### Added

- **Java pilot** (`.java`): no-toolchain adapter (comments, strings,
  char literals, and `"""` text blocks blanked; imports; bounded
  identifiers from declarations, annotations, generic uses, `new`
  targets, and calls; safe cache codec), `JAVA-COR-001` empty catch
  blocks, Java-idiom architecture signals through the shared catalog,
  and passive Maven/Gradle module intelligence: nested `pom.xml` /
  `build.gradle(.kts)` discovery, `JAVA-PKG-002` invalid manifests, and
  deliberately conservative `JAVA-PKG-001` drift limited to a curated
  set of almost-always-direct libraries (Maven/Gradle make transitive
  classes importable, so common starter-provided libraries are never
  flagged).
- **C#/.NET pilot** (`.cs`): no-toolchain adapter blanking regular,
  verbatim, interpolated (nested holes), and raw strings plus char
  literals; `using` directives (static/alias/global), declared
  namespaces, bounded identifiers; `CS-COR-001` empty catch blocks
  (including `when` filters); .NET-idiom architecture signals; and
  `.csproj` intelligence: nested project discovery, `CS-PKG-002` invalid
  project files, and `CS-PKG-001` drift matching `using` namespaces to
  `PackageReference`s by prefix in either direction while skipping
  `System.*`, shared-framework `Microsoft.*`, and self-declared
  namespaces.
- Shared `manifests.py`: bounded nested-manifest discovery and hardened
  XML parsing that rejects any document declaring a DOCTYPE or entities
  before parsing.
- Build-output directories `target`, `obj`, `.gradle`, `.mvn`, and
  `TestResults` are excluded from discovery.

### Changed

- Ruleset 2.14.0 → 2.15.0 (six new rules). The architecture signal
  score now aggregates five languages; `architecture_signal_scope`
  lists `["csharp", "go", "java", "python", "typescript"]`.

## 2.30.1 - 2026-09-09

Fixes from a staff-level review of the 2.29–2.30 changes.

### Fixed

- TypeScript/JavaScript blanker: template literals are now tracked
  through `${...}` interpolations with nesting, so a nested template's
  content can no longer leak into blanked code text and count as
  pattern evidence, and interpolations containing strings, braces, or
  further templates lex correctly. Unterminated interpolations mark the
  file incomplete.
- `requirements.txt` removed: it had drifted from `pyproject.toml`
  after the 3.11 floor. CI now audits runtime dependencies derived from
  the installed package metadata — one source of truth.
- The publish workflow now attaches the built sdist and wheel to the
  GitHub release, matching the artifacts uploaded to PyPI.
- `duplication.py` pins every added AST for the analyzer's lifetime,
  making the id()-based node grouping safe by construction rather than
  by caller convention.

### Added

- Dependabot configuration for pip and GitHub Actions (weekly).
- Roadmap: cross-language scoring fairness review (curves and maturity
  gate predate multi-language scoring).

## 2.30.0 - 2026-09-09

### Added

- `docs/MAINTENANCE.md`: the maintenance policy — what does not rot
  (pure-Python artifact, host-`ast` parsing, versioned contracts), what
  does (Python EOL, pattern relevance, pins, CI infrastructure), the
  yearly minimum cadence, and the Python version policy.

### Removed

- Python 3.10 support, ahead of its October 2026 end-of-life.
  `requires-python` is now `>=3.11`; the `tomli` conditional dependency
  is gone in favor of the standard-library `tomllib` everywhere.

## 2.29.0 - 2026-09-09

### Added

- `architecture_signal_scope` report field naming the signal-capable
  languages (currently `["python"]`) and whether the score applies to
  this analysis.
- Exit code 5: `--fail-under` on a not-applicable score exits distinctly
  instead of silently passing or failing.
- Bounded Go identifier extraction: `GoFacts.identifiers` captures
  declared func/type/var/const and short-declaration names plus selector
  call sites from blanked source, the prerequisite for Go architecture
  signals. Go adapter and cache codec 1.0.0 → 1.1.0 (old cache entries
  miss safely).
- Go architecture signals: a `go-architecture-signals` provider matches
  Go-idiom DSA and design pattern definitions (`container/heap`,
  `sort.Search`, corroborated BFS/DFS, `net/http`/gRPC API design,
  `database/sql`/GORM, message queues, `sync.Once` singletons, JWT/crypto
  auth, and more) against blanked source through the shared
  language-neutral matcher. Go pattern IDs reuse the shared scoring
  catalog, so Go and mixed projects now earn real architecture signal
  scores; Go-only projects are no longer reported as not applicable.
- TypeScript/JavaScript pilot: a bounded no-toolchain adapter for
  `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs` blanks comments, strings, and
  template literals (interpolations included), extracts bounded
  identifiers and import specifiers, emits `TS-COR-001` for empty catch
  blocks, and passively reads the root `package.json` to flag
  imported-but-undeclared dependencies (`TS-PKG-001`) and invalid
  manifests (`TS-PKG-002`). Workspace manifests skip drift analysis;
  node builtins, path aliases, and non-npm-name specifiers are never
  flagged. TS/JS architecture signals match ecosystem idioms
  (`new Map`/`new Set`, memoization, express/fastify/NestJS/tRPC API
  design, Prisma/TypeORM data access, redis/react-query caching,
  kafkajs/bullmq queues, jsonwebtoken/next-auth authentication,
  vitest/jest/playwright testing) through the shared scoring catalog,
  so TS/JS-only projects earn real scores and full-stack projects
  aggregate one score across Python, Go, and TS/JS.
  Ruleset 2.13.0 → 2.14.0.
- Nested `package.json` discovery: dependency-drift analysis covers
  manifests in subdirectories (bounded), associating each TS/JS file
  with its nearest enclosing manifest, unioning declared dependencies
  up the ancestor chain, skipping workspace or unreadable chains, and
  locating findings at each manifest's project-relative path.
  TypeScript package provider capability 1.0.0 → 1.1.0.
- Frontend build-output directories (`.next`, `.nuxt`, `.turbo`,
  `.svelte-kit`, `out`, `coverage`, `bower_components`, `.yarn`,
  `.pnpm-store`) are now excluded from discovery.

### Changed

- Projects with no successfully analyzed Python source now report the
  architecture signal score as **not applicable** (`null` in JSON,
  an explicit panel in text output) instead of a misleading 1.0 floor.
  Report schema 1.10.0 → 1.11.0 (score and `rating` are now nullable).

## 2.28.0 - 2026-09-08

### Added

- `PY-DUP-001` cross-file duplicate function implementation detection: a
  default-enabled `python-duplication` project provider compares
  docstring-stripped function bodies, parameter lists, and return annotations
  by exact AST structure. Renamed and re-decorated copies still report;
  trivial functions (fewer than three statements or forty AST nodes) and
  functions nested inside an already-reported duplicate do not. Findings
  flow through the standard severity policy, baseline, changed-line, SARIF,
  suppression, and privacy contracts. JSON reports expose aggregate group
  data under `project_analyses` (`python:duplication`).
- `--version` flag that prints the analyzer version and exits.

### Changed

- Ruleset version 2.12.0 → 2.13.0 (new rule `PY-DUP-001`).
- README restructured to lead with the privacy-first data boundary and to
  pin the published `v2.27.0` pre-commit tag.

## 2.27.0 - 2026-09-01

First public release. Earlier 2.x versions were development-only and were not
tagged or published.

### Added

- Python package intelligence and optional complexity project providers
- Bounded Go adapter and `GO-COR-001` ignored-error pilot rule
- Mixed Python/Go reports with language counts and adapter versions
- Language-neutral plugin contracts and deterministic extension registry
- Built-in Python adapter and normalized Python rule-pack plugin
- Fully anonymized text and JSON reports with opaque source-identity tokens
- Explicit offline enforcement that denies socket operations during analysis
- Privacy-state metadata in the JSON report contract
- Privacy-safe finding baselines and severity-based CI gates
- Passive Python package metadata and import-graph analysis
- Source-located actionable Python findings
- Versioned JSON report metadata
- Versioned analysis-authority schema, score-migration ADR, and golden contract fixtures
- Bounded `.code-quality.toml` source selection and per-rule policy
- Root `.gitignore`-aware inventory with deterministic negation handling
- Reason-required Python inline suppressions that never expose reason text
- Privacy-safe effective-configuration fingerprints in JSON reports
- High-confidence Python findings for broad handlers, swallowed exceptions, and unreachable statements
- Measured Python cyclomatic and cognitive complexity findings
- Python findings for long functions, excessive parameters, and boolean mode proliferation
- Conservative Python findings for blocking async calls and unmanaged local resources
- Literal `__all__` checks for missing module bindings and duplicate exports
- Bounded setuptools PEP 420 namespace discovery using shared parsed artifacts
- `PY-PKG-006` for missing literal static setuptools package-data targets
- Deterministic, privacy-bounded SARIF 2.1.0 output with a stable built-in rule catalog
- Bounded changed-line manifests with aggregate-only text, JSON, and SARIF selection metadata
- First-class serial offline pre-commit hook with advisory and gated adoption profiles
- Explicit deterministic content-hash caching for bounded Python and Go parse artifacts

### Changed

- Renamed the PyPI distribution to `cqa-analyzer` and the import package to
  `cqa_analyzer`; the `code-quality-analyzer` CLI name is unchanged.
- Analyzer version advanced to 2.27.0; report schema remains 1.10.0 and ruleset remains 2.12.0
- Scanner instances are explicitly single-use to prevent accumulated results.
- Optional complexity analysis now handles set and generator comprehensions,
  compares competing space allocations correctly, and requires stronger binary-search evidence.
- Reports now qualify authority with source-candidate, readable-file, and successful-analysis counts, completeness ratio, and stable reason codes
- `architecture_signal_score` replaces `rating` as the primary score name; `rating` remains a documented equal-valued 2.x compatibility alias
- Source candidates with zero successful analyses now exit 3 even without strict mode
- Built-in text, JSON, and SARIF reporters implement the versioned reporter contract and are selected dynamically through the plugin registry
- The CLI emits an immutable report envelope through negotiated reporters instead of directly serializing JSON
- Go imports now preserve default, explicit, blank, and dot-import semantics; `GO-COR-001` follows explicit aliases without trusting blank or dot imports
- A passive Go project provider now aggregates multi-file packages and local module import edges from shared facts and a bounded `go.mod` read
- JSON reports expose privacy-projected project-provider results and generic project-analysis health
- Optional Python complexity analysis now consumes the scanner's shared AST artifacts instead of discovering, reading, and parsing source again
- Plugins now declare a core API target; project providers and reporters are resolved through explicit versioned capability negotiation
- Python package and complexity analysis now resolve through cached project providers
- Reports now inventory registered language adapters and analyzed language counts
- Anonymized package intelligence exposes aggregate facts only
- Verbose anonymized reports replace source-derived signals and reasoning
- Reports use project-relative paths and omit semantic evidence from malformed source
- Strict mode covers truncation, package metadata, and requested complexity gaps
- Big-O output is explicitly experimental

### Security

- Project metadata, source, configuration, baseline, changed-line, and Go module
  reads use bounded descriptor-based regular-file checks with symlink rejection.
- GitHub Actions are pinned to reviewed immutable commit SHAs.
- Parse caches enforce aggregate entry and byte limits with deterministic pruning.

- Offline mode blocks connection and name-resolution socket entry points
- Baselines retain stable private identities without exposing them in reports
- Baselines store bounded SHA-256 fingerprints rather than source identifiers
- Changed-line manifests are strictly bounded and reports retain aggregate selection metadata only
- The published pre-commit hook enforces analyzer runtime `--offline` mode
- Parse cache entries use bounded typed JSON, restrictive permissions, and atomic replacement
- Skipped-file examples no longer expose absolute paths
