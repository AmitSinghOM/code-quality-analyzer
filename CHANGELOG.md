# Changelog

All notable changes are documented in this file. Versions follow semantic versioning for the analyzer CLI and independent semantic versions for report and ruleset contracts.

## Unreleased

## 2.29.0 - 2026-09-08

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
