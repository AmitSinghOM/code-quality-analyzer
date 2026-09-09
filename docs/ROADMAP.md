# Roadmap

Forward-looking plan for language support. Every item below inherits the
non-negotiable project invariants: analysis stays local-only and
`--offline`-enforceable, never executes project code or language
toolchains, never invokes Git or a shell, stays deterministic, and keeps
reports inside the documented privacy boundary. A language feature that
cannot satisfy those invariants does not ship, regardless of value.

## Language support today

| Capability | Python | Go (pilot) |
|---|---|---|
| File discovery + safety bounds | ✅ | ✅ |
| Correctness rules | ✅ 6 rules | ✅ 1 rule (`GO-COR-001`) |
| Maintainability rules | ✅ 5 rules | ❌ |
| Duplication (`*-DUP-001`) | ✅ | ❌ |
| Package intelligence | ✅ | ✅ package/import graph |
| Architecture signals (DSA + design) | ✅ 24 + 14 patterns | ❌ |
| Complexity estimates | ✅ experimental | ❌ |
| Parse artifact | full AST | regex facts (package, imports) |

Consequence, and the trigger for this roadmap: the architecture signal
score is currently computed **from Python signals only**, so a Go-only
project floors at 1.0 no matter how well it is built.

## 1. Score integrity for non-Python projects (✅ shipped in 2.29.0)

Before Go grows signals, the score must stop misrepresenting projects
that have none to give.

- Add an explicit `architecture_signal_scope` to reports naming the
  languages that can contribute signals (currently `["python"]`).
- When zero files from signal-capable languages were successfully
  analyzed, report the score as **not applicable** in text output and
  `null` in JSON (schema minor bump), instead of a floor value of 1.0.
- `--fail-under` on a not-applicable score exits with a distinct error
  rather than silently passing or failing.

Small, self-contained, and honest; ships independently of everything
below.

## 2. Go architecture signals (✅ shipped in 2.29.0)

Goal: Go projects earn a real architecture signal score through the same
`SignalProvider` contract Python uses, with Go-idiom pattern definitions.

Prerequisites in the Go adapter — **both complete as of 2.29.0**:

- ✅ Comment and string-literal blanking for Go syntax (shipped earlier
  than this roadmap assumed: `GoFacts.code_text` has always been blanked,
  and `GO-COR-001` already matches against it).
- ✅ Bounded identifier extraction (declared func/type/var/const/short
  declarations plus selector call sites) from blanked source, shipped in
  2.29.0 as `GoFacts.identifiers`. It is regex-based and deliberately
  approximate; patterns must therefore keep the same `min_signals`
  corroboration discipline as Python.

Remaining work: none — `go_patterns.py` and the `go-architecture-signals`
provider shipped in 2.29.0. Pattern IDs reuse the shared scoring catalog
(regression-locked in tests), scores aggregate across languages, and the
acceptance criterion was met live: HUMM's Go backend moved from a 1.0
floor to 6.4 with reviewable `-v` evidence and no literal/comment false
positives on spot-check.

Pattern set (initial, subject to the same strictness bar as 2.x Python):

- **DSA:** `container/heap`, `container/list`, `sort.Search` binary
  search, map-as-set algebra, BFS/DFS traversal corroborated by
  queue/stack + visited evidence, LRU via `container/list` + map,
  `sync.Map`, tries, union-find.
- **Design:** HTTP API design (`net/http`, mux/chi/gin/echo imports),
  `database/sql`/GORM/sqlx data access, caching layers (redis clients),
  message queues (kafka/amqp/nats), worker pools and pipelines
  (goroutines + channels with corroboration), `context` propagation,
  dependency injection via constructor wiring, structured logging
  (`slog`, zap, zerolog), auth middleware, configuration management,
  testing breadth (`_test.go` presence feeds maturity, not design).

Scoring: signal weights and breadth discounts are shared with Python;
`architecture_signal_scope` from item 1 grows to `["python", "go"]`,
and mixed-language projects aggregate signals across both.

Acceptance: HUMM's Go backend (146 files, currently 1.0) scores in a
band consistent with its Python-equivalent architecture breadth, with
`-v` evidence reviewable for every fired pattern; no pattern fires on
comment or string content.

## 3. Go rule and duplication depth (decision-gated)

`GO-DUP-001` structural duplication and measured-complexity rules need a
real Go parse tree; honest structural comparison is not achievable with
regex facts. The decision point is the parser dependency:

- **Option A — tree-sitter-go:** local wheels, no network, no Go
  toolchain execution; adds a compiled dependency and a grammar-version
  cache identity. Compatible with the privacy contract; weighs against
  the currently tiny dependency footprint (`click`, `rich`).
- **Option B — stay bounded:** grow only regex-provable rules (more
  discarded-error call sites, blanked-source patterns) and accept that
  duplication/complexity remain Python-only.

No commitment until Option A's dependency weight is evaluated; item 2
does not depend on this.

## 4. TypeScript/JavaScript pilot (✅ entry shipped in 2.29.0)

The pilot entry landed with the same shape as Go's: a bounded
no-toolchain adapter for `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs` with
comment/string/template-literal blanking (interpolations conservatively
included), bounded identifier and import-specifier extraction, the
`TS-COR-001` empty-catch launch rule, and passive root `package.json`
intelligence flagging imported-but-undeclared dependencies
(`TS-PKG-001`) and invalid manifests (`TS-PKG-002`), with workspace
manifests skipping drift analysis. Generated output directories
(`.next`, `coverage`, and friends) are excluded from discovery.

Remaining for the pilot, in order:

- ✅ TS/JS architecture signals shipped in 2.29.0 through the shared
  catalog (`ts_patterns.py` + `typescript-architecture-signals`
  provider). TS/JS-only projects now earn real scores; HUMM's frontend
  moved from not-applicable to 3.8 and the full platform aggregates
  Go + TS to 6.8. A shared UI-component pattern ID remains a
  cross-language scoring-policy decision.
- Regex-literal lexing hardening in the blanker (a regex containing
  quote or comment delimiters can currently over-blank its line).
- `tsconfig.json` path-alias awareness for drift analysis.
- ✅ Nested `package.json` discovery shipped in 2.29.0: manifests are
  discovered in every non-excluded directory enclosing an analyzed
  TS/JS file (bounded at 100), each file associates with its nearest
  enclosing manifest, declared dependencies union up the ancestor chain
  (matching Node module resolution), chains containing a `workspaces`
  or unreadable manifest skip drift, and findings locate at each
  manifest's project-relative path. Verified live: a full-stack scan
  from the repository root now reports frontend dependency drift at
  `frontend/package.json`.

## 5. Cross-language scoring fairness review (partially addressed in 2.32.0)

Scoring policy 2.0.0 (ADR 002) expanded the vocabulary to 56 patterns —
resilience, rate limiting, idempotency, event sourcing/CQRS,
dead-letter/outbox, observability, concurrency, pagination, and five GoF
patterns — and rescaled the curves, closing the review's recall finding:
production-systems engineering that was invisible now scores. Still
open: per-language signal density. Go, TS/JS, Java, and C# fire subsets
of the catalog with different densities, so mixed-language projects are
scored on a curve calibrated against Python-heavy corpora. Review the
weights against a corpus of single- and mixed-language projects; any
change is a further `scoring_policy_version` bump with a migration note.
A shared UI-component pattern ID (currently unrepresentable) belongs to
this review.

## 6. Java and C#/.NET pilots (✅ entries shipped in 2.31.0)

Together with Python, Go, and TypeScript/JavaScript these cover the
languages most professional developers work in. Both follow the proven
pilot shape — no-toolchain adapter, one high-confidence launch rule,
passive package intelligence, and signal definitions mapped onto the
shared scoring catalog.

**Java** (`.java`): blanking covers comments, strings, char literals,
and `"""` text blocks; imports, bounded identifiers (declarations,
annotations, generic type uses, calls). `JAVA-COR-001` empty catch.
Package intelligence discovers `pom.xml` and `build.gradle(.kts)`
modules with the nested-manifest machinery, fails closed on XML that
declares a DOCTYPE or entities, and reports invalid manifests
(`JAVA-PKG-002`). Dependency drift (`JAVA-PKG-001`) is deliberately
conservative: Java imports name packages while manifests name
artifacts, and Maven/Gradle make transitively-provided classes
importable, so drift is checked only against a curated map of
libraries that are almost always direct dependencies.

**C#/.NET** (`.cs`): blanking covers comments, regular, verbatim
(`@""`), interpolated (`$""` with nested braces), and raw (`"""`)
strings, and char literals; `using` directives (including `static`,
alias, and `global`), bounded identifiers (declarations, attributes,
generic type uses, calls). `CS-COR-001` empty catch. Package
intelligence reads `.csproj` `PackageReference`s with the same XML
hardening (`CS-PKG-002` on invalid project files). Drift (`CS-PKG-001`)
matches `using` namespaces against declared packages by prefix in either
direction, skipping `System.*`, shared-framework `Microsoft.*`
namespaces, and namespaces the analyzed source itself declares.

Remaining for both: architecture signals landed with the entries; the
next rules per language (Java: resource leaks outside try-with-
resources; C#: `async void`, un-awaited tasks) and Gradle Kotlin-DSL
edge cases are the open items.

## 7. Kotlin pilot (✅ shipped in 2.33.0)

Kotlin shares the JVM, standard library, build tools, and frameworks with
Java, so the pilot reuses the Java package provider (Maven/Gradle
manifests, conservative drift → `KT-PKG-001`/`KT-PKG-002`) and extends
the Java signal catalog with Kotlin idioms (`kotlinx.coroutines`, Ktor,
Exposed/Room, Koin/Hilt, kotest/MockK, collection builders). Only the
lexer is Kotlin-specific: nested block comments, `$name`/`${expr}`
templates lexed as code holes, raw `"""` strings whose terminator is the
last quote of a run, semicolon-free imports with `as` aliases.
`KT-COR-001` empty catch. Calibrated on ktor-samples (204 Kotlin files,
score 7.3, API/coroutines/DI/DB/logging/testing/observability all fire).

## 8. C and C++ (decision-gated; not started)

C/C++ would be the first pilot where the regex-facts approach is in
genuine doubt, so it is gated on an explicit design decision rather
than scheduled:

- **The preprocessor defeats regex blanking.** `#include`, `#define`
  macros that rewrite syntax, conditional compilation, and token pasting
  mean blanked text may not correspond to any compiled program. No
  language so far has this property.
- **No manifest standard.** CMake, Conan, vcpkg, Bazel, Meson, and plain
  Makefiles each need their own parser; package intelligence would
  start with CMake only.
- **The design catalog is a poor fit.** C/C++ idioms — RAII, smart
  pointers, templates and concepts, lock-free structures, allocator
  strategies, ABI boundaries — have no shared catalog IDs; scoring them
  honestly is a `scoring_policy_version` change, not a pattern file.

Decision required before any work: either (a) accept a bounded
"C-family lite" pilot limited to comment/string blanking, `#include`
graph facts, a small empty-`catch` / ignored-`errno` rule set, and DSA
signals only (no design score), or (b) adopt a real parser
(tree-sitter-c/cpp — the same dependency question as Go depth, item 3)
before attempting design signals. Until decided, `.c`/`.cc`/`.cpp`/`.h`
files are not discovered.

## 9. Explicit non-goals

- Executing `go build`, `go vet`, `tsc`, `node`, or any language
  toolchain — ever.
- Network-backed rule registries or telemetry.
- New languages beyond the pilots above until an existing pilot has
  architecture signals and at least one user-validated release.

## Sequencing

1. Score integrity (item 1) — next minor after 2.28.0.
2. Go adapter blanking + identifiers, then Go signals (item 2).
3. TS/JS pilot entry (item 4) in parallel with the item 3 parser
   evaluation.
4. Go duplication/complexity (item 3) only if Option A is accepted.
