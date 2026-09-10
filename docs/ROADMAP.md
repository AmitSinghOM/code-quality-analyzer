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

## 3. Go rule and duplication depth (✅ decided: optional `[deep]` extra, 2.36.0)

`GO-DUP-001` structural duplication and measured-complexity rules need a
real parse tree; honest structural comparison is not achievable with
regex facts. **Decision: Option A as an opt-in extra.** The default
install stays pure Python (`click`, `rich`); `pip install
'cqa-analyzer[deep]'` adds tree-sitter and the Go, C, and C++ grammars
(compiled abi3 wheels for every supported interpreter, no network, no
toolchain execution) and unlocks:

- `GO-DUP-001` / `C-DUP-001` — cross-file duplicate functions, using the
  same significance thresholds, outermost-only rule, grouping, and
  reporting as `PY-DUP-001`, so a duplicate means the same thing in
  every language.
- `GO-MAINT-001` / `C-MAINT-001` — cyclomatic complexity per function
  (gocyclo's rule for Go; `if/for/while/do/case/?:/catch/&&/||` for C
  and C++) against the shared limit of 10.

Without the extra the providers still run and report `available:
false` with the install hint; they never affect `authoritative` and
never invent a metric. tree-sitter's error recovery is surfaced
honestly: functions whose subtree contains a parse error are excluded
from duplication (a partial tree can fabricate a match) and counted in
`functions_excluded_for_parse_errors`; complexity still runs on them.
`.h` files use the C grammar unless the blanked text shows C++ syntax —
calibration on hiredis found the C++ grammar failing 111 of 127
functions in a macro-heavy C header that the C grammar parsed with 11
localized SIMD-intrinsic errors.

Calibrated on gin (1,323 functions, 15 over limit, two duplicate groups
that are byte-identical benchmark bodies), hiredis, and jq. Cognitive
complexity (`GO-MAINT-002`/`C-MAINT-002`) mirrors `PY-MAINT-002` rule
for rule since 2.38.0. Python itself does not use tree-sitter; its `ast`
remains the source of truth.

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

## 5. Cross-language scoring fairness review (round 1 ✅ in 2.35.0)

Scoring policy 2.0.0 (ADR 002) expanded the vocabulary to 56 patterns
and rescaled the curves, closing the review's recall finding. Round 1 of
the fairness calibration (`docs/CALIBRATION.md`, reproducible with
`scripts/calibration_corpus.py`) then asked whether the score depends on
language rather than on what a project does, using the same two domains
— a Redis client and a web framework — in all seven languages.

Findings: the curve is not the constraint (full marks need a fraction
of any catalog); catalog reach was unequal (Go lacked `hash_map`, TS
lacked three IDs) and is now 56/56 everywhere, locked by
`tests/test_fairness.py`; and every non-authoritative corpus result was
a language-specific lexer bug (TS regex literals, Kotlin backtick
identifiers and Kotlin 2.2 `$$` interpolation) — the most direct form of
unfairness, since a language whose files fail lexing is scored on a
lower bound. All fixed; 14/14 corpus projects are authoritative. Within
each domain, comparably sized projects now score within ~1 point across
languages; the remaining spread tracks project scope.

Round 2 (2.36.0) added a DSA-light domain — the most used CLI tool in
each language — to test anchor *depth* directly. Verdict: depth does
not order the languages (Python, with the most anchors, sits mid-pack;
size and scope do), so no systematic bias; two per-idiom gaps were
closed (hand-rolled C hash tables, Node's built-in test runner). Still
open: a shared UI-component pattern ID remains unrepresentable. Any
weight or curve change is a `scoring_policy_version` bump with a
migration note.

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

## 8. C and C++ (✅ decided: bounded pilot, shipped in 2.34.0)

C/C++ was the first language where the regex-facts approach was in
genuine doubt, so it was gated on an explicit decision. **Decision:
path (a), a bounded "C-family lite" pilot**, with these limits stated in
the adapter docstring and README:

- **The preprocessor is not modelled.** Every `#` directive line
  (with `\`-continuations) is blanked from code text, so macro bodies
  are never evidence and macro-generated syntax is never matched.
  Conditional compilation is not evaluated: code under `#if 0` remains
  visible, which can only over-report signals, never hide a finding.
  `#include` paths are the file's imports and the strongest evidence.
- **CMake only.** `CMakeLists.txt` is the sole manifest; a curated
  header→token map drives `C-PKG-001` (medium confidence) when none of
  a library's tokens appear anywhere in the governing manifest chain.
  Conan, vcpkg, Bazel, Meson, and Makefiles are out of scope.
- **One lexical rule** (`C-COR-001` empty catch). Nothing claims to
  understand types, ownership, or lifetimes.
- **Full catalog, include-anchored.** The design catalog was expected to
  be a poor fit; in practice the production-systems specs (concurrency,
  resilience, observability, message queues, caching) map cleanly onto
  C/C++ library headers, so the full shared catalog is scored with
  `min_signals` 2 wherever identifiers alone would be weak. C/C++
  idioms without a shared ID (RAII, smart pointers, allocators) are
  simply not scored — the same stance as Go's idioms.

Calibrated on drogon (445 files, 7.9, 18 design patterns) and hiredis
(53 files, 4.1). Calibration fixed one shared-catalog precision bug
(`lfu` substring matched `...SSLFuncs`) and two C-specific weak anchors
(`interval`, bare `dp`). Path (b) — tree-sitter — remains the route to
duplication and complexity metrics for C/C++, tied to item 3.

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
