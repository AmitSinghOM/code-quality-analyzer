# Changelog

All notable changes are documented in this file. Versions follow semantic versioning for the analyzer CLI and independent semantic versions for report and ruleset contracts.

## Unreleased

## 2.44.0 - 2026-09-12

Scoring policy **2.1.0** (ADR 003). Two reviews found the 56-pattern catalog
blind to the coordination-and-safety mechanisms that lead the maintainer's own
backends (leases / `SKIP LOCKED`, expected-version writes, HMAC signing and
SSRF egress control, schedulers) and to several chapters of labuladong's
algorithm framework. Scores are not comparable with policy 2.0.0; reports
carry `scoring_policy_version`. Ruleset stays 2.24.0 (no rule changed),
schema 1.12.0.

### Added — catalog 56 → 62

- Design: `distributed_locking` (leases, fencing tokens, `SKIP LOCKED`,
  advisory locks, redlock), `optimistic_concurrency` (expected-version
  writes, version conflicts, row versions), `security_hardening`
  (SSRF/egress control, HMAC signing and verification, constant-time
  compares, replay windows), `scheduling` (cron, periodic and background
  jobs; two signals required).
- DSA: `ring_buffer` (circular buffers; `deque(maxlen=)` needs a ring
  anchor), `randomized_sampling` (weighted choice, reservoir sampling,
  Fisher-Yates, alias tables; plain `random()` is not evidence).
- Specs live once in `production_patterns.py` and are inherited by all eight
  language catalogs, so the fairness gate holds by construction; Python and
  Rust add library imports (redis.lock/redlock/etcd3, apscheduler/celery
  beat/croniter, `rand::distributions::WeightedIndex`, tokio-cron-scheduler…).
- `SHARED_ANCHOR_EXTENSIONS` / `extend_shared_anchors`: labuladong
  vocabulary added to eight existing DSA IDs — monotonic queue, difference
  array, two-heap median, ordered maps (TreeMap, SortedDict, BTreeMap, skip
  list, red-black, AVL), Floyd-Warshall/SPFA, bipartite and cycle checks,
  flood fill, sweep line / meeting rooms, Rabin-Karp / rolling hash / KMP.

### Changed

- `MATURITY_PATTERN_TARGET` 28 → 31 (half the vocabulary, as ADR 002 set
  it). Curves unchanged: the new patterns are rarer than the 2.0.0
  additions, so added weight lifts only projects that have them.

### Calibration (24 projects, full rerun)

- 17 scores moved, range −0.1 … +0.5, median +0.1; the three −0.1 moves are
  the maturity target alone. Rank order within each domain unchanged.
- Four anchors removed after tracing hits to source: HTTP constant tables
  (`IF_MATCH`, `PRECONDITION_FAILED`, `CONTENT_SECURITY_POLICY` on javalin),
  generic allow/deny lists (fzf keybindings), bare `import secrets` (wallet
  load script), atomic `CompareAndSwap` (HUMM circuit breaker).
- Maintainer repos, which motivated the design IDs: fastapi-microservices-
  platform 8.1 → 8.6, cloudscale 7.3 → 8.0, HUMM 7.4 → 7.5, wallet 6.0.

### Tests

- `tests/test_catalog_policy_2_1.py` (22): every new ID and every extension
  anchor reachable in all eight catalogs, one recognition and one refusal
  per new ID, one recognition per labuladong anchor; golden fixture and
  policy pins updated. 631 total.

## 2.43.0 - 2026-09-12

Rust is a full language. The 2.42.0 pilot was gated on `tree-sitter-rust`
on the argument that a Rust project without duplication and complexity
would be scored on fewer dimensions; that argument applies equally to Go
and C/C++, which have always shipped in the default install with
`available: false` for the deep metrics. The gate is removed and the rule
catalog is brought to parity with the other seven languages. No weight or
curve changed; scoring policy stays 2.0.0, schema 1.12.0. Ruleset 2.24.0.
68 rules.

### Changed

- Rust registers in the default install (`register_rust_plugins` in
  `plugins.py`); `RS-DUP-001`/`RS-MAINT-001/002` self-report availability
  like Go's and C/C++'s. Adapter and rule pack are 1.0.0.
- Rust import anchors match whole `::` segments (`_RustFileSignals`): the
  shared substring test let `hyper` match ripgrep's local `hyperlink`
  module and `cached` match `…::cached_…`.
- Rust catalog: universal syntax removed as evidence (`dyn`, `impl From<`,
  `new`, `from`, `default`, `as_ref`, `into_inner`, `state`, `span`,
  `counter`, `starts_with`, bare `fn union(`, `capacity`, `.chunks(`);
  `repository_pattern` needs two anchors. ripgrep 8.6 → 6.8 (16 phantom
  patterns), redis-rs 9.3 → 8.7, axum 9.0 → 8.6.

### Added

- `RS-COR-002` SQL assembled with `format!`/`write!`/`writeln!` or
  `"…".to_string() + &x`. The shared detector now steps over Rust's
  `r#`/`b`/`br#` literal prefixes and takes a per-language `concat_right`.
- `RS-COR-003` blocking call in `async fn` — `thread::sleep`, `std::fs::*`,
  `.block_on`, `TcpStream::connect`, `reqwest::blocking`. Closure bodies are
  excluded (`spawn_blocking(|| …)` is the fix); a file importing
  `tokio::fs`/`async_std::fs`/`async_fs`/`smol::fs` keeps its unqualified
  `fs::` calls.
- `RS-COR-004` crate-wide `#![allow(dead_code | unused | unused_imports |
  unused_variables | warnings | clippy::all)]` without `reason = "…"`.
- Calibration corpus: Rust rows in all three domains (redis-rs, axum,
  ripgrep); `docs/calibration-latest.json` now holds 24 rows;
  `docs/CALIBRATION.md` records the fairness alarm the first run raised and
  the two defects it exposed.
- README: Rust pilot section; language lists say eight.

### Tests

- `tests/test_rust.py` 19 (SQL, blocking-in-async with closure and
  `tokio::fs` cases, crate-wide allow, deep providers unavailable without
  the grammar); `signal_languages()` is a fixed eight-language list;
  609 total.

## 2.42.0 - 2026-09-12

Rust pilot (experimental), gated on the `[deep]` extra. Decision recorded as
roadmap item 10: without duplication and complexity a Rust project would be
scored on fewer dimensions than every other language, so the whole pilot
registers only when `tree-sitter-rust` is installed. A plain install neither
discovers `.rs` files nor mentions Rust. No weight or curve changed; scoring
policy stays 2.0.0, report schema 1.12.0. Ruleset 2.23.0.

### Added

- `languages/rust.py`: lexer (nested block comments, `r#"…"#` raw and `b"…"`
  byte strings, char literals vs lifetimes, `r#ident` raw identifiers),
  `use`/`extern crate` roots as imports, bounded identifiers, portable cache
  codec.
- `RS-COR-001` `.unwrap()` density outside test code (`#[cfg(test)]` blocks,
  `#[test]`/`#[tokio::test]`/`#[rstest]` functions, `tests/`, `benches/`,
  `examples/` excluded; `.expect("why")` not counted).
- `RS-PKG-001` undeclared crate against the nearest `Cargo.toml` chain
  (all dependency tables, `[workspace.dependencies]`, `package =` renames,
  separator-insensitive names) and `RS-PKG-002` unreadable manifest.
- `rust_patterns.py`: full 56-ID catalog anchored on std collections
  (`BinaryHeap`, `VecDeque`, `BTreeMap` …) and the crate ecosystem (tokio,
  serde, sqlx, tracing, axum …); fairness-gated like every other language.
- `RS-DUP-001`, `RS-MAINT-001`, `RS-MAINT-002` through `RUST_SPEC` in the
  deep engine; `_ =>` is the default arm, closures are their own scope.
- `pyproject` `[deep]` extra adds `tree-sitter-rust>=0.23,<0.25`;
  `deep.availability()` reports it; CI's `deep-test` job runs
  `tests/test_rust.py` and fails on unexpected skips.

### Calibration (axum, ripgrep, sqlx — 866 files, 0 lexer failures, 8,843 functions)

- `use` paths are read from *blanked* text: ripgrep embeds
  `extern crate snap;` and prose beginning "use the …" inside string
  literals, which became phantom crates before the fix.
- Crate names are compared with `-`/`_` removed: sqlx declares `md-5` and
  imports `md5::Md5`.
- `mod r#type;` (raw identifier) was lexed as a raw-string opener.
- `Vec::dedup` no longer claims the `idempotency` pattern in Rust.
- Remaining `RS-PKG-001` on sqlx (`sqlx_rt` in a `#![allow(dead_code)]`
  file) verified as a genuine dead import.

### Tests

- `tests/test_rust.py` (14; one runs only *without* the grammar);
  `signal_languages()` conftest helper for the gated adapter list; 606 total.

## 2.41.0 - 2026-09-12

Parity release. Before this, "seven languages" meant Python's 18 rules plus
one empty-catch rule in each other language. A Stack Overflow review of the
most-voted questions per language tag (2025 survey: JavaScript 66 %, SQL
58.6 %, Python 57.9 %, …) showed the same defect classes Python already
covers are the top concerns elsewhere; this release adds 20 rules (39 → 59)
so every language has correctness rules anchored to its own idioms. No
weight or curve changed; scoring policy stays 2.0.0, report schema 1.12.0.
Ruleset 2.22.0. All 12 probed calibration scores are unchanged to the
decimal — findings are reported, never scored.

### Added — dynamic SQL, every language

- `PY-COR-007`, `GO-COR-002`, `TS-COR-002`, `JAVA-COR-002`, `KT-COR-002`,
  `CS-COR-002`, `C-COR-002`: a SQL statement assembled with interpolation,
  `+` concatenation or a formatting call. One classifier
  (`cqa_analyzer/sql_text.py`) decides "is this SQL" for all seven languages
  — statement and clause keywords must share case, so prose such as
  `"Select an item from the list"` is rejected. Python uses the AST; the
  regex languages read literals through the blanked text via
  `languages/_sql.py`, which honours multi-line literals, triple-quoted
  text blocks and C#'s `$`/`@` prefixes. Driver parameters, literal-only
  concatenation and numeric constants never fire. Precision on the
  calibration corpus: 0 findings across 11 non-SQL repositories; 19 in
  drogon's ORM, all genuine.

### Added — parity with the Python catalog

- `JAVA-COR-003`, `KT-COR-003`, `CS-COR-003`, `C-COR-003`: broad exception
  handler (PY-COR-002's counterpart). Java/Kotlin: `Exception`, `Throwable`,
  `RuntimeException`, `Error`, including multi-catch; C#: `Exception`,
  `System.Exception`, bare `catch` (exception filters exempt); C++:
  `catch (...)`. A handler that rethrows is a `note`.
- `CS-COR-004`, `KT-COR-004`, `TS-COR-003`: blocking call in an
  asynchronous body (PY-COR-005's counterpart) — `.Result`/`.Wait()`/
  `GetAwaiter().GetResult()` in `async`; `runBlocking`/`Thread.sleep` in
  `suspend fun` (expression bodies included); `*Sync` I/O in `async`
  functions. Nested lambdas are not attributed to the enclosing declaration.
- `TS-COR-004`: `@ts-ignore` / `@ts-expect-error` / `@ts-nocheck` without a
  reason.
- `TS-COR-005`, `KT-COR-005`: non-null assertion density (`!` / `!!`), one
  finding per file above four; `note` in test paths.
- `GO-COR-003`: unchecked single-value type assertion (`note` in
  `_test.go`); `GO-COR-004`: `defer` directly inside a loop.
- `C-COR-004`: file-scope `using namespace` in a header.

### Changed

- Rule-pack `ruleset_version`: python 2.14.0, go 2.6.0, java/kotlin/csharp/
  typescript/c_cpp 1.1.0.
- New shared helpers `languages/_parity.py` (`block_end`,
  `strip_nested_blocks`, `broad_catch_findings`,
  `blocking_in_async_findings`, `non_null_density_findings`,
  `is_test_path`, `downgrade_in_tests`).

### Calibration notes (precision fixes made before release)

- C# `.Result` requires a call-shaped or `*task*` receiver: StackExchange.Redis
  exposed `msg.Result` as a plain struct property (56 → 26 findings; the
  remainder are guarded-but-real `task.Result` reads).
- Unchecked Go assertions and `!`/`!!` density are graded `note` in test
  files: 167 of go-redis's 209 assertions and most of ktor's and nest's
  density were in tests.

### Tests

- `tests/test_sql_rules.py` (32) and `tests/test_parity_rules.py` (18);
  existing empty-catch fixtures that catch `Exception` are scoped to
  `*-COR-001` because the broad-catch rules now also fire on them, exactly
  as PY-COR-002 and PY-COR-003 both fire on `except Exception: pass`.

## 2.40.0 - 2026-09-10

Actionability release, found by dogfooding on a 391-file Python service
where one file failed to parse: the report said `parse_failures` but never
said *which* file. No rule, weight or curve changed; scoring policy stays
2.0.0, ruleset 2.21.0, report schema 1.12.0 (`scan_health` is an open
object, so the new field is additive).

### Added

- `scan_health.unparsed_examples`: up to five project-relative paths of files
  that were read but could not be parsed (`unparsed_files` remains the exact
  count). Paths honour `--redact-paths` and are tokenized under
  `--anonymize`, exactly like `skipped_examples`.
- `-v` lists the same paths under the "could not be parsed" warning and adds
  an "... and N more (see unparsed_files in the JSON report)" line when the
  bound is hit.

### Tests

- Scanner: examples are named, bounded (`UNPARSED_EXAMPLE_LIMIT`),
  deterministic, and redaction-aware. CLI: JSON and verbose text name the
  file, the overflow line appears only when needed, and the anonymized
  report never leaks the file name.

## 2.39.0 - 2026-09-10

Second staff-review release. Every finding from the round-2 review of
2.38.1 is addressed. No weight or curve changed; scoring policy stays
2.0.0.

### Security

- **CI gates can be pinned outside the tree being gated.** New
  `--config PATH` (use this file, ignore the repository's own
  `.code-quality.toml`), `--no-project-config` (defaults only), and
  `--expect-config-fingerprint SHA256` (exit **6** before analysis if the
  effective configuration differs). Previously a pull request could
  disable a rule or exclude a path and pass `--fail-on`.
- **Text reporter no longer crashes on markup in paths or names.** A file
  named `arr[/i].py` raised Rich's `MarkupError`; source-derived text is
  now escaped and C0 control characters stripped.
- **Total read budget** (512 MB, `truncated_reasons: ["byte_budget"]`)
  bounds memory against trees that would otherwise OOM the scanner.
- **`[deep]` tree cache is bounded** (2,000 files; larger languages
  re-parse) and cleared by the scanner when its providers finish.
- **gitignore character-class fuzzing** found that a body like `[s-:]`
  made `re.compile` raise; class bodies are now rendered safely.

### Fixed — regressions from 2.37.0

- TypeScript: `return'x'`, `case'a':`, `typeof'a'` (keyword-glued
  strings, common in minified code) are strings again; the JSX-apostrophe
  rule applies only to non-keyword identifiers.
- `[deep]` cyclomatic complexity no longer enters nested function
  literals or lambdas — the same scope as `PY-MAINT-001` and as cognitive
  complexity. (Deliberate deviation from gocyclo; parity wins.)
- `architecture_signal_scope.by_language` lists every scanned language,
  including ones with files but no signals.
- Skip-list pruning is accounted for (`pruned_directories`,
  `pruned_examples`), and `[analysis] keep_directories` opts first-party
  `external/`-style directories back in.

### Fixed — language logic

- Python: a commented `except: pass` is a documented swallow and reports
  `PY-COR-003` at `note`, matching the other five languages.
- Gradle: version-catalog aliases written as TOML dotted keys
  (`groovy.core = …`) flatten to `groovy-core`.
- CMake: `target_link_libraries(x ${VAR})` marks the manifest chain as
  unknowable (`variable_bound_links`) and suppresses `C-PKG-001`.
- gitignore: `[abc]`, `[a-z]`, `[!x]` character classes match like git.

### Added

- Release gate: the newest dated CHANGELOG heading must equal
  `__version__`.
- Fuzzing of the manifest parsers (Gradle regexes, catalog flattening,
  CMake tokenizer, glob translator).

### Changed

- Ruleset 2.20.0 → 2.21.0 (severity semantics of `PY-COR-003`; scope of
  `GO-MAINT-001`/`C-MAINT-001`).

## 2.38.1 - 2026-09-10

### Fixed

- README **Upgrade** section: the pinned-version example had gone stale
  one release after it was written. `docs/RELEASING.md` step 2 now names
  the bump, and `tests/test_release_metadata.py` fails when any README
  `cqa-analyzer==X.Y.Z` pin differs from `__version__` (lines marked
  "last release", such as the final Python 3.10 pin, are exempt).

No analyzer, rule, or scoring change.

## 2.38.0 - 2026-09-10

### Added

- **Cognitive complexity for Go and C/C++** (`GO-MAINT-002`,
  `C-MAINT-002`, `[deep]` extra), computed by exactly `PY-MAINT-002`'s
  rules on tree-sitter nodes: branches add `1 + nesting` with bodies one
  level deeper (so `else if` costs one more), switches add once with
  cases deeper, a same-operator boolean chain counts once, function
  literals and lambdas are not entered. Shared limit 15. The complexity
  payload gains `average_cognitive`, `over_cognitive_limit`,
  `cognitive_limit`, and per-function `cognitive`.
- README **Upgrade** section: pipx and pip upgrade commands, pinning a
  version, and what happens to caches and baselines across releases.

### Changed

- Ruleset 2.19.0 → 2.20.0 (two rules).

### Fixed

- The remaining quadratic term in C/Java/C# identifier extraction: even
  with possessive quantifiers, `finditer` retried the qualified-chain
  regexes from every word boundary inside `a::a::a::…`, each attempt
  re-consuming the rest of the chain (3–4 s on CI runners for a 45 KB
  line). Chain regexes now attempt only at a chain start; the
  pathological case takes 0.02 s, and the fuzz test asserts linear
  scaling (doubling input must not quadruple time) instead of wall-clock.

## 2.37.0 - 2026-09-10

Staff-level review release: every finding from the 2.36.0 review
(security, per-language lexer correctness, rule logic, scoring, CI) is
addressed here. No weight or curve changed; scoring policy stays 2.0.0.

### Fixed — lexers (each was making files silently non-authoritative)

- **TypeScript/TSX**: JSX text containing an apostrophe (`<p>Don't have
  an account?</p>`) opened a string and marked the file incomplete —
  the highest-impact bug in the review, affecting most React apps with
  English copy. An apostrophe glued to an identifier character is now
  code. Keyword-preceded regex literals after whitespace (`b in /re/`)
  are recognised (`last_word` no longer concatenates across spaces).
- **C/C++**: `case'a':` and C++17 `u8'a'` were read as C++14 digit
  separators because `e`/`8` and `a` are hex digits; a separator must
  now belong to a token that starts with a decimal digit.
- **ReDoS (found by the new fuzz suite)**: identifier extraction took
  42 s on 200 KB of adversarial C, and 4–5 s on a 45 KB dotted chain in
  Java and C#. All affected regexes use possessive quantifiers (Python
  3.11+); worst case is now 0.08 s / 0.3 s.

### Fixed — rules and manifests

- **Gradle version catalogs** (`implementation(libs.guava)`) and
  `platform()`/`enforcedPlatform()` BOMs now declare dependencies for
  `JAVA-PKG-001`/`KT-PKG-001`; catalogs are resolved from
  `gradle/*.versions.toml` (libraries and bundles). Unresolvable
  accessors suppress drift claims for that chain (`unresolved_catalog_refs`).
- **`C-PKG-001`** matched CMake tokens as substrings of the whole file:
  `"z"` made zlib undetectable, and a URL in a comment "declared" curl.
  Tokens are now whole words of ≥ 3 characters with comments removed.
- **Documented empty catches** (`catch (e) { /* best effort */ }`) are
  reported at `note` severity across all five regex languages, via one
  shared `empty_catch_finding` helper.
- Go `hash_map` dropped the generic `lookup`/`index` identifiers; text
  anchors respect word boundaries at their edges (`"lo, hi"` no longer
  matches `hello, hi`; `">> 1"` no longer matches `>> 10`).

### Fixed — `[deep]` extra

- A grammar/runtime **ABI mismatch** in `tree_sitter.Language()` crashed
  the scan; it now degrades to `available: false` with the reason.
- Generated Go/C# files (`// Code generated … DO NOT EDIT.`, `*.pb.go`,
  `*_generated.go`, `*.g.cs`, …) are skipped and counted; function names
  behind pointer/parenthesized declarators resolve; structure keys are
  SHA-256 digests instead of serialized bodies; each file is parsed once
  and shared by the duplication and complexity providers.

### Added

- `tests/test_lexer_fuzz.py`: seeded adversarial soup for all six lexers
  (length/newline preservation, blank-only-to-space, termination) plus
  linearity checks for identifier extraction.
- `architecture_signal_scope.by_language` (schema 1.12.0): per-language
  file counts and pattern lists for polyglot repositories; score unchanged.
- Discovery skips `vendor/`, `third_party/`, `external/`, `Pods/`,
  `.terraform/`, Bazel output directories, and CMake build directories.
- `docs/MAINTENANCE.md`: style-gate decision and documented analysis bounds.

### CI

- `deep-test` step runs with `pipefail`; pip is pinned like every other
  tool. README states what the PyPI attestation does and does not cover.

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
