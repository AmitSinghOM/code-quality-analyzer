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

## 1. Score integrity for non-Python projects (next minor)

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

## 2. Go architecture signals

Goal: Go projects earn a real architecture signal score through the same
`SignalProvider` contract Python uses, with Go-idiom pattern definitions.

Prerequisites in the Go adapter (today it extracts only package name and
imports by regex):

- Comment and string-literal blanking for Go syntax, mirroring the
  Python guarantee that literals and comments are not evidence.
- Bounded identifier extraction (declared names, called selectors) from
  blanked source. This stays regex-based and deliberately approximate;
  patterns must therefore keep the same `min_signals` corroboration
  discipline as Python.

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

## 4. TypeScript/JavaScript pilot (next language)

Motivated by full-stack projects whose frontends are currently
invisible to analysis. Same shape as the Go pilot's entry:

- `.ts`/`.tsx`/`.js` discovery with the standard safety bounds
  (`node_modules` already excluded).
- Regex-facts adapter: module imports/exports, declared identifiers
  from blanked source.
- One narrow launch rule mirroring `GO-COR-001` in spirit (for example,
  discarded promise results from a small allowlist of known-async
  standard APIs), plus package intelligence from `package.json`
  (declared vs. imported dependency drift).
- Architecture signals follow only after the same blanking and
  corroboration bar as Go (item 2), never before.

## 5. Explicit non-goals

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
