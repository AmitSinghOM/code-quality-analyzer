# ADR 004: Positioning and longevity structure for the model era

**Status:** Accepted (2.45.0)

## Context

The analyzer is one year old: eight languages, 68 rules, a 62-pattern
architecture catalog, 647 tests, versioned report-schema / ruleset /
scoring-policy / plugin-API contracts, and a 24-project calibration corpus.
The question this ADR answers is whether any of it remains useful over a
seven-year horizon in which language models — and possibly something
general-purpose beyond them — read and judge code better than any heuristic.

The answer depends on separating two things the package currently sells as
one.

**Judgment** — "is this codebase well engineered?", "does this class
implement a circuit breaker?", "is this SQL dangerous *in context*?" — is
what models do. The architecture signal score and the pattern catalog
approximate judgment with identifier and import heuristics. A model reads
the code and answers better today; under stronger models the score has no
independent value *as a grade*.

**Verification** — "does this diff introduce a finding at or above
`warning` under ruleset 2.24.0 with configuration fingerprint X?" — is what
models cannot do and will not be able to do, for reasons that are not
about intelligence:

- *Cost.* A gate runs on every push of every repository. Inference per run
  is orders of magnitude more expensive than a 200 ms deterministic scan.
- *Reproducibility.* A gate must return the same answer for the same input,
  be versioned, and be explainable in an audit. Model output is neither
  reproducible nor versionable.
- *Volume.* Models write far more code than humans did. Every line needs
  cheap, offline verification before a human or a model spends attention
  on it. Verification scales with generated code; judgment scales with
  attention, which is fixed.
- *Egress.* Regulated and air-gapped environments will run local models
  eventually, but a zero-network tool with `safe_io`, `offline.py` and an
  anonymizer remains the lowest-trust-requirement option, independent of
  model capability.

Compilers, type checkers and linters did not disappear when senior
engineers became abundant; ruff and mypy are growing fastest in the model
era because coding agents call them in a loop. The analyzer already ships
an Agent Skill that wraps it as a changed-line gate; that is the shape of
its future user.

What actually ends a package over seven years is not model progress:

1. **Dependency rot.** `pyproject.toml` pinned `click==8.5.0` and
   `rich==15.0.0` exactly. For a tool installed into a project's own
   environment, exact pins guarantee resolver conflicts within a year or
   two. The `[deep]` extra needed three tree-sitter ABI adjustments in
   twelve months.
2. **Interpreter churn.** Roughly seven Python minor releases over the
   horizon; nothing tested pre-release interpreters.
3. **Bus factor of one**, with no scheduled work that runs when nobody is
   committing.
4. **No users.** Without external installs there are no bug reports and
   decay is silent. Seven-year survival is a distribution problem before it
   is a technical one.
5. **Breadth creep.** Eight languages in a year; each is a permanent
   liability (grammar ABIs, idioms, calibration rows).

## Decision

1. **Position the package as the deterministic, zero-egress verification
   layer for model-written code.** The primary user is an agent. Gates,
   baselines, changed-line manifests, configuration fingerprints, SARIF and
   the versioned contracts lead; the architecture score is retained as a
   *reproducible inventory* of which patterns exist where — structured
   evidence an agent can consume instead of re-reading a repository — and
   is no longer grown or marketed as a grade.
2. **Agent-native interface, stdlib only.** `cqa_analyzer/mcp_server.py`
   (`cqa-mcp`) serves `scan`, `gate`, `explain_rule` and `list_rules` over
   the MCP stdio transport. It is a *transport, not a second analysis
   path*: `scan` and `gate` run the CLI in a subprocess with
   `--output-format json --offline` and return the report verbatim, so an
   agent sees byte-for-byte what CI sees. No SDK dependency: the protocol
   surface is small enough to implement directly and cannot rot with a
   third-party release.
3. **Compatible ranges, not exact pins**, for runtime dependencies
   (`click>=8.3.3,<9`, `rich>=13,<16`). Development and CI stay pinned for
   reproducible releases.
4. **Canary workflow** (`.github/workflows/canary.yml`), monthly: newest
   compatible runtime dependencies on the floor and ceiling interpreters,
   newest tree-sitter grammars with the `[deep]` bounds deliberately
   ignored, and the next Python pre-release. Failure opens or refreshes a
   single tracking issue. This is how a bus-factor-one project learns about
   ecosystem drift before a user does.
5. **Stdlib core is a 3.0 change, not a 2.x change.** `__main__.py` is
   1,180 lines with 20 click options driven by 56 `CliRunner` test files.
   Replacing click and rich with `argparse` and plain text is the right end
   state (a pure-stdlib core has nothing left to rot) but is a major
   version with a deprecation path, not a line item in a feature release.
6. **Compatibility promise**, written into `docs/ROADMAP.md`: the report
   schema is additive-only within a major; readers keep every archived
   schema; rule IDs and CLI flags carry a twelve-month deprecation window;
   the golden authority contract test loads every historical schema.
7. **Breadth freeze.** No ninth language and no new pattern ID without
   corpus evidence of a false negative. Depth — fewer false positives,
   machine-readable remediation — over breadth.

## Alternatives considered (the repositioning debate)

*Keep selling the score; it is what recruiters and README readers respond
to.* The score is the most legible artefact and the calibration work behind
it is real engineering. But a headline that a model makes obsolete is a
headline with a shelf life, and everything the package does *well* — the
contracts, the gates, the privacy posture — is precisely what ages
gracefully. The résumé claims are unchanged by this ADR; the product pitch
leads with gates.

*Remove the score entirely.* Rejected. It is deterministic, cheap, and as
an inventory it gives an agent a structured map of a repository in one
call. Removal would break the report schema and ADR 001's migration
promise for no gain. Freeze, do not delete.

*Add a model at runtime ("hybrid" analysis).* Rejected outright. A runtime
model dependency destroys every property this ADR identifies as durable:
determinism, cost, offline operation, auditability. Models are welcome as
*contributors* — reviewing anchors, drafting rules, mapping vocabularies,
as the labuladong review did — never as a dependency of a scan.

*Use the official MCP SDK.* Rejected for the same reason exact pins were
removed: it is one more thing that can break the install. The four methods
the analyzer needs fit in 400 lines of stdlib.

*Rewrite the CLI on argparse now.* Rejected for 2.45.0 as a big-bang
change bundled with a new interface; scheduled as 3.0.

## Consequences

- 2.45.0 ships the MCP server, the dependency ranges and the canary with
  no change to any analysis output; ruleset, schema and scoring policy are
  unchanged.
- The README leads with the gate and the agent workflow; the score section
  moves below them and describes the score as an inventory.
- A `canary` label exists in the repository; the first scheduled run is the
  1st of the following month.
- Measured survival metrics from here on are external CI installs, PyPI
  downloads and issues — not rule or language counts.
