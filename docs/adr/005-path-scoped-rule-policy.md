# ADR 005: Path-scoped rule policy and baseline unmatched count

**Status:** Proposed (target 3.6.0; design only — no code ships in 3.5.0)

## Context

`.code-quality.toml` can select files (`analysis.include` / `analysis.exclude`,
`config.py:129-149`) and set a rule's `enabled` / `severity` for the whole
project (`config.py:27-31`, `:186-209`). It cannot say "PY-MAINT-003 is off
under `tests/**`" or "PY-COR-007 is an error under `db/**`"
(`docs/ROADMAP.md:447-456`, item 13). Users who want that today either disable
the rule everywhere or exclude the tree from analysis, and both hide more than
they meant to.

Two existing behaviours decide how the feature must be shaped:

- A finding whose rule is disabled is dropped with a bare `continue`
  (`scanner.py:176-178`); nothing records that it existed. A finding removed
  by an in-source `# cqa: ignore` directive, by contrast, keeps its full
  `Finding` in a per-scan ledger (`suppression_ledger.py:32-52`, opened at
  `scanner.py:97`) and is reported in `scan_health.suppressed`
  (`scanner.py:297`), `suppressed_findings` (`__main__.py:613-635`) and as a
  SARIF result carrying `suppressions[]` (`reporters.py:131-139`).
- A baseline is a set of SHA-256 fingerprints over rule id, hidden
  project-relative path, whitespace-collapsed line text and an ordinal
  (`baseline.py:86-107`); severity is not part of the identity. The comparison
  reports `known_fingerprints`, `current_findings` and `new_findings`
  (`baseline.py:44-52`, printed at `__main__.py:1136-1149`) but never how many
  baseline entries matched nothing. The file stores only schema, algorithm and
  hashes (`baseline.py:215-219`); it carries no configuration fingerprint.

The 3.5.0 planning debate (pro/con openings, one rebuttal round and the
lead's verdict of 2026-11-16, kept with the release notes outside this
repository) showed the two requests interact: a baseline entry whose
finding a path rule now hides would read, in a naive "unmatched" count, as
fixed debt. So an unmatched count (E6) means nothing until the drop is
recorded, and path policy (E8) must record its drops. Both sides of the debate
converged on shipping them together behind this note.

## Decision

### 1. Config shape, glob engine, precedence

```toml
[overrides."tests/**"]
disabled = ["PY-MAINT-003"]
severity = { "PY-COR-007" = "note" }

[overrides."db/**"]
severity = { "PY-COR-007" = "error" }
```

A top-level `overrides` table keyed by glob. Each entry may carry `disabled`
(array of rule ids) and `severity` (inline table rule id → level); any other
key is rejected the way `rules.<ID>` rejects unknown keys today
(`config.py:192`). Rule ids must match `_RULE_ID` (`config.py:19`); unknown
but well-formed ids stay inert, as for `[rules]` (`docs/CONFIGURATION.md:43-45`).
The glob is validated by `_validate_pattern` (`config.py:275-282`:
project-relative, no `..`, at most 512 characters) and matched by the same
`_glob_matches` / `_translate_glob` engine as include/exclude
(`config.py:285-334`), so `*`, `**`, `?` and `[...]` mean exactly what they
mean in `analysis.exclude`, and a pattern with no `/` matches at any depth
(`config.py:294-297`). Matching runs against the finding's hidden identity
path (`scanner.py:205-214`), never the redacted display path. The table is
bounded by `MAX_PATTERNS` entries (`config.py:17`).

Resolution is per (path, rule). Start from the rule default, apply `[rules]`,
then every override whose glob matches the path. `disabled` is monotone: a
rule disabled by any matching table stays disabled; a more specific table
cannot re-enable it (there is no `enabled` list). `severity` conflicts resolve
by specificity: the table with the longest literal prefix (the characters
before the first `*`, `?` or `[`) wins; equal prefixes → the table that appears
later in the file wins. Because order breaks ties, the overrides table is
folded into the configuration fingerprint in file order (decision 5).

*Rationale.* Path-keyed tables are how users already think about this (ruff
`per-file-ignores`, eslint `overrides` are both path → rules), and they reuse
an engine whose semantics are documented and fuzz-tested rather than adding a
second glob dialect. Monotone disable keeps the common case ("never flag X in
tests") impossible to undo by accident three tables later; longest-prefix wins
makes `src/db/**` beat `src/**` without the user counting lines.

*Rejected.* Per-rule path lists under `[rules."ID"]` (`paths_disabled = [...]`):
inverts the mental model and scatters one tree's policy across N tables.
First-match or last-match in file order for every conflict: meaning then
depends on where a line sits, which `include`/`exclude` deliberately avoids
(`docs/CONFIGURATION.md:23`). A second file (the open-code-review
`.opencodereview/rule.json` shape): the contract is one configuration file
(`docs/CONFIGURATION.md:3-5`). Rejecting ambiguous overlaps at load time:
whether two globs overlap is undecidable from the patterns alone, and
rejecting equal-prefix pairs would refuse disjoint `src/a/**` / `src/b/**`.

### 2. Allowed severity values: add `note`

`severity` in both `[rules]` and `[overrides]` accepts `note | warning | error`
(today `warning | error` only, `config.py:194-195`). `note` is already a
severity the packs emit: the test-path downgrade rewrites `warning` to `note`
(`languages/_parity.py:223-225`, `languages/_security.py:94`,
`python_security.py:186`, `languages/_shared.py:44`), and SARIF maps it to
level `note` (`reporters.py:22-27`).

*Exit-code consequence.* `--fail-on` keeps its two choices
(`__main__.py:188-189`). `_findings_reach_severity` ranks `warning` 1,
`error` 2 and anything else 0 (`__main__.py:667-670`), so a finding demoted to
`note` is still reported in `findings[]`, keeps its baseline fingerprint
(severity is not hashed, `baseline.py:86-107`; `docs/CONFIGURATION.md:84-86`),
and never produces exit 4. Promotion (`note` → `warning`/`error`) uses the same
table and does gate. Nothing changes for `--fail-under` or `--strict`.

*Rationale.* A path override's most common job is "keep showing this, stop
failing on it". Without `note` the only tool is `disabled`, which hides the
finding and inflates the policy-dropped ledger with things the user wanted to
see. The downgrade the packs apply to tests by heuristic becomes something a
user can state explicitly for any tree.

*Rejected.* Keep `warning | error`: forces `disabled` for the demotion case.
Add `--fail-on note`: contradicts the documented purpose of `note` ("stays
visible; it just carries no warning weight", `languages/_parity.py:218-220`)
and would make every test-path downgrade gate again.

### 3. `*-SEC-*` rules may be disabled by path, and it is always counted

A path override may disable a security rule. Nothing in the parser treats
security ids specially today (`config.py:188-192` checks only the id shape), so
a project-wide `[rules."GO-SEC-001"] enabled = false` is already accepted and
already unrecorded. The change is that every policy drop — security or not,
`[rules]` or `[overrides]` — lands in the ledger of decision 4, and the
report carries `scan_health.policy_dropped.security` (count of dropped
findings whose rule has a CWE, the same predicate `_rule_descriptor` uses for
the `security` tag, `reporters.py:161-166`). Under `--strict` the text report
adds one line, `Policy-disabled security findings: N`, when N > 0. The exit
code does not change: `--strict` fails on incomplete analysis
(`__main__.py:637-664`), and a fingerprinted, declared policy is a decision,
not a coverage gap. The control against tampering is
`--expect-config-fingerprint` (exit 6, `__main__.py:411-422`), which decision 5
makes sensitive to the overrides table.

*Rationale.* Vendored and generated trees are the legitimate case, and the
alternative — excluding the tree or disabling the rule project-wide — hides
strictly more. Making the count visible, always, is what turns "silently
weakened" into "declared".

*Rejected.* Forbid disabling `*-SEC-*` by path: users fall back to the
project-wide disable, which is worse and equally allowed. Fail `--strict` on
any policy-disabled security finding: punishes the declared, pinned policy and
teaches users to drop `--strict`.

### 4. Recording: a policy ledger, `policy_source` on every finding

`scanner.py:177-178` stops dropping silently. The scanner opens a
`PolicyLedger` per scan beside the `SuppressionLedger` (`scanner.py:97`) and
records each dropped `Finding` with its source, `"project"` (dropped by
`[rules]`) or `"override:<glob>"` (dropped by the winning table). Entries keep
the full `Finding`, exactly as suppressions do (`suppression_ledger.py:32-35`),
so they can be fingerprinted for decision 5. Reports carry **counts only**:
`scan_health.policy_dropped = {count, by_rule, by_source, security}`, shaped
like `scan_health.suppressed` (`suppression_ledger.py:51-52`). Neither the
score nor the exit code ever counts a dropped finding.

Every emitted finding gains `policy_source`: `"project"` when its effective
policy came from the rule default or `[rules]`, `"override:<glob>"` naming the
winning table when an override changed its severity. The value is attached
the way `fingerprint` is (`__main__.py:1356-1372`), from a per-scan side table,
so `Finding` (`findings.py:45-65`) and `PLUGIN_API_VERSION`
(`protocols.py:12`) are untouched — the same reason the suppression ledger is
a context variable rather than a signature change (`suppression_ledger.py:17-20`).

*Privacy.* The glob is author-written and path-shaped, so it is treated as a
path. Under `--redact-paths` only its last segment survives, mirroring
`display_path` (`discovery.py:328-330`): `override:tests/**/*_test.py` →
`override:*_test.py`. Under `--anonymize` the glob goes through the report's
`ReportAnonymizer.file()` map (`anonymize.py:22-25`) and is emitted as
`override:file-NNNN`; the raw glob string appears nowhere in an anonymized
report, and `by_source` keys are tokenized the same way. `"project"` is a
constant and is never transformed.

*SARIF.* `policy_source` lives in `result.properties.policySource`: the result
object forbids unknown keys (`tests/fixtures/sarif-schema-2.1.0.json:1739`)
but `properties` is an open `propertyBag` (`sarif-schema-2.1.0.json:1405`), which is where
`category`, `confidence` and `remediation` already go (`reporters.py:231-235`).
The counts live in `run.properties.policyDropped`, next to `baselineSelection`
(`reporters.py:142-151`). Policy-dropped findings are **not** emitted as SARIF
results.

*Rationale.* The ledger exists so the unmatched count can tell hidden from
fixed; the counts exist so a reviewer can tell a clean tree from a policed one;
`policy_source` exists so one finding's severity can be traced to the table
that set it. Counts rather than a list because a path policy is bulk by
design — the whole point of `disabled` under `tests/**` is not to see hundreds
of entries — whereas a directive is one line.

*Rejected.* A `policy_dropped_findings[]` list mirroring `suppressed_findings`
(`__main__.py:613-635`): bulk noise, and under `--anonymize` it would still
reveal how many findings each tokenized file hides. Emitting drops as SARIF
results with `suppressions[].kind = "external"` (the schema's other kind,
`sarif-schema-2.1.0.json:2336`): GitHub would list every vendored-tree finding as a dismissed alert,
which is the volume the user removed. Leaving `scanner.py:177` as it is and
labelling the count "unmatched (fixed, disabled or out of scope)": the label
is honest but the number is useless for pruning, which is E6's purpose.

### 5. `baseline.unmatched_count` ships with E8, one schema bump, fingerprint folds overrides

`compare_findings` (`baseline.py:144-176`) gains `suppressed` and
`policy_dropped` keyword arguments (default empty, so every existing caller is
unchanged) and `BaselineComparison.as_dict()` (`baseline.py:44-52`) gains:

```json
"baseline": {
  "unmatched_count": 3,
  "matched": {"active": 40, "suppressed": 2, "policy_dropped": 17}
}
```

`unmatched_count` is the number of baseline fingerprints matched by **no**
current finding — not active, not suppressed, not policy-dropped — i.e. the
prune candidates. `matched.policy_dropped` sits beside it so policy-hidden debt
is a separate number and can never be read as fixed. Each set is fingerprinted
with `fingerprints_for` (`baseline.py:110-141`); a policy drop applies to a
whole (rule, path), so it never splits identical-line ordinals, and severity
overrides never change identity. The text panel (`__main__.py:1136-1149`) gains
`Unmatched (prune candidates): N` and `Hidden by policy: N`; SARIF inherits the
keys through `baselineSelection` (`reporters.py:142-151` copies
`baseline_summary` wholesale). `docs/BASELINES.md` states that re-writing the
baseline is the prune: nothing removes an unmatched entry automatically.

Report schema `1.14.0 → 1.15.0`, once, for both items: `findings[].policy_source`,
`scan_health.policy_dropped`, `baseline.unmatched_count`, `baseline.matched`.
The bump is per release, as 3.4.0's `1.13.0 → 1.14.0` was (`CHANGELOG.md:120-128`),
so E8 and E6 may land as two PRs that both edit `docs/report-schema-1.15.0.json`
before 3.6.0 is cut. The schema stays additive (`docs/ROADMAP.md:430-432`).

The configuration fingerprint (`config.py:57-86`) folds the overrides table in
as an ordered list — `[{"glob", "disabled", "severity"}, ...]` in file order,
because order breaks ties (decision 1) — emitted **only when the table is
non-empty**, the same guard `keep_directories` uses (`config.py:65-71`), so
every configuration without overrides keeps its fingerprint byte-for-byte and
no pinned gate breaks. Adding, editing or reordering an override therefore
fails `--expect-config-fingerprint` with exit 6 (`__main__.py:411-422`).

The baseline file gains nothing: schema `2.0.0`, the same three keys
(`baseline.py:215-219`), no configuration fingerprint.

*Rationale.* A baseline is the set of findings a team accepted; a policy is how
the current scan views them. Binding the file to a configuration fingerprint
would force a regeneration on every unrelated config edit and would reintroduce
the "regenerate to make CI pass" habit `docs/BASELINES.md:29` warns against.
The gate already pins configuration separately, and the overrides table is now
part of what it pins.

*Rejected.* Ship E6 first with a plain count: reads policy-hidden debt as fixed
(the debate's objection). Two schema bumps: two migrations for readers of one
feature. Store the config fingerprint in the baseline file: couples two
independent contracts and changes a file format that 1.0.0 → 2.0.0 just
migrated. Auto-prune unmatched entries on `--baseline`: silently rewrites a
committed file; `--write-baseline` is the explicit, atomic path
(`baseline.py:207-240`).

## Compatibility and migration

- Configurations without `[overrides]` parse identically and keep their
  fingerprint byte-for-byte. The only loosening is that `severity = "note"` is
  now accepted where it was rejected; nothing that parsed before changes
  meaning.
- Baselines in schema `1.0.0` and `2.0.0` load unchanged; the unmatched count
  works with both because comparison already hashes per the file's own schema
  (`baseline.py:144-176`). No baseline needs regenerating.
- JSON report `1.15.0` is additive; readers of `1.14.0` ignore the new keys.
  SARIF changes are confined to property bags and validate against the vendored
  2.1.0 schema. Exit codes 0–6 are unchanged in meaning.
- The delegate `rules_for_files` groups files by their exact resolved rule set
  (`delegate.py:184-200`, `rules_for_language` at `:127`); resolution becomes
  per path and groups simply split, as `docs/ROADMAP.md:452-455` anticipated.
  MCP `scan` / `gate` return the CLI's JSON verbatim and inherit the keys.
- Sequencing: lands after the `AnalysisOptions` refactor (round 2, item R2-1)
  so the two `__main__.py` changes do not collide; E8 first, E6 second, both
  under `1.15.0`, released together as 3.6.0.

## Test plan (each test proven to fail on the pre-change code)

1. **Shape and precedence.** `[overrides."tests/**"]` parses (today:
   `ConfigError: Unknown configuration key: overrides`, `config.py:166`);
   unknown key inside an override, absolute or `..` glob, malformed rule id and
   a non-array `disabled` are each rejected before scanning. `src/**` vs
   `src/db/**` setting the same rule: `db` wins. Two tables with equal literal
   prefix: the later wins. A more specific table does not re-enable a rule a
   broader one disabled. A glob with no `/` matches at any depth.
2. **`note`.** Accepted in `[rules]` and `[overrides]`; the demoted finding is
   present in JSON and SARIF (`level: note`) with the fingerprint it had as a
   `warning`; `--fail-on warning` exits 0 on it; promotion to `error` exits 4;
   `severity = "info"` is rejected with a message naming the three values.
3. **Security drops.** A `*-SEC-*` rule disabled under a glob: absent from
   `findings[]`, counted in `scan_health.policy_dropped.by_rule` and
   `.security`; `--strict` prints the line; exit code equals the non-strict
   run's.
4. **`policy_source` and privacy.** Every finding carries it; `"project"` with
   no overrides; `override:<glob>` when matched; `--redact-paths` keeps only
   the last segment; `--anonymize` yields `override:file-NNNN` and the raw glob
   string is absent from JSON and SARIF text (the existing anonymized-output
   assertion pattern); SARIF validates against the vendored schema with
   `properties.policySource` and `run.properties.policyDropped`.
5. **Unmatched count and fingerprint.** Baseline of three findings; fix one,
   suppress one, policy-drop one → `unmatched_count == 1`, `matched ==
   {active: 0, suppressed: 1, policy_dropped: 1}`; the same with a `1.0.0`
   file. The golden `configuration_fingerprint` in
   `tests/fixtures/analysis-authority.json` is unchanged; adding an override
   changes it; `--expect-config-fingerprint <old>` exits 6. A baseline written
   while overrides are active has schema `2.0.0` and exactly three keys.
   `REPORT_SCHEMA_VERSION == "1.15.0"` and `docs/report-schema-1.15.0.json`
   declares the four new keys; `test_report_contract.py` points at it.

Discrimination is proven per the house rule: `git checkout origin/main --
<module>` in the worktree, run the new tests red, restore, run green.

## Effort

E8 (config parse + fingerprint, scanner resolution and ledger, `policy_source`
attach, delegate per-path grouping, SARIF properties): 6–8 h. E6 (comparison
arguments, `as_dict`, text panel, schema 1.15.0): 3–4 h. Docs
(`CONFIGURATION.md`, `BASELINES.md`, `PRIVACY.md`, `SARIF.md`, CHANGELOG):
~2 h. Total 11–14 h across two PRs.

## Consequences

- A finding can be hidden by configuration, but never silently: every drop is
  counted by rule and by source, every reported finding names the table that
  set its severity, and the configuration pin catches any edit to the table.
- `unmatched_count` becomes a safe prune signal because hidden debt is
  reported beside it, not inside it.
- Report schema `1.15.0`; ruleset and scoring policy unchanged; baseline schema
  unchanged; exit codes unchanged; plugin API unchanged.
- Known limits, stated rather than solved: identical-line ordinals between an
  active and a *suppressed* finding of the same rule can still diverge from the
  baseline's (a directive is per line; this is already true of `new_findings`
  today); `--redact-paths` on a glob ending in `**` leaves `override:**`,
  which is honest but uninformative; the overrides table makes table order
  part of the fingerprint, which `docs/CONFIGURATION.md:80-81` must stop
  claiming it never is.
