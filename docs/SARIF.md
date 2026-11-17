# SARIF output

Use `-f sarif` to emit deterministic SARIF 2.1.0 for actionable findings:

```bash
code-quality-analyzer . -f sarif > code-quality-results.sarif
```

The command emits exactly one SARIF run, including when no findings are
reported. Output is written before normal CI gate exit codes are returned, so a
valid artifact remains available when `--fail-on`, `--fail-under`, or `--strict`
fails the command.

## Result selection

SARIF consumes the same normalized finding set as text and JSON. Baseline and
`--new-findings-only` selection happens first, optional changed-line selection
intersects that result, and `--fail-on` evaluates the same final set:

```bash
code-quality-analyzer . \
  --baseline .code-quality-baseline.json \
  --new-findings-only \
  --changed-lines-manifest changed-lines.json \
  --fail-on warning \
  --strict \
  -f sarif > code-quality-results.sarif
```

Rule descriptors are sorted by rule ID. Results are sorted by encoded relative
artifact URI, location, rule ID, message, and remediation. Duplicate findings
are retained. Rule indexes always refer to the run's sorted descriptor catalog.
The effective finding severity determines each result level; the built-in
rule's documented default determines its descriptor default. When enabled, the
`changedLineSelection` run property contains aggregate schema/file/range/input/
selected counts only; no manifest path or raw ranges are emitted.

## Privacy boundary

SARIF never contains absolute paths, `file://` URIs, source snippets, source
text, command lines, environment variables, timestamps, fixes, finding
fingerprints, repository metadata, or network-derived data. Artifact URIs are
percent-encoded project-relative paths using `/` separators.

`--redact-paths` reduces artifact URIs to percent-encoded basenames.
`--anonymize` replaces them with report-local `file-0001` tokens and replaces
source-derived finding messages and remediation with generic guidance. Rule
IDs, severity, category, confidence, line and column ranges, analysis health,
privacy state, configuration fingerprint, and baseline-selection counts remain.
Policy sources follow the same path treatment; see
[Path-scoped rule policy](#path-scoped-rule-policy).

Path validation fails closed for empty, absolute, scheme-based, NUL-containing,
or parent-traversing artifact paths. `--offline` applies the same socket-denial
guard used by other formats; rendering itself performs no network access.

## Path-scoped rule policy

When a `[overrides."<glob>"]` table in `.code-quality.toml` sets a finding's
severity or drops a rule under a path, SARIF records it in two property bags
(see `docs/adr/005-path-scoped-rule-policy.md`, decision 4):

- `result.properties.policySource`: `project` when the effective severity came
  from the rule default or `[rules]`; `override:<glob>` naming the winning
  table when an override changed it. It sits beside `category`, `confidence`
  and `remediation` because the SARIF `result` object forbids unknown keys and
  `properties` is an open bag. Suppressed results carry it the same way.
- `run.properties.policyDropped`: `{count, by_rule, by_source, security}`,
  next to `baselineSelection`. `by_source` keys are `project` or
  `override:<glob>`; `security` counts dropped findings whose rule has a CWE.
  Policy-dropped findings are counted here and **never emitted as results**,
  so a vendored tree a user silenced does not reappear as dismissed alerts.

Both keys appear only when the analyzer produced them; a run without an
overrides table renders exactly as before.

```json
"properties": {
  "category": "maintainability",
  "confidence": "high",
  "policySource": "override:tests/**",
  "remediation": "..."
}
```

*Privacy.* The glob is author-written and path-shaped, so it is treated as a
path. Plain output emits it as written. `--redact-paths` keeps only its last
segment (`override:tests/**/*_test.py` becomes `override:*_test.py`), mirroring
artifact basenames. `--anonymize` maps it through the report's file-token map,
so a glob renders as `override:file-0001` (sharing the token of any artifact
with the same path text) in `policySource` and in every `policyDropped.by_source`
key; the raw glob appears nowhere in anonymized SARIF. `project` is a constant
and is never transformed. `count`, `by_rule` and `security` carry no paths.

## Security classification

Rules anchored to a CWE (the `*-SEC-*` family and the eight dynamic-SQL rules)
carry two extra properties on their `tool.driver.rules[]` descriptor:

```json
"properties": {
  "category": "security",
  "confidence": "medium",
  "defaultSeverity": "warning",
  "language": "python",
  "security-severity": "8.8",
  "tags": ["security", "external/cwe/cwe-78"]
}
```

`security-severity` is CVSS-like (`0.0`–`10.0`); the `security` tag and the
`external/cwe/cwe-NNN` form are what GitHub code scanning uses to classify a
result as a security alert, rank it, and link the CWE. Quality rules carry
neither property. The result `level` is unchanged (`warning`), so an existing
`--fail-on error` gate does not fail on upgrade.

## Rule help links

Every descriptor carries `helpUri` and `help.markdown` next to the existing
`help.text`. `helpUri` is the release-pinned rule reference,
`https://github.com/AmitSinghOM/code-quality-analyzer/blob/v<version>/docs/RULES.md#<anchor>`,
where `<version>` is the analyzer's `semanticVersion` and `<anchor>` is the
GitHub heading anchor documenting that rule (its own heading, or the combined
heading it shares with sibling rules). `help.markdown` is what GitHub code
scanning renders beside an alert: the rule title, what it detects, the CWE
when anchored, the remediation, every `not_when` condition, and that same
link. Both are built from `RuleMetadata` only, never from scanned source, so
`--anonymize` and `--redact-paths` leave them byte-identical;
`tests/test_rule_help.py` checks the anchors against `docs/RULES.md`.

## Contract versions

The output declares SARIF `2.1.0`. Analyzer semantic versioning identifies the
producer. Cache enablement advances the independent JSON report schema to
`1.10.0`; SARIF remains `2.1.0` and the built-in ruleset contract is unchanged.
