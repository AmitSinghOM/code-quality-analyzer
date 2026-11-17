# Finding baselines

Baselines let a project adopt actionable findings without accepting new debt while existing findings are addressed.

## Create a baseline

Review the current findings, then write their fingerprints:

```bash
code-quality-analyzer . --write-baseline .code-quality-baseline.json
```

Commit the baseline if it is part of the project's CI policy. The file contains only a schema version, fingerprint algorithm, and SHA-256 hashes. It does not contain source paths, messages, identifiers, snippets, or evidence.

## Gate new findings

```bash
code-quality-analyzer . \
  --baseline .code-quality-baseline.json \
  --new-findings-only \
  --fail-on warning \
  --strict
```

`--fail-on error` blocks only error findings. `--fail-on warning` blocks warning and error findings. Exit code 4 identifies a finding-policy failure.

## Update safely

Do not regenerate a baseline merely to make CI pass. Review resolved, moved, and newly accepted findings before updating it. Baseline writes use an atomic replacement so an interrupted write does not leave a partial file.

Schema 2.0.0 hashes the rule ID, hidden project-relative path, whitespace-collapsed
text of the reported line, and an ordinal among identical occurrences. Line
shifts and message wording do not change that identity. Findings without line
context fall back to line/column identity. Legacy schema 1.0.0 still compares
using location and message. Redaction and anonymization do not change identity.

This is not semantic matching or universal formatter stability: punctuation
spacing, multiline wrapping, changed reported text, and file renames can create
new fingerprints. Identical occurrences are distinguished by count/order, not
surrounding function identity; replacing an occurrence elsewhere with identical
text may remain known. Review that trade-off rather than refreshing baselines
automatically. Test both harmless-edit noise and newly introduced defects.

## Safety limits

- Baselines larger than 5 MB are rejected.
- More than 100,000 fingerprints are rejected.
- Unknown schema versions are rejected.
- Fingerprints must be lowercase SHA-256 hexadecimal strings.
- `--new-findings-only` requires an existing `--baseline`.

## Unmatched entries (prune candidates)

A baseline grows stale as findings are fixed. The `baseline` block of the JSON
report (and `run.properties.baselineSelection` in SARIF) says where every
stored fingerprint went:

```json
"baseline": {
  "known_fingerprints": 45,
  "current_findings": 41,
  "new_findings": 1,
  "unmatched_count": 3,
  "matched": {"active": 40, "suppressed": 2, "policy_dropped": 0}
}
```

- `baseline.unmatched_count` -- baseline fingerprints matched by **no** current
  finding: not an active one, not one hidden by an in-source `# cqa: ignore`
  directive, and not one dropped by project or path rule policy. These are the
  prune candidates: the findings were fixed, or their text or file changed.
- `baseline.matched.active` -- entries matched by a reported finding.
- `baseline.matched.suppressed` -- entries whose finding is still in the code
  but hidden by a directive.
- `baseline.matched.policy_dropped` -- entries whose finding is still in the
  code but hidden by configuration (a disabled rule or a path override).

Hidden debt is reported beside the unmatched count, never inside it: a
finding you silenced is not a finding you fixed, and a rule you disabled
yesterday must not make the baseline look cleaner today. Each set is
fingerprinted on its own with the baseline file's own schema, so a policy that
drops a whole (rule, path) keeps the ordinals those findings had when active,
and a severity change never alters identity.

Re-writing the baseline with `--write-baseline` **is** the prune: it stores the
fingerprints of the current active findings and nothing else. No entry is ever
removed automatically. Review the unmatched count the way you review new
findings -- a sudden jump usually means a rename or a reformat, not a fix.

The baseline file format is unchanged: schema `2.0.0`, the same three keys
(`schema_version`, `fingerprint_algorithm`, `fingerprints`) and no
configuration fingerprint. Files written as schema `1.0.0` keep working, and
their unmatched count is computed with the `1.0.0` hashing.

## Changed-line intersection

`--changed-lines-manifest` is an independent final selector. The analyzer first
compares every current finding with the baseline, applies
`--new-findings-only`, and then keeps only findings overlapping changed lines.
`--fail-on` evaluates that final intersection.

Baseline summaries remain global. `--write-baseline` always fingerprints all
current findings before changed-line selection, so combining the options cannot
silently create a partial baseline. See [`CHANGED_LINES.md`](CHANGED_LINES.md)
for the manifest and overlap contract.
