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

## Changed-line intersection

`--changed-lines-manifest` is an independent final selector. The analyzer first
compares every current finding with the baseline, applies
`--new-findings-only`, and then keeps only findings overlapping changed lines.
`--fail-on` evaluates that final intersection.

Baseline summaries remain global. `--write-baseline` always fingerprints all
current findings before changed-line selection, so combining the options cannot
silently create a partial baseline. See [`CHANGED_LINES.md`](CHANGED_LINES.md)
for the manifest and overlap contract.
