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

A finding fingerprint includes its rule ID, hidden project-relative identity path, location, and message. Report path redaction does not change this identity. Moving code or changing a finding's meaning can intentionally cause it to appear as new.

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
