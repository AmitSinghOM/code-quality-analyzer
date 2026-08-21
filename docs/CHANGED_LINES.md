# Changed-line selection

`--changed-lines-manifest` limits actionable findings and `--fail-on` gating to
findings whose source span overlaps caller-supplied changed lines. The analyzer
still scans the full project: architecture signals, analysis authority,
`--strict`, and `--fail-under` remain full-project results.

The analyzer does not invoke Git, infer a comparison branch, run a shell, or
execute project code. A CI system or local tool must generate the manifest.

## Manifest format

The input is strict UTF-8 JSON with schema version `1.0.0`:

```json
{
  "schema_version": "1.0.0",
  "files": [
    {
      "path": "src/service.py",
      "ranges": [
        {"start_line": 12, "end_line": 18},
        {"start_line": 27, "end_line": 27}
      ]
    }
  ]
}
```

Paths are project-relative POSIX identities. Empty, absolute, scheme-based,
Windows-drive, backslash-containing, NUL-containing, empty-segment, dot, and
parent-traversing paths are rejected. Paths need not exist; deleted, ignored,
or non-source files simply cannot match a current finding. Duplicate file
entries, empty range lists, unknown keys, and unsupported schema versions are
rejected.

Line numbers are inclusive positive 32-bit integers. Input ranges may be in any
order. Overlapping and adjacent ranges are merged deterministically. An empty
`files` array is valid and selects no findings.

## Finding overlap

A finding is selected when its inclusive start/end line span intersects a
changed range for the same hidden project-relative identity path. Columns are
not considered. Findings without an end line occupy only their start line.
This identity is independent of `--redact-paths` and `--anonymize`, so duplicate
basenames cannot change selection.

## Baseline ordering

Selection order is:

1. Analyze the full project and produce all current findings.
2. Write `--write-baseline` from all current findings, when requested.
3. Compare all current findings with `--baseline`.
4. Apply `--new-findings-only`, when requested.
5. Intersect that result with changed lines.
6. Render and apply `--fail-on` to the final selected findings.

A changed-line run therefore never writes a partial baseline. Baseline summary
counts remain global; changed-line summary counts describe the final
intersection.


## Report and privacy contract

Text, JSON, and SARIF add aggregate selection metadata only: manifest schema
version, canonical file/range counts, findings entering the selector, and
findings selected. The selection block never exposes the manifest path,
manifest source paths, raw ranges, content, or a manifest hash. Selected
findings otherwise follow each format's normal or anonymized path contract.
JSON uses `changed_lines`; SARIF uses the run property
`changedLineSelection`.

The manifest is bounded to 5 MB, 20,000 files, 100,000 input ranges, and 4,096
characters per path. It must be a regular file; symbolic links, directories,
malformed JSON, invalid UTF-8, and out-of-range values fail before analysis.
`--offline` applies normally and manifest processing performs no network access.

## CI usage

After an external CI step creates `changed-lines.json`:

```bash
code-quality-analyzer . \
  --baseline .code-quality-baseline.json \
  --new-findings-only \
  --changed-lines-manifest changed-lines.json \
  --fail-on warning \
  --strict \
  -f sarif > code-quality-results.sarif
```

The SARIF artifact is emitted before gate exit codes, as with an unfiltered
run. Review the aggregate selection block to distinguish no current findings
from a selector that excluded current findings.
