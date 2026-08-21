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

Path validation fails closed for empty, absolute, scheme-based, NUL-containing,
or parent-traversing artifact paths. `--offline` applies the same socket-denial
guard used by other formats; rendering itself performs no network access.

## Contract versions

The output declares SARIF `2.1.0`. Analyzer semantic versioning identifies the
producer. Cache enablement advances the independent JSON report schema to
`1.10.0`; SARIF remains `2.1.0` and the built-in ruleset contract is unchanged.
