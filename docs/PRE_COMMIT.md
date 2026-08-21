# Pre-commit integration

The repository publishes a `code-quality-analyzer` hook for
[pre-commit](https://pre-commit.com/). Pin a released tag rather than a moving
branch:

```yaml
repos:
  - repo: https://github.com/AmitSinghOM/code-quality-analyzer
    rev: v2.25.0
    hooks:
      - id: code-quality-analyzer
```

The built-in hook runs:

```text
code-quality-analyzer . --offline
```

It sets `pass_filenames: false` because the analyzer accepts a project directory,
not individual staged paths. A matching source or root policy change triggers
one serial full-repository analysis. Python and Go files, `pyproject.toml`,
`go.mod`, `.code-quality.toml`, and `.gitignore` trigger the hook. Documentation-
only changes do not. Pre-commit does not pass deleted files as ordinary file
inputs, so a deletion-only commit may not trigger this local hook; CI remains
the full-project safety net.

## Default policy

The default hook is adoption-safe: actionable findings are displayed but do not
fail the commit. Existing integrity exits still apply when no source can be
successfully analyzed. Runtime socket and name-resolution operations are denied
by the fixed `--offline` entry.

To block error findings, override hook arguments:

```yaml
hooks:
  - id: code-quality-analyzer
    args: [--fail-on, error]
```

To block warning-or-higher findings and incomplete analysis:

```yaml
hooks:
  - id: code-quality-analyzer
    args: [--fail-on, warning, --strict]
```

Consumer arguments are appended to the fixed entry, so `.` and `--offline`
remain active.

## Baseline adoption

Projects with accepted findings can gate only regressions:

```yaml
hooks:
  - id: code-quality-analyzer
    args:
      - --baseline
      - .code-quality-baseline.json
      - --new-findings-only
      - --fail-on
      - warning
      - --strict
```

Baseline paths are resolved from the repository root. The hook writes no
baseline; update baselines through the reviewed workflow in
[`BASELINES.md`](BASELINES.md).


## Changed-line selection

The hook intentionally does not generate changed-line manifests or invoke Git.
Use the full-repository pre-commit scan locally. CI systems that already know a
comparison range can independently generate a manifest as documented in
[`CHANGED_LINES.md`](CHANGED_LINES.md).

## Privacy and installation boundary

The analyzer invocation processes source locally, sends no telemetry, and runs
with socket/DNS denial. Pre-commit itself may use the network during the first
installation to clone the pinned repository and install declared Python
dependencies. That environment is cached by pre-commit and can run without
analyzer network access afterward.

The hook does not write reports or caches. Pre-commit independently owns its
environment cache outside the analyzed repository. Review pre-commit's own
configuration and cache policy separately from the analyzer privacy contract.
