# Configuration reference

The analyzer reads at most one configuration file: `.code-quality.toml` in the
analyzed project root. It never searches parent directories. Configuration is
parsed as data only; no project code, commands, or plugins are executed.

```toml
[analysis]
include = ["src/**/*.py", "cmd/**/*.go"]
exclude = ["src/generated/**", "tests/fixtures/**"]
respect_gitignore = true

[rules."PY-COR-001"]
enabled = true
severity = "error"
```

## Source selection

`analysis.include` and `analysis.exclude` are arrays of project-relative POSIX
globs. The supported operators are `*` within one path segment, `**` across
segments, and `?` for one non-separator character. An empty include list selects
all registered source types. Include rules run first, then exclude rules win.
Intentional exclusions do not count as candidates, skips, or coverage gaps and
do not consume `--max-files`.

With `respect_gitignore = true` (the default), the root `.gitignore` is applied
after include/exclude policy. Blank lines and comments are ignored, `!` negates
a previous match, `/` anchors a pattern to the project root, and trailing `/`
selects a directory and its descendants. This bounded release reads only the
root `.gitignore`; nested ignore files and bracket character classes are not
supported. Set the option to `false` when exact Git ignore compatibility is
required elsewhere in a toolchain.

Built-in safety exclusions such as `.git`, virtual environments, build output,
and tool caches cannot be overridden.

## Rule policy

Each table below `rules` uses a stable rule ID. `enabled` defaults to `true`.
`severity` may be `warning` or `error`; when omitted, the rule default is used.
Policy is applied to normalized findings from all languages and project
providers before reporting, baseline comparison, and CI gates. A syntactically
valid rule ID with no loaded provider is inert, which permits shared
configuration across analyzer/plugin versions.

## Python inline suppressions

Python file rules support explicit, same-line suppressions:

```python
def legacy(cache={}):  # cqa: ignore=PY-COR-001 reason="public API compatibility"
    return cache
```

The rule ID list may be comma-separated. A nonempty quoted reason is mandatory.
The directive must be a real Python comment on the finding's reported line;
text in strings or docstrings is ignored. Missing reasons, blank reasons,
malformed directives, different rule IDs, and directives on other lines do not
suppress a finding. Invalid directives do not add a second finding. Suppression
reasons are intentionally excluded from reports and baselines to avoid leaking
source context.

## Validation and fingerprinting

Unknown keys, invalid types, invalid severities, absolute/traversing globs,
malformed TOML, unsafe symlinks, non-UTF-8 input, and configuration or ignore
files above 256 KiB fail before source scanning with a concise error.

Every JSON report includes `configuration_fingerprint`, a SHA-256 digest of the
validated effective configuration, including active root-ignore rules. TOML
comments and table/key ordering do not affect it. The digest contains no
project path, source text, suppression reason, or file content.

Severity is not part of a finding's baseline identity. Changing a severity
therefore preserves an accepted finding's fingerprint; without
`--new-findings-only`, the current severity still controls `--fail-on`.
