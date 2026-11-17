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

[overrides."tests/**"]
disabled = ["PY-MAINT-003"]
severity = { "PY-COR-007" = "note" }
```

## Source selection

`analysis.include` and `analysis.exclude` are arrays of project-relative POSIX
globs. The supported operators are `*` within one path segment, `**` across
segments, `?` for one non-separator character, and `[...]` character classes
(`[abc]`, `[a-z]`, `[!x]`). An empty include list selects
all registered source types. Include rules run first, then exclude rules win.
Intentional exclusions do not count as candidates, skips, or coverage gaps and
do not consume `--max-files`.

With `respect_gitignore = true` (the default), the root `.gitignore` is applied
after include/exclude policy. Blank lines and comments are ignored, `!` negates
a previous match, `/` anchors a pattern to the project root, and trailing `/`
selects a directory and its descendants. This bounded release reads only the
root `.gitignore`; nested ignore files are not supported. Set the option to
`false` when exact Git ignore compatibility is required elsewhere in a
toolchain.

Built-in safety exclusions such as `.git`, virtual environments, build output,
and tool caches cannot be overridden.

## Rule policy

Each table below `rules` uses a stable rule ID. `enabled` defaults to `true`.
`severity` may be `note`, `warning` or `error`; when omitted, the rule default
is used. A finding demoted to `note` stays visible in every report, carries no
`--fail-on` weight (neither `--fail-on warning` nor `--fail-on error` exits 4
on it), and keeps its baseline fingerprint, because severity is not part of a
finding's identity. Promoting a rule to `warning` or `error` gates as usual.
Policy is applied to normalized findings from all languages and project
providers before reporting, baseline comparison, and CI gates. A syntactically
valid rule ID with no loaded provider is inert, which permits shared
configuration across analyzer/plugin versions.

## Path-scoped overrides

`[rules]` applies to the whole project. An `overrides` table scopes the same
two knobs to a path glob:

```toml
[overrides."tests/**"]
disabled = ["PY-MAINT-003"]
severity = { "PY-COR-007" = "note" }

[overrides."db/**"]
severity = { "PY-COR-007" = "error" }
```

Each table is keyed by one glob and may carry `disabled` (an array of rule IDs)
and `severity` (an inline table of rule ID to `note` | `warning` | `error`).
Any other key is rejected. The glob follows the `analysis.exclude` rules
exactly: project-relative, no `..`, at most 512 characters, with `*`, `**`,
`?` and `[...]` meaning what they mean there, and a glob without a `/`
matching at any depth. Globs are matched against the finding's real
project-relative path, never a redacted display path. At most 1,000 tables
are accepted. Rule IDs must be well formed; an ID with no loaded provider is
inert, as in `[rules]`.

Resolution is per (path, rule):

1. Start from the rule default and apply `[rules]`.
2. Apply every override whose glob matches the path.
3. `disabled` is monotone. A rule disabled by `[rules]` or by **any** matching
   table stays disabled; a more specific table cannot re-enable it (there is no
   `enabled` list).
4. When several matching tables set a severity for the same rule, the table
   with the longest literal prefix (the characters before the first `*`, `?`
   or `[`) wins, so `src/db/**` beats `src/**`. Equal prefixes resolve to the
   table that appears **later in the file**. A table severity always beats a
   `[rules]` severity.

Security rules (`*-SEC-*`) may be disabled by path like any other rule; the
legitimate case is a vendored or generated tree. Nothing is hidden silently:
every finding dropped by `[rules]` or by an override is counted in the report
by rule and by source, and the configuration fingerprint covers the overrides
table, so a pinned gate (`--expect-config-fingerprint`) fails when the policy
changes.

## Inline suppressions

Source findings support explicit, same-line suppressions. Python has had them
since 2.x (including the literal `__all__` package rules `PY-PKG-004` and
`PY-PKG-005`); 3.2.0 extends the identical directive to the other seven
languages in `//`, `#`, `/* */` and `--` comments:

```python
def legacy(cache={}):  # cqa: ignore=PY-COR-001 reason="public API compatibility"
    return cache
```

```go
cfg := &tls.Config{InsecureSkipVerify: true} // cqa: ignore=GO-SEC-001 reason="local test proxy"
```

The rule ID list may be comma-separated. A nonempty quoted reason is mandatory.
For Python the directive must be a real comment on the finding's reported line
(text in strings or docstrings is ignored); for the regex languages the raw
source line is matched by shape.
Missing reasons, blank reasons,
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
comments and the ordering of keys inside a table do not affect it, and neither
does the order of `[rules]` tables. The order of `[overrides]` tables **does**:
it breaks severity ties, so adding, editing or reordering an override changes
the digest. A configuration with no overrides keeps the fingerprint it had
before the table existed. The digest contains no project path, source text,
suppression reason, or file content.

Severity is not part of a finding's baseline identity. Changing a severity
therefore preserves an accepted finding's fingerprint; without
`--new-findings-only`, the current severity still controls `--fail-on`.
