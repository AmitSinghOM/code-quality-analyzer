# readme_sample

The small synthetic project whose analyzer output the top of the repository
[README](../../../README.md) quotes. Three Python files, three deliberate
defects (`PY-COR-006`, `PY-SEC-004`, `PY-COR-002`), a manual LRU cache and a
heap so the pattern tables are not empty.

## Why the files end in `.sample`

The repository gates itself with `code-quality-analyzer` in CI (baseline
ratchet, `--strict`, changed-line selection). Real `.py` files here would
either add three new findings to that gate or, if excluded by
configuration, count as in-scope files that were not analyzed (a strict
coverage gap, exit 3). Storing them as `*.sample` keeps them out of the
repository's own scan and out of `ruff`, while the content stays exactly
what the README shows being analyzed.

## Re-running it

`tests/test_readme_links.py` copies the files into a temporary directory
named `readme_sample` with the suffix removed, runs the analyzer there, and
asserts the README's fenced block equals the output. To see it yourself:

```bash
tmp="$(mktemp -d)/readme_sample"
(cd tests/fixtures/readme_sample && find . -name '*.sample' | while read -r f; do
  mkdir -p "$tmp/$(dirname "$f")" && cp "$f" "$tmp/${f%.sample}"; done)
code-quality-analyzer "$tmp" --offline
```

When the output changes on purpose (a rule message, a new pattern), paste the
new output into the README's `What a run looks like` block; the test tells
you when the two disagree.
