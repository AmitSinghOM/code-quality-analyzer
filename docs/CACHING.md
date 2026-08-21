# Incremental parse cache

Caching is explicit and local. Supply a directory when repeated analysis should
reuse unchanged Python and Go parse artifacts:

```bash
code-quality-analyzer . --cache-dir ~/.cache/code-quality-analyzer/my-project
```

The analyzer creates a private `parsed-v1` namespace below that directory. It
does not enable caching by default, choose a global location, invoke Git, or
write into the analyzed repository automatically.

## What is cached

Only language-adapter parse artifacts are cached. On a hit, all enabled rules,
architecture-signal providers, package providers, suppressions, severity
policy, baselines, changed-line selection, scoring, rendering, and CI gates run
again. Python package metadata and Go module metadata are reread on every run.
Project-provider results and final reports are never cached.

This boundary preserves full-project behavior and means warm and cold runs with
the same arguments produce byte-identical reports. Cache hits do not change
file counts, analysis authority, strict-mode decisions, findings, or exit
codes. Incomplete parse results may be cached, but they remain incomplete and
non-authoritative exactly as on a cold run.

## Invalidation

Each cache key is a SHA-256 digest of canonical metadata containing:

- Cache schema and plugin API versions
- Language, adapter, and cache-codec versions
- Adapter runtime identity, including Python major/minor version for Python ASTs
- Project-relative identity path
- SHA-256 digest of the exact UTF-8 source content

Changing content, renaming a file, changing an adapter/codec, or changing the
Python AST runtime therefore causes a miss. Source selection still runs before
cache lookup, so include/exclude policy, `.gitignore`, size limits, file limits,
and deleted files take effect immediately.

## Safety and privacy

Cache entries are bounded UTF-8 JSON. The analyzer never uses `pickle`,
dynamic imports, executable object tags, or project code to restore an entry.
Entries are limited to 16 MiB, validated against exact typed shapes, read as
regular files without following final-component symbolic links where the
platform supports it, and written with atomic replacement. The private cache
namespace uses directory mode `0700` and entry mode `0600` where supported.

A missing, corrupt, oversized, stale, unsafe, or incompatible entry is treated
as a cache miss. A cache write failure does not fail analysis or reduce
analysis authority. The selected cache directory itself and its fixed
`parsed-v1` namespace must not be symbolic links.

Cached artifacts contain source-derived identifiers, imports, literal values,
and stripped source layout. Treat the cache as source-equivalent sensitive
data. `--anonymize` changes report presentation; it does not anonymize cache
contents. Reports expose only `privacy.cache_enabled`, never the cache path,
keys, hit counts, entry names, source digests, or cache errors.

Cache access is local filesystem I/O and remains inside `--offline` enforcement.
It performs no network access, imports, builds, shell commands, language-tool
invocations, or project-code execution.

## Lifecycle and compatibility

The cache is disposable acceleration state, not a report or baseline. The
analyzer does not delete user-selected cache directories or run eviction hooks.
Remove a dedicated cache directory with normal operating-system tools when it
is no longer needed.

Cache entries have no cross-version migration guarantee. Incompatible schema,
adapter, codec, plugin API, or Python-runtime entries become misses. Baseline
fingerprints and report contracts are independent of cache keys.
