# Privacy and threat model

## Privacy promise

The analyzer processes source locally. Runtime analysis does not require an account, API key, hosted model, telemetry endpoint, or network connection. It does not upload source, findings, metadata, or usage information.

`--offline` enforces this boundary in the analyzer process by denying socket connections and name resolution while analysis runs. A blocked attempt terminates the command with an error. The guard is not an operating-system sandbox and does not control unrelated processes; the analyzer currently launches no project code or network-backed subprocess during passive analysis.

## Data read

Default analysis reads bounded regular Python files under the selected project root and, when present, `pyproject.toml`. When explicitly requested, it also reads one bounded regular UTF-8 changed-lines manifest, which may be outside the project root. It does not follow directory symlinks, read symlink targets outside the project, read non-regular files, import the project, run build hooks, or execute project code.

## Normal report data

Normal reports can contain:

- Project directory name and project-relative source paths
- Function, argument, package, module, dependency, and script names
- Rule messages, locations, and remediation
- Architecture signals and optional source-derived evidence
- Package metadata and import relationships
- Experimental complexity estimates and reasoning

SARIF contains only normalized actionable findings plus the built-in rule
catalog, analysis health, privacy state, effective-configuration fingerprint,
and baseline-selection metadata. It omits architecture evidence, package
intelligence, complexity data, source snippets, command lines, environment
variables, timestamps, fixes, finding fingerprints, and repository metadata.
Artifact locations are percent-encoded project-relative URIs, never absolute or
`file://` URIs.

When changed-line selection is enabled, every format adds only its schema
version and aggregate file, canonical-range, input-finding, and selected-finding
counts. That selection metadata omits the manifest path, manifest source paths,
raw ranges, content, and hash. Selected findings retain the format's normal or
anonymized path behavior. Selection uses hidden project-relative identities
before any path redaction or anonymization.

`--redact-paths` removes directory components from report paths, but it is not full anonymization. Basenames, identifiers, messages, package metadata, and architecture signals can still be sensitive.

## Fully anonymized reports

`--anonymize` is stronger than `--redact-paths` and applies to text, JSON,
and SARIF output. It:

- Replaces the project name with `anonymized-project`
- Replaces file and function identities with report-local opaque tokens
- Replaces finding messages and remediation with generic rule guidance
- Reduces package intelligence to booleans and aggregate counts
- Replaces verbose architecture evidence with signal counts
- Removes detailed complexity reasoning and operation identifiers

Anonymized reports intentionally retain rule IDs, finding categories and severities, line and column numbers, aggregate counts, rating data, built-in pattern names, and complexity classes. Those facts may still reveal project characteristics. Review any artifact before sharing it with an untrusted party. Tokens provide data minimization, not cryptographic anonymity or stable cross-report pseudonyms.

## Baselines

Baseline files contain a schema version, algorithm name, and SHA-256 finding fingerprints. They do not contain source paths, messages, snippets, identifiers, or evidence in plain text. Fingerprints are deterministic and are intended for regression comparison, not cryptographic secrecy against an attacker who already knows likely finding inputs. Anonymization and path redaction do not change fingerprint identity.

## Parse cache

`--cache-dir` explicitly enables local parse-artifact caching. Cache entries can
contain source-derived identifiers, imports, literals, and stripped source
layout, so they must be protected like source code. `--anonymize` applies only
to reports and does not anonymize cache contents.

The cache uses bounded typed JSON, a private fixed namespace, restrictive
permissions where supported, and atomic replacement. It never uses executable
deserialization or imports project classes. Unsafe, corrupt, stale, oversized,
or incompatible entries become misses. Reports expose only the aggregate
`cache_enabled` boolean; cache paths, keys, source digests, hit counts, entry
errors, and contents are omitted. See [`CACHING.md`](CACHING.md).

## Pre-commit execution

The published hook fixes the analyzer entry to
`code-quality-analyzer . --offline`, processes the repository locally, and
sends no telemetry. Pre-commit
is a separate tool and may access the network during first installation to
clone the pinned hook repository and install declared dependencies. Its cached
environment and lifecycle are outside the analyzer process and threat boundary.

## Local storage

The analyzer writes no report unless the user explicitly redirects text, JSON,
or SARIF output or requests `--write-baseline`. It writes bounded parse
artifacts only when `--cache-dir` explicitly selects a local directory. SARIF
rendering is local and performs no network access. Baselines and cache entries
are written with atomic replacement. Python, package-management,
shell-redirection, and CI tools may independently create caches, build
artifacts, or logs outside the analyzer's control.
