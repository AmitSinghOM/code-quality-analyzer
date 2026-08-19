# Privacy and threat model

## Privacy promise

The analyzer processes source locally. Runtime analysis does not require an account, API key, hosted model, telemetry endpoint, or network connection. The analyzer does not upload source, findings, metadata, or usage information.

## Data read

Default analysis reads bounded regular Python files under the selected project root and, when present, `pyproject.toml`. It does not follow directory symlinks, read symlink targets outside the project, read non-regular files, import the project, run build hooks, or execute project code.

## Data emitted

Normal reports can contain:

- Project directory name
- Project-relative source paths
- Function, argument, package, module, and dependency names
- Rule messages, locations, and remediation
- Architecture signals and optional evidence
- Package metadata and import relationships
- Experimental complexity estimates

`--redact-paths` removes directory components from report paths, but it is not full anonymization. Basenames, identifiers, messages, package metadata, and architecture signals can still be sensitive. Review reports before sharing them outside the trusted environment.

## Baselines

Baseline files contain a schema version, algorithm name, and SHA-256 finding fingerprints. They do not contain source paths, messages, snippets, identifiers, or evidence in plain text. Fingerprints are deterministic and are intended for regression comparison, not cryptographic secrecy against an attacker who already knows likely finding inputs.

## Local storage

The analyzer writes no cache or report unless the user explicitly redirects output or requests `--write-baseline`. Baselines are written with atomic replacement. Python, package-management, shell-redirection, and CI tools may independently create caches, build artifacts, or logs outside the analyzer's control.
