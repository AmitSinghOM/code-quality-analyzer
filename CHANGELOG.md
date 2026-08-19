# Changelog

All notable changes are documented in this file. Versions follow semantic versioning for the analyzer CLI and independent semantic versions for report and ruleset contracts.

## Unreleased

### Added

- Language-neutral plugin contracts and deterministic extension registry
- Built-in Python adapter and normalized Python rule-pack plugin
- Fully anonymized text and JSON reports with opaque source-identity tokens
- Explicit offline enforcement that denies socket operations during analysis
- Privacy-state metadata in the JSON report contract
- Privacy-safe finding baselines and severity-based CI gates
- Passive Python package metadata and import-graph analysis
- Source-located actionable Python findings
- Versioned JSON report metadata

### Changed

- Report schema remains 1.4.0 and analyzer version advanced to 2.6.0
- Anonymized package intelligence exposes aggregate facts only
- Verbose anonymized reports replace source-derived signals and reasoning
- Reports use project-relative paths and omit semantic evidence from malformed source
- Strict mode covers truncation, package metadata, and requested complexity gaps
- Big-O output is explicitly experimental

### Security

- Offline mode blocks connection and name-resolution socket entry points
- Baselines retain stable private identities without exposing them in reports
- Baselines store bounded SHA-256 fingerprints rather than source identifiers
- Skipped-file examples no longer expose absolute paths
