# Changelog

All notable changes are documented in this file. Versions follow semantic versioning for the analyzer CLI and independent semantic versions for report and ruleset contracts.

## Unreleased

### Added

- Python package intelligence and optional complexity project providers
- Bounded Go adapter and `GO-COR-001` ignored-error pilot rule
- Mixed Python/Go reports with language counts and adapter versions
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

- Analyzer version advanced to 2.9.0; report schema remains 1.5.0 and ruleset remains 2.3.0
- Plugins now declare a core API target; project providers and reporters are resolved through explicit versioned capability negotiation
- Python package and complexity analysis now resolve through cached project providers
- Reports now inventory registered language adapters and analyzed language counts
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
