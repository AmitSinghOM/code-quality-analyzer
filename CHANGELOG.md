# Changelog

All notable changes are documented in this file. Versions follow semantic versioning for the analyzer CLI and independent semantic versions for report and ruleset contracts.

## Unreleased

### Added

- Privacy-safe finding baselines and severity-based CI gates
- Passive Python package metadata and import-graph analysis
- Source-located actionable Python findings
- Versioned JSON report metadata

### Changed

- Reports use project-relative paths and omit semantic evidence from malformed source
- Strict mode covers truncation, package metadata, and requested complexity gaps
- Big-O output is explicitly experimental

### Security

- Baselines store bounded SHA-256 fingerprints rather than source identifiers
- Skipped-file examples no longer expose absolute paths
