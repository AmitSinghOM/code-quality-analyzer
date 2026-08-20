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
- Versioned analysis-authority schema, score-migration ADR, and golden contract fixtures
- Bounded `.code-quality.toml` source selection and per-rule policy
- Root `.gitignore`-aware inventory with deterministic negation handling
- Reason-required Python inline suppressions that never expose reason text
- Privacy-safe effective-configuration fingerprints in JSON reports
- High-confidence Python findings for broad handlers, swallowed exceptions, and unreachable statements

### Changed

- Analyzer version advanced to 2.16.0; report schema remains 1.8.0 and ruleset advanced to 2.6.0
- Reports now qualify authority with source-candidate, readable-file, and successful-analysis counts, completeness ratio, and stable reason codes
- `architecture_signal_score` replaces `rating` as the primary score name; `rating` remains a documented equal-valued 2.x compatibility alias
- Source candidates with zero successful analyses now exit 3 even without strict mode
- Built-in text and JSON reporters now implement the versioned reporter contract and are selected dynamically through the plugin registry
- The CLI emits an immutable report envelope through negotiated reporters instead of directly serializing JSON
- Go imports now preserve default, explicit, blank, and dot-import semantics; `GO-COR-001` follows explicit aliases without trusting blank or dot imports
- A passive Go project provider now aggregates multi-file packages and local module import edges from shared facts and a bounded `go.mod` read
- JSON reports expose privacy-projected project-provider results and generic project-analysis health
- Optional Python complexity analysis now consumes the scanner's shared AST artifacts instead of discovering, reading, and parsing source again
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
