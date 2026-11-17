# Architecture

How a scan flows through the package, and what each module is for. The
[README](../README.md) is the user-facing entry point; this page is for
people reading or changing the code.

## How one run flows

1. `__main__.py` parses the command line, loads `.code-quality.toml`
   (`config.py`), optionally enables process-local network denial
   (`offline.py`), and builds the plugin registry (`plugins.py` ->
   `registry.py`).
2. `scanner.py` walks the project through `discovery.py` (skip list,
   size and count limits, symlink guard, generated-asset exclusion) and
   reads each file with the bounded reader in `safe_io.py`.
3. For every file, the language adapter registered for its extension
   (`languages/*.py`) parses it; the parse artifact may come from or go to
   the optional cache (`cache.py`). Each registered rule pack evaluates the
   artifact into findings (`findings.py`), and each signal provider records
   DSA and design pattern evidence (`signals.py`, `patterns.py`,
   `production_patterns.py`, `<language>_patterns.py`).
4. Project-level providers run once over all parsed files: package
   intelligence (`package_intelligence.py`, `manifests.py`), cross-file
   duplication (`duplication.py`), measured maintainability
   (`maintainability.py`), and the optional tree-sitter depth
   (`deep/`).
5. Rule policy from the configuration is applied as findings are stored;
   in-source suppressions are recorded in the ledger
   (`suppression_ledger.py`) rather than dropped silently.
6. `rater.py` turns pattern evidence into the architecture signal score;
   `__main__.py` applies changed-line selection (`changed_lines.py`),
   baselines (`baseline.py`), and anonymization (`anonymize.py`), then the
   negotiated reporter (`reporters.py`, `text_render.py`) renders text,
   JSON, or SARIF and the exit code is decided.

The contracts between those stages are the protocols in `protocols.py`:
`LanguageAdapter`, `ParsedArtifactCodec`, `RulePack`, `SignalProvider`,
`MetricProvider`, `ProjectProvider`, and `Reporter`. Every built-in language
is a plugin behind them, which is why `plugins.create_default_registry`
reads as a list of `register_*_plugins` calls.

## Module map

One line per module. Descriptions are the modules' own docstrings, shortened.

```
code-quality-analyzer/
├── cqa_analyzer/
│   ├── __init__.py              # Package and public contract versions
│   ├── __main__.py              # CLI entry point (argparse; no third-party dependencies)
│   ├── mcp_server.py            # MCP server for coding agents (stdio, stdlib only)
│   ├── delegate.py              # Delegate mode: deterministic review planning for a host agent
│   ├── text_render.py           # Plain-text panels and tables for the CLI (stdlib)
│   ├── anonymize.py             # Fully anonymized report projections for safe sharing
│   ├── baseline.py              # Privacy-safe hashed finding baselines
│   ├── cache.py                 # Bounded local cache for parse artifacts
│   ├── changed_lines.py         # Bounded changed-line finding selection
│   ├── config.py                # Bounded configuration, path, and rule policy
│   ├── discovery.py             # Safe file discovery (limits, symlink guard, skip list)
│   ├── safe_io.py               # Descriptor-based bounded reads of untrusted files
│   ├── offline.py               # Process-local network denial for --offline
│   ├── duplication.py           # Cross-file duplicate function detection
│   ├── maintainability.py       # Measured Python maintainability rules
│   ├── findings.py              # Language-neutral actionable finding model
│   ├── rule_metadata.py         # Stable built-in rule catalog (titles, remediation, not_when, CWE)
│   ├── rule_catalog.py          # Rule catalog behind --explain / --list-rules
│   ├── signals.py               # Per-file signal extraction and pattern matching
│   ├── patterns.py              # DSA and system design pattern definitions
│   ├── production_patterns.py   # Scoring policy 2.x production-systems specs shared by languages
│   ├── go_patterns.py           # Go signal definitions
│   ├── ts_patterns.py           # TypeScript/JavaScript signal definitions
│   ├── java_patterns.py         # Java signal definitions
│   ├── kotlin_patterns.py       # Kotlin signal definitions (extends Java)
│   ├── csharp_patterns.py       # C#/.NET signal definitions
│   ├── c_patterns.py            # C/C++ signal definitions (include-anchored)
│   ├── rust_patterns.py         # Rust signal definitions
│   ├── python_rules.py          # Source-located Python correctness and maintainability rules
│   ├── python_resources.py      # Blocking-call and resource-ownership Python rules
│   ├── python_security.py       # PY-SEC-001..005 (AST based)
│   ├── python_sql.py            # PY-COR-007: SQL assembled from runtime values
│   ├── python_suppressions.py   # Reason-required, comment-only suppressions for Python
│   ├── suppression_ledger.py    # Per-scan ledger of suppressed findings
│   ├── sql_text.py              # Decides whether a string literal starts a SQL statement
│   ├── secret_names.py          # Secret-bearing identifier classification shared by every language
│   ├── test_paths.py            # Test-path classification shared by every adapter
│   ├── manifests.py             # Shared nested-manifest discovery and hardened XML
│   ├── package_intelligence.py  # Passive Python metadata, modules, imports, cycles
│   ├── protocols.py             # Adapter, rule, provider, and reporter contracts
│   ├── registry.py              # Versioned plugin and capability negotiation registry
│   ├── plugins.py               # Built-in plugin assembly
│   ├── reporters.py             # Registered text, JSON, and SARIF renderers
│   ├── scanner.py               # Language-neutral orchestration through plugins
│   ├── complexity.py            # Time/space complexity analyzer (-c)
│   ├── rater.py                 # Architecture signal score (1-10)
│   ├── languages/               # Built-in language adapters and rule packs
│   │   ├── python.py            # Python plugins behind the extension contracts
│   │   ├── go.py                # Go adapter and pilot rule pack
│   │   ├── typescript.py        # TypeScript/JavaScript adapter, rule pack, provider
│   │   ├── java.py              # Java adapter, rule pack, signals, package provider
│   │   ├── kotlin.py            # Kotlin adapter, rule pack, signals, JVM package reuse
│   │   ├── csharp.py            # C#/.NET adapter, rule pack, signals, package provider
│   │   ├── c_family.py          # Bounded C/C++ adapter
│   │   ├── rust.py              # Rust adapter, rules, signals, Cargo intelligence
│   │   ├── _parity.py           # Correctness rules mirroring the Python catalog
│   │   ├── _security.py         # *-SEC-* rules shared by the regex-language adapters
│   │   ├── _sql.py              # Shared token-based SQL-assembly detection
│   │   ├── _suppressions.py     # Reason-required same-line suppressions for the regex packs
│   │   └── _shared.py           # Helpers shared by the regex-based adapters
│   └── deep/                    # Optional tree-sitter depth for Go, C/C++, Rust ([deep] extra)
├── tests/                       # Regression tests; tests/fixtures/ holds synthetic inputs
├── docs/                        # Rule, workflow, privacy, and release guidance (docs/README.md is the index)
├── scripts/                     # Calibration corpus, AACR-Bench slice, findings snapshot
├── .github/workflows/           # ci.yml, canary.yml, publish.yml
├── .code-quality.toml           # Policy for this repository's own scan
├── .code-quality-baseline.json  # Fingerprinted debt the CI ratchet compares against
├── .pre-commit-hooks.yaml       # Published pre-commit hook contract
├── requirements-release.*       # Hashed pins for the release workflow
├── pyproject.toml
├── MANIFEST.in
├── CHANGELOG.md
├── SECURITY.md
├── LICENSE
└── README.md
```

The map is checked against the package by `tests/test_readme_links.py`:
every module under `cqa_analyzer/` must appear here, and every name here
must exist, so the page cannot drift the way the README tree once did.
