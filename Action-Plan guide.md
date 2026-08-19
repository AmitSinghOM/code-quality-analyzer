# Code Quality Analyzer Action-Plan Guide

**Status:** Proposed roadmap  
**Current focus:** Python packages  
**Long-term direction:** Private, deterministic, multi-language package analysis

## 1. Purpose

This guide converts the August 2026 code-quality-analyzer audit into an implementation plan. It is the reference for deciding what to build, in what order, and how each phase is accepted.

The product goal is:

> A deterministic, privacy-first code health analyzer that runs entirely on the developer's machine and produces actionable, source-located findings for packages and changed code.

The current DSA and system-design detection remains useful, but it should be positioned as an **Algorithm and Architecture Signal Inventory**, not as proof of overall code quality.

## 2. Product principles

1. **Private by default:** source code, paths, identifiers, and findings never leave the machine.
2. **Deterministic:** identical inputs, configuration, analyzer version, and ruleset produce identical results.
3. **Actionable:** every finding has a rule ID, location, severity, confidence, explanation, and remediation.
4. **Honest confidence:** incomplete or heuristic analysis is clearly identified and cannot silently produce an authoritative score.
5. **Package-aware:** analysis covers package metadata, dependencies, imports, public APIs, tests, and build artifacts—not only individual files.
6. **CI-friendly:** stable schemas, useful exit codes, baselines, changed-code analysis, and standard report formats are first-class features.
7. **Language-extensible:** the core owns inventory, policy, findings, and reports; language adapters own parsing and language-specific facts.
8. **No AI dependency:** core analysis works offline and does not require an account, API key, model, or network connection.

## 3. Audit reference baseline

### 3.1 Existing strengths

- Fully local runtime with no analyzer telemetry or source upload.
- Defensive Python file discovery with size limits, file-count limits, symlink escape protection, and non-regular-file checks.
- Deterministic file ordering and focused regression tests.
- DSA and system-design signal detection with evidence.
- Text and JSON output, scan-health reporting, CI thresholds, and strict mode.
- Experimental function time/space complexity summaries.
- Existing validation baseline: 44 tests pass and Ruff reports no issues.

### 3.2 Critical shortcomings found by the audit

1. **Privacy output does not match the README guarantee.** The project root and skipped-file examples can contain absolute paths; skipped examples may leak paths even when path redaction is enabled.
2. **The 1–10 rating does not measure general code quality.** It rewards DSA, framework, testing, authentication, singleton, and architecture-related signals without establishing correctness or maintainability.
3. **Findings are not sufficiently actionable.** Most results lack stable rule IDs, precise locations, severity, remediation, and suppression support.
4. **Malformed source can influence text-based signal detection.** Files that cannot be parsed must not increase a semantic score.
5. **Complexity estimates are overconfident.** Constant loops, independent input sizes, sorting inside loops, collection operations, and recursive state spaces can be classified incorrectly.
6. **Strict mode does not include all complexity-analysis failures.** Complexity health must participate when complexity analysis is requested.
7. **Truncated scans can produce optimistic results.** An incomplete scan must not look authoritative.
8. **Metadata and CLI behavior are inconsistent.** Package and runtime versions differ; numeric options need bounds; JSON evidence behavior differs from the verbose flag.
9. **The JSON contract is not versioned.** It lacks analyzer, schema, ruleset, and scoring-policy versions.
10. **Redacted basenames are ambiguous.** Separate files with the same basename cannot be distinguished.
11. **Files are parsed more than once.** Pattern and complexity analysis should consume shared parsed facts.
12. **Multi-language concerns are hard-wired to Python.** Discovery, AST extraction, rules, complexity, CLI, and output lack extension interfaces.

## 4. Target product model

Replace the single pattern-derived quality score with a multidimensional report:

```text
Maintainability       74/100
Correctness risk      82/100
Testing maturity      61/100
Package health        90/100
Security hygiene      77/100
Architecture signals  12 detected
Analysis confidence   96%
```

The first release does not need every dimension. It does need to distinguish:

- **Findings:** actionable defects, risks, and maintainability concerns.
- **Metrics:** measured values such as cognitive complexity or module coupling.
- **Signals:** descriptive observations such as framework or design-pattern usage.
- **Analysis health:** coverage, skipped files, parser failures, truncation, and confidence.

If an overall score remains, its formula must be documented, configurable, versioned, and derived primarily from actionable findings. The current score should be renamed to `architecture_signal_score` during a compatibility period and eventually removed from default CI gating.

## 5. Normalized finding contract

All rules and language adapters should emit one common model:

```json
{
  "rule_id": "PY-MAINT-004",
  "category": "maintainability",
  "severity": "warning",
  "confidence": "high",
  "message": "Function has cognitive complexity of 24",
  "location": {
    "path": "src/orders/service.py",
    "line": 87,
    "column": 1
  },
  "remediation": "Extract validation and pricing branches into separate functions."
}
```

Required report metadata:

- Schema version
- Analyzer version
- Ruleset version
- Policy/scoring version, when scoring is enabled
- Language adapter versions
- Configuration fingerprint
- Analysis completeness and confidence
- Deterministic project-relative file IDs

## 6. Target architecture

```text
Core
├── safe file inventory and ignore handling
├── configuration and policy
├── normalized project/file/finding models
├── baselines and changed-code comparison
├── report generation
└── plugin registry

Language adapters
├── Python frontend
├── future Go frontend
├── future Java frontend
└── future JavaScript/TypeScript frontend

Rule packs
├── common package rules
├── maintainability rules
├── security-hygiene rules
└── language-specific rules
```

Proposed extension contracts:

```python
class LanguageAdapter(Protocol):
    language_id: str
    extensions: tuple[str, ...]

    def parse(self, file: SourceFile) -> ParsedFile: ...
    def extract_facts(self, parsed: ParsedFile) -> FileFacts: ...


class Rule(Protocol):
    rule_id: str

    def evaluate(self, project: ProjectFacts) -> Iterable[Finding]: ...


class Reporter(Protocol):
    format_name: str

    def render(self, report: AnalysisReport) -> bytes: ...
```

Do not force every language into one universal AST. Normalize only shared facts such as definitions, references, imports, calls, dependencies, control-flow metrics, and locations. Preserve language-specific facts behind adapter-owned models.

## 7. Phase plan

### Phase 0 — Baseline and decision records

**Objective:** Freeze current behavior and document decisions before changing public contracts.

**Work:**

- Capture golden text and JSON output for representative repositories.
- Add a rule catalog for all current DSA and design signals.
- Record current performance on small, medium, and large Python packages.
- Create architecture decisions for the finding model, privacy defaults, schema versioning, and score migration.
- Define supported Python versions and operating systems.
- Define compatibility policy for CLI, configuration, JSON, and rules.

**Deliverables:**

- Baseline fixtures and benchmark script
- Initial rule catalog
- Architecture decision records
- Published compatibility policy

**Exit criteria:**

- Current behavior is reproducible in tests.
- Public-contract changes planned for Phase 1 are documented.
- The team can measure correctness, privacy, and performance regressions.

### Phase 1 — Trust, privacy, and correctness

#### Phase 1 progress (August 20, 2026)

**Status:** In progress

Completed in the first trust slice:

- Reports identify the project by directory name and use project-relative skipped-file examples.
- JSON now exposes schema, analyzer, and ruleset versions.
- Package metadata reads its version from the runtime package.
- CLI numeric options enforce valid positive/rating ranges.
- Unparsed source no longer contributes semantic pattern evidence.
- Strict mode now covers truncation and requested complexity-analysis gaps.
- JSON evidence now follows `--verbose` consistently.
- Complexity output is explicitly labeled experimental.
- Privacy, malformed-source, strict-mode, metadata, and option-boundary regressions are covered by tests.

Remaining Phase 1 work includes anonymized stable file identifiers, duplicate-basename-safe redaction, scoring-policy metadata, complete/incomplete confidence semantics, and zero-source versus zero-success distinction.

**Objective:** Make every report safe and make incomplete analysis explicit.

**Work:**

- Centralize path rendering and use project-relative paths by default.
- Ensure project roots, skipped examples, complexity findings, errors, and debug data use the same privacy policy.
- Add `--anonymize` with stable per-report file identifiers.
- Synchronize package/runtime version metadata from one source.
- Add bounds for file size, file count, thresholds, and related numeric CLI options.
- Prevent unparsed or untokenizable files from contributing semantic evidence or score.
- Include complexity health and truncation in strict-mode decisions.
- Mark Big-O output as experimental and expose assumptions/confidence.
- Add schema, analyzer, ruleset, and scoring-policy versions to JSON.
- Make JSON evidence honor an explicit option consistently.
- Distinguish zero source files from zero successfully analyzed files.

**Required tests:**

- No absolute path appears in any output mode, including skipped-file cases.
- Redaction distinguishes files with duplicate basenames.
- Malformed files cannot increase scores or emit semantic findings.
- Strict mode fails for truncation and complexity coverage gaps.
- CLI rejects invalid ranges with useful messages.
- Golden JSON validates against the versioned schema.

**Exit criteria:**

- Privacy claims in documentation are enforced by tests.
- No incomplete scan can produce an unqualified authoritative result.
- All report consumers can identify the exact report contract version.

### Phase 2 — Actionable Python findings

#### Phase 2 progress (August 20, 2026)

**Status:** In progress

Completed in the first Phase 2 vertical slice:

- Added language-neutral `Finding` and `Location` report contracts.
- Added a Python rule protocol and deterministic rule runner.
- Reused the AST created during signal extraction instead of parsing files again.
- Added `PY-COR-001` for mutable default arguments with precise locations and remediation.
- Added JSON finding details, aggregate finding summaries, and terminal rendering.
- Added positive, negative, determinism, location, parse-once, and report integration tests.
- Added the initial rule reference in `docs/RULES.md`.

Next work is `.code-quality.toml`, ignore/suppression support, severity-based gates, and additional high-confidence correctness rules.

**Objective:** Provide enough value for developers to use the analyzer during daily Python development.

**Work:**

- Implement the normalized finding model with file, line, column, severity, confidence, explanation, and remediation.
- Add `.code-quality.toml` configuration.
- Support include/exclude globs and `.gitignore`-aware inventory.
- Add per-rule configuration and inline suppressions that require a reason.
- Add measured cyclomatic and cognitive complexity.
- Add initial Python correctness and maintainability rules:
  - Mutable default arguments
  - Broad, empty, or silently swallowed exceptions
  - Unreachable code
  - Excessive nesting
  - Long functions, classes, and modules
  - Excessive parameters
  - Blocking operations in async functions
  - Resource handling without context managers
  - Boolean parameter proliferation
  - High module coupling
- Parse each file once and share facts between rule packs and metrics.
- Move existing DSA/design detection under the Architecture Signal Inventory category.

**Deliverables:**

- Versioned Python ruleset
- Config reference
- Rule reference with good/bad examples
- Source-located text and JSON findings

**Exit criteria:**

- A developer can identify what is wrong, where it is, why it matters, and how to address it.
- Every enabled rule has positive, negative, boundary, and suppression tests.
- Existing architecture signals no longer claim to establish general quality.

### Phase 3 — Python package intelligence

**Objective:** Analyze whether a Python package is correctly structured and distributable.

**Work:**

- Read and validate `pyproject.toml` and supported legacy metadata.
- Understand flat, `src/`, namespace-package, application, and library layouts.
- Build module and dependency graphs.
- Detect circular imports.
- Detect imported-but-undeclared and declared-but-unused dependencies where confidence is sufficient.
- Validate console-script and plugin entry points.
- Analyze accidental public APIs and `__all__` consistency.
- Validate package-data declarations.
- Add optional wheel/sdist build and isolated import smoke checks; never execute package code by default without explicit consent.
- Import local coverage reports and report source modules without test coverage.
- Add basic test-quality signals such as tests without assertions, excessive skips, and overly broad exception assertions.

**Privacy and safety constraints:**

- Package builds and imports are opt-in because project build hooks and imports can execute arbitrary code.
- Opt-in execution runs with documented isolation and time/resource limits.
- No dependency or vulnerability lookup contacts the network unless explicitly requested.

**Exit criteria:**

- Common package-layout and metadata problems produce actionable findings.
- The analyzer can explain the package/module dependency graph.
- Potentially executable checks are clearly separated from passive static analysis.

### Phase 4 — Developer and CI workflows

**Objective:** Make adoption practical without forcing teams to fix all historical findings immediately.

**Work:**

- Add baseline creation and comparison.
- Add changed-file and changed-line analysis.
- Add `--new-findings-only`.
- Add severity/category/rule-based CI gates.
- Add stable SARIF output.
- Add optional HTML and JUnit-style summaries.
- Add pre-commit integration.
- Add deterministic content-hash caching and incremental analysis.
- Provide concise terminal output with a separate verbose diagnostic mode.
- Document CI examples for common code-hosting systems.

**Target workflow:**

```bash
code-quality-analyzer check . \
  --baseline .code-quality-baseline.json \
  --new-findings-only \
  --fail-on error \
  --format sarif
```

**Exit criteria:**

- Teams can adopt the analyzer without failing on accepted legacy debt.
- CI can block only newly introduced high-severity findings.
- Results can be consumed by standard code-scanning interfaces.
- Unchanged files are not reparsed when cache inputs remain valid.

### Phase 5 — Distribution and privacy hardening

**Objective:** Make installation, offline use, and report sharing dependable.

**Work:**

- Add LICENSE, SECURITY, privacy/threat-model, changelog, migration, and contribution documents.
- Build and install wheel/sdist artifacts in CI.
- Test supported Python versions on macOS, Linux, and Windows.
- Remove duplicated dependency declarations or enforce synchronization.
- Define dependency pinning and reproducible-build policies.
- Cover runtime, development, and build dependencies in local audits.
- Add a fully anonymized report mode that removes paths and source identifiers.
- Add explicit `--offline` behavior that rejects network-backed integrations.
- Document precisely what is written to stdout, files, caches, and temporary storage.
- Add resource-limit, timeout, malformed-input, and filesystem safety tests.

**Exit criteria:**

- The package installs from built artifacts and passes a smoke analysis.
- Air-gapped analysis is documented and continuously tested.
- Shared anonymized reports reveal no project paths or source identifiers.
- Supported platforms pass privacy and filesystem behavior tests.

### Phase 6 — Multi-language foundation

**Objective:** Extract a stable language-neutral core before adding another language.

**Work:**

- Separate safe inventory, configuration, findings, policies, baselines, caching, and reporters from Python parsing.
- Introduce language-adapter, rule-pack, metric-provider, and reporter registries.
- Move Python behavior behind the new contracts without changing validated outputs.
- Define plugin compatibility and capability negotiation.
- Allow parsers and rule packs to be optional dependencies.
- Define cross-language project and package dependency facts.

**Exit criteria:**

- The core contains no Python AST assumptions.
- Python passes all existing contract and behavior tests through its adapter.
- A minimal test adapter can register a language, emit a finding, and use every standard reporter without CLI changes.

### Phase 7 — Pilot second language

**Objective:** Prove the extension model with one useful, bounded language implementation.

**Recommended pilot:** Go, because its package model and parser/tooling conventions are relatively standardized.

**Work:**

- Implement source discovery and parsing through the language-adapter contract.
- Add a small high-confidence rule pack rather than matching Python feature count.
- Add package/import graph support.
- Reuse configuration, findings, baselines, SARIF, caching, privacy, and CI gates unchanged.
- Record adapter friction and revise extension contracts before a third language.

**Exit criteria:**

- A mixed Python/Go repository produces one coherent report.
- Language-specific rules remain isolated from the core.
- Adding the pilot requires no hard-coded branching in standard reporters or policies.

## 8. Recommended implementation order within each phase

Use vertical slices rather than building all infrastructure first:

1. Define or extend the report contract.
2. Implement one representative rule or feature end-to-end.
3. Add text, JSON, and applicable SARIF rendering.
4. Add privacy, correctness, and contract tests.
5. Document configuration and remediation.
6. Measure performance.
7. Expand the rule/feature set only after the slice is stable.

## 9. Definition of done for every rule

A rule is complete only when it has:

- Stable namespaced rule ID
- Category, default severity, and confidence policy
- Clear message and remediation
- Precise source location when available
- Positive and negative fixtures
- Boundary and malformed-input tests
- Suppression test
- Documentation with compliant/non-compliant examples
- Deterministic output test
- Performance consideration
- Privacy review confirming that evidence does not expose unnecessary source

## 10. Success metrics

Track product quality without collecting user telemetry. Measurements should come from local fixtures, opt-in community feedback, and CI:

- False-positive rate on the maintained calibration corpus
- False-negative rate for rules with known vulnerable/incorrect examples
- Percentage of findings with precise source locations
- Analysis completeness percentage
- Median and worst-case analysis time by repository size
- Peak memory by repository size
- Incremental cache hit rate in controlled benchmarks
- Report-schema compatibility test results
- Number of privacy leakage tests
- Percentage of rules with complete rule-quality fixtures
- Time for a developer to understand and resolve a sampled finding

Do not add telemetry to collect these metrics automatically from user projects.

## 11. Explicit non-goals

- Replacing a compiler, language server, or type checker.
- Executing untrusted project code during default analysis.
- Claiming that architecture-pattern presence proves quality.
- Producing authoritative Big-O guarantees from syntax alone.
- Sending source code to hosted AI or analysis services.
- Supporting many languages before the extension contracts are validated.
- Reimplementing every mature local tool when importing its local output is safer and faster.

## 12. Private local-tool integrations

Privacy does not require rebuilding every analyzer. Optional adapters may consume local outputs from tools such as Ruff, mypy, Bandit, coverage.py, or package builders. Requirements:

- Integrations are local and explicit.
- External tool versions are recorded in report metadata.
- Raw source is never transmitted.
- Network-backed database updates are opt-in.
- Findings are normalized into the same report model.
- Missing optional tools degrade gracefully.

## 13. Immediate next backlog

Start with these tasks in order:

1. Fix path leakage in project and skipped-file output.
2. Add privacy regression fixtures for every output mode.
3. Unify version metadata.
4. Add CLI range validation.
5. Version the JSON contract.
6. Make parse failure and truncation authoritative analysis-health failures.
7. Include complexity health in strict mode.
8. Rename the current quality score in output and documentation.
9. Introduce the normalized `Finding` and `Location` models.
10. Implement one end-to-end maintainability rule as the architectural proving slice.

## 14. Roadmap dependency summary

```text
Phase 0: Baseline and decisions
    ↓
Phase 1: Trust, privacy, correctness
    ↓
Phase 2: Actionable Python findings
    ↓
Phase 3: Python package intelligence
    ↓
Phase 4: Developer and CI workflows
    ↓
Phase 5: Distribution/privacy hardening
    ↓
Phase 6: Multi-language foundation
    ↓
Phase 7: Pilot second language
```

Phases may overlap only when their dependencies are satisfied. In particular, do not begin a second language before the Phase 6 contracts are proven by the Python adapter.

## 15. Reference conclusion

The analyzer should compete with hosted AI review products through privacy, determinism, reproducibility, source-located evidence, and transparent rules—not through open-ended generated advice. The shortest route to real developer value is to establish trustworthy privacy, replace pattern-presence scoring with actionable findings, understand Python packages, and support baseline-driven CI. Multi-language support should follow only after those capabilities are separated into a stable language-neutral core.
