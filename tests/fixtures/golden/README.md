# CLI goldens

Byte-for-byte expected output of `code-quality-analyzer` for every reporter,
privacy mode, gate and analysis flag, consumed by `tests/test_analysis_options.py`.
Captured from `origin/main` at ee13547 (3.4.2 code, before the 3.5.0
`AnalysisOptions` refactor of `cqa_analyzer/__main__.py`) with the installed
binary, so the refactor is checked against what the released CLI printed.

| File | What it is |
|---|---|
| `src/` | The second fixture project (`golden_project`), stored as `*.sample` like `tests/fixtures/readme_sample/` so the repository's own gate and ruff never read it. Nested directory, one suppressed finding, five rule families, `late.py` absent from the baseline. |
| `baseline.json` | Written by `--write-baseline` from `src/` without `late.py`; `--baseline` + `--new-findings-only` therefore reports exactly one new finding. |
| `changed_lines.json` | Manifest naming one analysed range, one source file that does not exist and one non-source path, so the changed-line and not-analysed branches both print. |
| `*.golden` | stdout of one case (`<fixture>.<flags>.<format>`), unmodified except as noted below. |
| `*.stderr.golden` | The final `error:` line of a usage error (argparse wraps the usage block to the terminal width). |
| `exit_codes.json` | Exit code of every case. |

Normalised, JSON only: `project_analyses` and `scan_health.project_analysis`
entries are replaced by a marker (keys kept) because they report tree-sitter
availability and versions, which differ between the `[dev]` and `[dev,deep]`
installs CI runs. The raw `json.dumps(..., indent=2)` serialisation is still
asserted. Text and SARIF output is identical on both installs and is compared raw.

Regenerate after an intentional output change or a version bump
(`analyzer_version` and the `helpUri` tag appear in JSON and SARIF):

```bash
CQA_UPDATE_GOLDENS=1 pytest tests/test_analysis_options.py
```

Then read the diff: every changed line must be the change you meant to make.
