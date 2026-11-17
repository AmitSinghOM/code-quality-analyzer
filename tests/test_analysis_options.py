"""CLI goldens around the ``AnalysisOptions`` refactor (3.5.0, R2-1).

The goldens under ``tests/fixtures/golden/`` were captured from ``origin/main``
at ee13547, BEFORE ``_run_analysis`` and the reporters took an
``AnalysisOptions`` instead of their long parameter lists, by running the
installed ``code-quality-analyzer`` binary. Every case here re-runs the CLI
in-process and compares stdout byte for byte, so any reordering, reworded
string, dropped line or changed exit code the refactor introduced fails one
named case.

Two fixtures: ``tests/fixtures/readme_sample/`` (the README's project) and
``tests/fixtures/golden/src/`` (nested directory, a suppressed finding, five
rule families, one file absent from the committed baseline). Both are stored
with a ``.sample`` suffix so the repository's own gate never reads them.

What is normalised, and why (nothing else is):

* JSON ``project_analyses`` and ``scan_health.project_analysis``: each
  provider entry is replaced by a marker, keys kept. Those blocks report
  tree-sitter availability and versions, which differ between the ``[dev]``
  and ``[dev,deep]`` installs CI runs. The raw serialisation is still locked
  (``json.dumps(..., indent=2)`` must reproduce the output exactly).
* The stderr golden keeps only the final ``error:`` line; argparse wraps the
  usage block to the terminal width.

Regenerate after an intentional output change or a version bump
(``analyzer_version`` and the ``helpUri`` tag are in the JSON/SARIF goldens)::

    CQA_UPDATE_GOLDENS=1 pytest tests/test_analysis_options.py
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
from pathlib import Path

import pytest

from clirunner import CliRunner

from cqa_analyzer.__main__ import AnalysisOptions, build_parser, main

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
README_FIXTURE = ROOT / "tests" / "fixtures" / "readme_sample"
PROJECT_FIXTURE = GOLDEN / "src"
BASELINE = GOLDEN / "baseline.json"
MANIFEST = GOLDEN / "changed_lines.json"
EXIT_CODES = GOLDEN / "exit_codes.json"
SAMPLE_SUFFIX = ".sample"
UPDATE = os.environ.get("CQA_UPDATE_GOLDENS") == "1"

# The default configuration's fingerprint (no .code-quality.toml in either fixture).
DEFAULT_FINGERPRINT = "7f2042db6205d44e3ce413ff9080011ffc8edd6904b18c87b1268e1331ccdf62"
INSTALL_DEPENDENT = "<install-dependent: tree-sitter availability>"

README, PROJECT = "readme_sample", "golden_project"

# (golden name, fixture, extra CLI arguments). ``--offline`` is always added.
CASES: list[tuple[str, str, list[str]]] = []
for _label in (README, PROJECT):
    CASES += [
        (f"{_label}.text", _label, []),
        (f"{_label}.json", _label, ["-f", "json"]),
        (f"{_label}.sarif", _label, ["-f", "sarif"]),
        (f"{_label}.anonymize.text", _label, ["--anonymize"]),
        (f"{_label}.anonymize.json", _label, ["-f", "json", "--anonymize"]),
        (f"{_label}.anonymize.sarif", _label, ["-f", "sarif", "--anonymize"]),
        (f"{_label}.redact.text", _label, ["--redact-paths"]),
        (f"{_label}.redact.json", _label, ["-f", "json", "--redact-paths"]),
        (f"{_label}.redact.sarif", _label, ["-f", "sarif", "--redact-paths"]),
    ]
_BASELINE = ["--baseline", str(BASELINE)]
_NEW = [*_BASELINE, "--new-findings-only"]
_MANIFEST = ["--changed-lines-manifest", str(MANIFEST)]
_FINGERPRINT = ["--expect-config-fingerprint"]
CASES += [
    (f"{PROJECT}.baseline_new.text", PROJECT, _NEW),
    (f"{PROJECT}.baseline_new.json", PROJECT, ["-f", "json", *_NEW]),
    (f"{PROJECT}.baseline_new.sarif", PROJECT, ["-f", "sarif", *_NEW]),
    (f"{PROJECT}.baseline_new.anonymize.sarif", PROJECT, ["-f", "sarif", "--anonymize", *_NEW]),
    (f"{PROJECT}.baseline_all.text", PROJECT, _BASELINE),
    (f"{PROJECT}.baseline_changed_lines.text", PROJECT, [*_BASELINE, *_MANIFEST]),
    (f"{PROJECT}.baseline_changed_lines.json", PROJECT, ["-f", "json", *_BASELINE, *_MANIFEST]),
    (
        f"{PROJECT}.baseline_changed_lines.anonymize.text",
        PROJECT,
        ["--anonymize", *_BASELINE, *_MANIFEST],
    ),
    (f"{PROJECT}.verbose_complexity.text", PROJECT, ["-v", "-c"]),
    (f"{PROJECT}.verbose_complexity.json", PROJECT, ["-v", "-c", "-f", "json"]),
    (
        f"{PROJECT}.verbose_complexity.anonymize.json",
        PROJECT,
        ["-v", "-c", "-f", "json", "--anonymize"],
    ),
    (f"{PROJECT}.changed_lines.text", PROJECT, _MANIFEST),
    (f"{PROJECT}.changed_lines.json", PROJECT, ["-f", "json", *_MANIFEST]),
    (f"{PROJECT}.changed_lines.anonymize.json", PROJECT, ["-f", "json", "--anonymize", *_MANIFEST]),
    (f"{PROJECT}.changed_lines.sarif", PROJECT, ["-f", "sarif", *_MANIFEST]),
    (f"{PROJECT}.changed_lines_strict.text", PROJECT, ["--strict", *_MANIFEST]),
    (f"{PROJECT}.max_file_size.text", PROJECT, ["--max-file-size", "600"]),
    (f"{PROJECT}.max_file_size_strict.text", PROJECT, ["--strict", "--max-file-size", "600"]),
    (f"{PROJECT}.max_files.text", PROJECT, ["--max-files", "2"]),
    (f"{PROJECT}.fail_on.text", PROJECT, ["--fail-on", "warning"]),
    (f"{PROJECT}.fail_on_error.text", PROJECT, ["--fail-on", "error"]),
    (f"{PROJECT}.fail_under.text", PROJECT, ["--fail-under", "9.5"]),
    (f"{PROJECT}.cache.text", PROJECT, ["--cache-dir", "{tmp}/cache"]),
    (f"{PROJECT}.fingerprint_ok.text", PROJECT, [*_FINGERPRINT, DEFAULT_FINGERPRINT]),
    (f"{PROJECT}.fingerprint_mismatch.text", PROJECT, [*_FINGERPRINT, "0" * 64]),
    (f"{PROJECT}.no_project_config.text", PROJECT, ["--no-project-config"]),
    (f"{PROJECT}.unknown_format.text", PROJECT, ["-f", "yaml"]),
]
_FIXTURES = {README: README_FIXTURE, PROJECT: PROJECT_FIXTURE}


def materialize(fixture: Path, root: Path, skip: frozenset[str] = frozenset()) -> Path:
    """Copy ``fixture`` into ``root`` with the ``.sample`` suffix removed."""
    for source in sorted(fixture.rglob(f"*{SAMPLE_SUFFIX}")):
        relative = source.relative_to(fixture).with_suffix("")
        if relative.as_posix() in skip:
            continue
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


def normalize_json(text: str) -> str:
    payload = json.loads(text)
    assert json.dumps(payload, indent=2) + "\n" == text, "JSON serialisation changed"
    payload["project_analyses"] = dict.fromkeys(payload["project_analyses"], INSTALL_DEPENDENT)
    health = payload["scan_health"]["project_analysis"]
    payload["scan_health"]["project_analysis"] = dict.fromkeys(health, INSTALL_DEPENDENT)
    return json.dumps(payload, indent=2) + "\n"


def _golden(name: str) -> Path:
    return GOLDEN / f"{name}.golden"


def _expected_exit_codes() -> dict[str, int]:
    return json.loads(EXIT_CODES.read_text(encoding="utf-8"))


def _check(name: str, actual: str, exit_code: int, stderr: str = "") -> None:
    """Compare with the golden, or rewrite it under CQA_UPDATE_GOLDENS=1."""
    if name.endswith(".json"):
        actual = normalize_json(actual)
    error_line = stderr.splitlines()[-1] + "\n" if stderr else ""
    if UPDATE:
        _golden(name).write_text(actual, encoding="utf-8")
        if error_line:
            _golden(f"{name}.stderr").write_text(error_line, encoding="utf-8")
        codes = _expected_exit_codes() if EXIT_CODES.exists() else {}
        codes[name] = exit_code
        EXIT_CODES.write_text(json.dumps(codes, indent=2) + "\n", encoding="utf-8")
        return
    assert actual == _golden(name).read_text(encoding="utf-8"), name
    if error_line:
        assert error_line == _golden(f"{name}.stderr").read_text(encoding="utf-8"), name
    assert exit_code == _expected_exit_codes()[name], name


@pytest.mark.parametrize(("name", "label", "args"), CASES, ids=[case[0] for case in CASES])
def test_cli_output_matches_the_pre_refactor_golden(tmp_path, name, label, args):
    project = materialize(_FIXTURES[label], tmp_path / label)
    (tmp_path / "cache").mkdir()
    argv = [str(project), "--offline", *(arg.replace("{tmp}", str(tmp_path)) for arg in args)]

    result = CliRunner().invoke(main, argv)

    _check(name, result.stdout, result.exit_code, result.stderr)


def test_write_baseline_output_and_file_match_the_goldens(tmp_path):
    """The committed baseline.json was written from the project without late.py."""
    project = materialize(PROJECT_FIXTURE, tmp_path / PROJECT, skip=frozenset({"late.py"}))
    written = tmp_path / "baseline.json"

    result = CliRunner().invoke(main, [str(project), "--offline", "--write-baseline", str(written)])

    _check(f"{PROJECT}.write_baseline.text", result.stdout, result.exit_code)
    if UPDATE:
        shutil.copyfile(written, BASELINE)
    assert written.read_bytes() == BASELINE.read_bytes()


def test_every_golden_file_belongs_to_a_case():
    expected = {f"{name}.golden" for name, _, _ in CASES}
    expected |= {
        f"{PROJECT}.write_baseline.text.golden",
        f"{PROJECT}.unknown_format.text.stderr.golden",
        BASELINE.name,
        MANIFEST.name,
        EXIT_CODES.name,
        "README.md",
    }

    present = {path.name for path in GOLDEN.iterdir() if path.is_file()}

    assert present == expected, sorted(present ^ expected)


def test_golden_fixture_holds_no_source_the_repository_gate_would_read():
    stray = sorted(
        path.relative_to(PROJECT_FIXTURE).as_posix()
        for path in PROJECT_FIXTURE.rglob("*")
        if path.is_file() and path.suffix != SAMPLE_SUFFIX
    )
    assert stray == [], stray


# --- AnalysisOptions itself -------------------------------------------------

CATALOG_DESTS = {"explain", "list_rules", "language"}


def _parser_dests() -> set[str]:
    parser = build_parser()
    return {
        action.dest
        for action in parser._actions
        if not isinstance(action, (argparse._HelpAction, argparse._VersionAction))
    }


def test_options_fields_are_exactly_the_analysis_flags_of_the_parser():
    """Adding a flag to the parser without a field (or the reverse) fails here."""
    fields = {field.name for field in dataclasses.fields(AnalysisOptions)}

    assert fields == _parser_dests() - CATALOG_DESTS


def test_options_defaults_equal_the_parser_defaults():
    """``AnalysisOptions(project_path=p)`` is what a bare ``code-quality-analyzer p`` parses to."""
    namespace = build_parser().parse_args([str(ROOT)])

    assert AnalysisOptions.from_namespace(namespace) == AnalysisOptions(project_path=str(ROOT))


def test_options_are_built_from_the_namespace_and_frozen():
    namespace = build_parser().parse_args(
        [str(ROOT), "-f", "sarif", "--strict", "--fail-under", "6.5", "--max-files", "9"]
    )

    options = AnalysisOptions.from_namespace(namespace)

    assert options.project_path == str(ROOT)
    assert options.output_format == "sarif"
    assert options.strict is True
    assert options.fail_under == 6.5
    assert options.max_files == 9
    assert options.anonymize is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        options.strict = False  # type: ignore[misc]
