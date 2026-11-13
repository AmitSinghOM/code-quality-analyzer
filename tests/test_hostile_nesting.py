"""Hostile deeply nested TOML/JSON inputs take the existing invalid-input path.

``tomllib`` and ``json`` recurse per nesting level, so a 20000-deep ``[[[[``
raises ``RecursionError`` instead of the decode error the loaders expected.
Each untrusted parser (project config, ``pyproject.toml`` metadata,
changed-lines manifest, baseline) must report exactly what it reports for
any other unreadable input: same message, same exit code, no traceback, and
no new exit code (0-6 are a documented contract).
"""

from __future__ import annotations

import pytest
from clirunner import CliRunner

from cqa_analyzer.__main__ import EXIT_OK, main

DEPTH = 20_000
NESTED = "[" * DEPTH


def run(args):
    return CliRunner().invoke(main, args)


@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param(f"[analysis]\nexclude = {NESTED}\n", id="nested-array"),
        pytest.param(f"[analysis]\nexclude = {NESTED}{']' * DEPTH}\n", id="closed-array"),
    ],
)
def test_nested_project_config_is_invalid_toml(project, hostile):
    plain_invalid = project(
        {".code-quality.toml": "[analysis\n", "module.py": "VALUE = 1\n"}
    )
    expected = run([str(plain_invalid)])

    root = project({".code-quality.toml": hostile, "module.py": "VALUE = 1\n"})
    result = run([str(root)])

    assert expected.exit_code != EXIT_OK
    assert result.exit_code == expected.exit_code
    assert "Configuration is not valid TOML" in result.output
    assert "Traceback" not in result.output
    assert "RecursionError" not in result.output


def test_nested_pyproject_is_reported_as_invalid_metadata(project):
    plain_invalid = project(
        {"pyproject.toml": "[project\n", "module.py": "VALUE = 1\n"}
    )
    expected = run([str(plain_invalid), "--output-format", "json"])

    root = project(
        {
            "pyproject.toml": f"[project]\nkeywords = {NESTED}\n",
            "module.py": "VALUE = 1\n",
        }
    )
    result = run([str(root), "--output-format", "json"])

    assert result.exit_code == expected.exit_code
    assert '"PY-PKG-003"' in result.output
    assert "Traceback" not in result.output
    assert "RecursionError" not in result.output


def test_nested_changed_lines_manifest_is_invalid_json(project, tmp_path):
    root = project({"module.py": "VALUE = 1\n"})
    plain_invalid = tmp_path / "plain.json"
    plain_invalid.write_text("not json", encoding="utf-8")
    expected = run([str(root), "--changed-lines-manifest", str(plain_invalid)])

    manifest = tmp_path / "nested.json"
    manifest.write_text(NESTED, encoding="utf-8")
    result = run([str(root), "--changed-lines-manifest", str(manifest)])

    assert expected.exit_code != EXIT_OK
    assert result.exit_code == expected.exit_code
    assert "not readable valid UTF-8 JSON" in result.output
    assert "Traceback" not in result.output
    assert "RecursionError" not in result.output


def test_nested_baseline_is_invalid_json(project, tmp_path):
    root = project({"module.py": "VALUE = 1\n"})
    plain_invalid = tmp_path / "plain.json"
    plain_invalid.write_text("not json", encoding="utf-8")
    expected = run([str(root), "--baseline", str(plain_invalid)])

    baseline = tmp_path / "nested.json"
    baseline.write_text(NESTED, encoding="utf-8")
    result = run([str(root), "--baseline", str(baseline)])

    assert expected.exit_code != EXIT_OK
    assert result.exit_code == expected.exit_code
    assert "Baseline is not readable valid JSON" in result.output
    assert "Traceback" not in result.output
    assert "RecursionError" not in result.output


@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            {"Cargo.toml": f"[package]\nname = {NESTED}\n", "src/main.rs": "fn main() {}\n"},
            id="cargo-toml",
        ),
        pytest.param(
            {"package.json": NESTED, "index.ts": "export const value = 1;\n"},
            id="package-json",
        ),
        pytest.param(
            {
                "build.gradle": "plugins { id 'java' }\n",
                "gradle/libs.versions.toml": f"[libraries]\nguava = {NESTED}\n",
                "src/main/java/App.java": "class App {}\n",
            },
            id="gradle-version-catalog",
        ),
    ],
)
def test_nested_adapter_manifest_does_not_crash_the_scan(project, files):
    root = project(files)

    result = run([str(root), "--output-format", "json"])

    assert result.exception is None, repr(result.exception)
    assert "Traceback" not in result.output
    assert "RecursionError" not in result.output
