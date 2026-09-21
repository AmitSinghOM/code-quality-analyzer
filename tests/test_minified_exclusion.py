"""Minified / bundled asset exclusion (3.2.1).

A vendored typedoc bundle in ioredis's ``docs/assets/main.js`` (42 KB on one
line, plain ``.js`` name) produced four genuine-but-unactionable
``TS-SEC-003`` findings in the 3.2.0 calibration run. Discovery now leaves
such files out — by name (``*.min.js``, ``*.bundle.js``) or by content (a
5 000-character line in a file whose lines average 500+) — and accounts for
them separately from skips, so the analysis stays authoritative.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cqa_analyzer.discovery import (
    MINIFIED_AVERAGE_LINE_LENGTH,
    MINIFIED_LINE_LENGTH,
    DiscoveryReport,
    generated_reason,
    iter_source_files,
)
from cqa_analyzer.plugins import create_default_registry

from tests.test_cli import run  # noqa: E402 - shared CLI harness


def _extensions() -> tuple[str, ...]:
    return tuple(sorted(create_default_registry()._extensions))


def _bundle(statements: int = 400) -> str:
    return (
        '"use strict";'
        + ";".join(f"var v{i}=function(e){{e.innerHTML=x{i}}}" for i in range(statements))
        + "\n"
    )


# ---- classifier -------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "vendor.min.js",
        "app-min.js",
        "lib.bundle.js",
        "lib.pack.mjs",
        "ui.umd.cjs",
        "x.min.ts",
        "X.MIN.JS",
    ],
)
def test_minified_names(name):
    assert generated_reason(name, "short\n") == "minified_name"


@pytest.mark.parametrize("name", ["min.js", "admin.js", "bundle.ts", "minimal.js", "app.min.py"])
def test_ordinary_names_are_not_minified(name):
    assert generated_reason(name, "short\n") is None


def test_single_line_bundle_is_minified_content():
    assert generated_reason("main.js", _bundle()) == "minified_content"
    assert len(_bundle()) >= MINIFIED_LINE_LENGTH


def test_one_long_data_line_inside_ordinary_code_is_kept():
    source = "\n".join(f"const line{i} = {i};" for i in range(300))
    source += "\nconst TABLE = [" + ",".join("1" for _ in range(3000)) + "];\n"
    assert max(map(len, source.splitlines())) >= MINIFIED_LINE_LENGTH
    assert len(source) / len(source.splitlines()) < MINIFIED_AVERAGE_LINE_LENGTH
    assert generated_reason("table.js", source) is None


def test_few_long_lines_are_minified_even_with_low_average():
    source = ("x" * (MINIFIED_LINE_LENGTH + 1)) + "\n" + "\n" * 8
    assert generated_reason("out.js", source) == "minified_content"


def test_empty_file_is_not_minified():
    assert generated_reason("empty.js", "") is None


# ---- discovery accounting ---------------------------------------------------


def _project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "docs" / "assets").mkdir(parents=True)
    (tmp_path / "src" / "app.js").write_text(
        "export function f(el, html) {\n  el.innerHTML = html;\n}\n"
    )
    (tmp_path / "src" / "vendor.min.js").write_text("function f(a){a.innerHTML=b}\n")
    (tmp_path / "docs" / "assets" / "main.js").write_text(_bundle())
    return tmp_path


def test_discovery_excludes_and_accounts_without_marking_a_skip(tmp_path: Path):
    root = _project(tmp_path)
    report = DiscoveryReport()
    found = [
        p.relative_to(root).as_posix()
        for p, _ in iter_source_files(root, _extensions(), report=report)
    ]
    assert found == ["src/app.js"]
    assert report.total_skipped == 0
    assert report.excluded_generated == {"minified_content": 1, "minified_name": 1}
    assert report.excluded_generated_examples == {
        "minified_content": ["docs/assets/main.js"],
        "minified_name": ["src/vendor.min.js"],
    }
    assert report.source_candidates == 3  # considered, then deliberately left out
    payload = report.as_dict()
    assert payload["excluded_generated"] == {"minified_content": 1, "minified_name": 1}


def test_cli_reports_exclusion_and_stays_authoritative(tmp_path: Path):
    root = _project(tmp_path)
    result = run([str(root), "--offline", "-f", "json"])
    payload = json.loads(result.output)
    health = payload["scan_health"]
    assert health["files_found"] == 1
    assert health["excluded_generated"] == {"minified_content": 1, "minified_name": 1}
    assert payload["analysis_health"]["authoritative"] is True
    assert [f["location"]["path"] for f in payload["findings"] if f["rule_id"] == "TS-SEC-003"] == [
        "src/app.js"
    ]

    verbose = run([str(root), "--offline", "-v"])
    assert "2 minified/bundled file(s) left out" in verbose.output
    assert "docs/assets/main.js" in verbose.output
    assert "vendor.min.js" in verbose.output


def test_anonymize_tokenizes_excluded_examples(tmp_path: Path):
    root = _project(tmp_path)
    result = run([str(root), "--offline", "-f", "json", "--anonymize"])
    health = json.loads(result.output)["scan_health"]
    for paths in health["excluded_generated_examples"].values():
        assert all(p.startswith("file-") for p in paths)
    assert "main.js" not in result.output


# ---- delegate parity --------------------------------------------------------


def test_preview_mirrors_the_name_rule_and_documents_the_content_rule(tmp_path: Path):
    from cqa_analyzer.config import load_config
    from cqa_analyzer.delegate import plan_file, preview

    root = _project(tmp_path)
    report = preview(root)
    planned = {item["path"] for item in report["planned"]}
    assert "src/vendor.min.js" not in planned
    assert report["excluded"]["minified_name"]["examples"] == ["src/vendor.min.js"]
    # Content cannot be previewed without reading: the bundle is planned here
    # and left out at scan time (scan_health.excluded_generated).
    assert "docs/assets/main.js" in planned
    plan = plan_file("src/vendor.min.js", create_default_registry(), load_config(root), root=root)
    assert (plan.selected, plan.reason) == (False, "minified_name")


# ---- Review 5, A4: the content rule is JS/TS-only -----------------------------
# On 3.2.1 these two hand-written files came back "minified_content" and were
# silently left out of every rule, including the security family.


def _one_long_literal(prefix: str, suffix: str, lines_around: int) -> str:
    body = "\n".join(f"{prefix}{i}{suffix}" for i in range(lines_around))
    return f'{body}\nBLOB = "{"A" * 6_000}"\n'


@pytest.mark.parametrize(
    "name, source",
    [
        ("constants.py", _one_long_literal("x", " = 1", 2)),
        (
            "schema.go",
            "package db\n\nconst ddl = `"
            + "CREATE TABLE t (id int); " * 300
            + "`\n"
            + "var _ = ddl\n" * 8,
        ),
        ("Blob.java", 'class Blob { static final String B = "' + "A" * 6_000 + '"; }\n'),
        ("blob.rs", 'const B: &str = "' + "A" * 6_000 + '";\n'),
    ],
)
def test_hand_written_non_js_files_with_one_long_literal_are_analyzed(name, source):
    assert generated_reason(name, source) is None


@pytest.mark.parametrize("name", ["main.js", "app.mjs", "widget.tsx", "lib.cts"])
def test_js_family_content_rule_still_applies(name):
    assert generated_reason(name, _bundle()) == "minified_content"


def test_non_js_long_literal_file_is_scanned_by_the_cli(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    blob = "A" * 6_000
    (root / "constants.py").write_text(
        "import subprocess\n"
        f'BLOB = "{blob}"\n'
        "def f(u):\n"
        '    subprocess.run("ls " + u, shell=True)\n'
    )
    result = run(["--output-format", "json", "--offline", str(root)])
    payload = json.loads(result.output)
    assert payload["scan_health"]["excluded_generated"] == {}
    assert "PY-SEC-002" in {f["rule_id"] for f in payload["findings"]}
