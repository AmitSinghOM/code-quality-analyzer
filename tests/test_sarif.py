"""Deterministic SARIF 2.1.0 reporting contracts."""

import json

import pytest
from click.testing import CliRunner

from analyzer.__main__ import EXIT_FINDINGS, EXIT_OK, main
from analyzer.reporters import AnalysisReport, SarifReporter, SarifRun
from analyzer.rule_metadata import builtin_rule_ids


def _finding(
    rule_id="PY-COR-001",
    path="pkg/service.py",
    line=2,
    column=3,
    severity="warning",
    message="Mutable default argument.",
    end_line=None,
    end_column=None,
):
    location = {"path": path, "line": line, "column": column}
    if end_line is not None:
        location["end_line"] = end_line
    if end_column is not None:
        location["end_column"] = end_column
    return {
        "rule_id": rule_id,
        "category": "correctness",
        "severity": severity,
        "confidence": "high",
        "message": message,
        "location": location,
        "remediation": "Apply the documented remediation.",
    }


def _run(*findings):
    return SarifRun(
        analyzer_version="2.25.0",
        configuration_fingerprint="a" * 64,
        analysis_health={"complete": True, "authoritative": True},
        privacy={
            "anonymized": False,
            "paths_redacted": False,
            "offline_enforced": True,
        },
        baseline_selection={"newFindingsOnly": False},
        findings=tuple(findings),
    )


def _render(run):
    rendered = SarifReporter().render(AnalysisReport(sarif=run))
    return rendered, json.loads(rendered)


def test_empty_sarif_run_has_one_deterministic_run():
    rendered, payload = _render(_run())

    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(payload["runs"]) == 1
    run = payload["runs"][0]
    assert run["tool"]["driver"] == {
        "name": "Code Quality Analyzer",
        "rules": [],
        "semanticVersion": "2.25.0",
    }
    assert run["results"] == []
    assert run["properties"]["configurationFingerprint"] == "a" * 64
    assert rendered == SarifReporter().render(AnalysisReport(sarif=_run()))


def test_rules_results_levels_ranges_and_indexes_are_stable():
    python_finding = _finding(
        path="z module.py",
        severity="error",
        end_line=3,
        end_column=8,
    )
    go_finding = _finding(
        rule_id="GO-COR-001",
        path="cmd\\worker.go",
        line=7,
        column=18,
        message="Ignored error.",
    )

    _, payload = _render(_run(python_finding, go_finding))
    driver = payload["runs"][0]["tool"]["driver"]
    results = payload["runs"][0]["results"]

    assert [rule["id"] for rule in driver["rules"]] == [
        "GO-COR-001",
        "PY-COR-001",
    ]
    assert driver["rules"][1]["defaultConfiguration"]["level"] == "warning"
    assert [result["ruleId"] for result in results] == [
        "GO-COR-001",
        "PY-COR-001",
    ]
    assert [result["ruleIndex"] for result in results] == [0, 1]
    assert results[1]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == "cmd/worker.go"
    assert results[1]["locations"][0]["physicalLocation"]["region"] == {
        "endColumn": 8,
        "endLine": 3,
        "startColumn": 3,
        "startLine": 2,
    }


def test_sarif_is_byte_identical_for_permuted_findings_and_keeps_duplicates():
    first = _finding(path="b.py", message="Second")
    second = _finding(path="a.py", message="First")

    forward, payload = _render(_run(first, second, second))
    reverse, _ = _render(_run(second, first, second))

    assert forward == reverse
    assert len(payload["runs"][0]["results"]) == 3


@pytest.mark.parametrize(
    "path",
    ["", "/private/project.py", "../private.py", "pkg/../../private.py", "file.py\x00x"],
)
def test_sarif_rejects_unsafe_artifact_paths(path):
    with pytest.raises(ValueError, match="SARIF artifact paths"):
        _render(_run(_finding(path=path)))


@pytest.mark.parametrize("path", ["file:///tmp/a.py", "https://host/a.py", "C:\\a.py"])
def test_sarif_rejects_scheme_and_drive_paths(path):
    with pytest.raises(ValueError, match="project-relative"):
        _render(_run(_finding(path=path)))


def test_sarif_encodes_relative_uri_characters():
    _, payload = _render(_run(_finding(path="pkg/a file#1.py")))
    uri = payload["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"]

    assert uri == "pkg/a%20file%231.py"


def test_catalog_covers_every_current_builtin_rule():
    assert builtin_rule_ids() == (
        "GO-COR-001",
        "PY-COR-001",
        "PY-COR-002",
        "PY-COR-003",
        "PY-COR-004",
        "PY-COR-005",
        "PY-COR-006",
        "PY-MAINT-001",
        "PY-MAINT-002",
        "PY-MAINT-003",
        "PY-MAINT-004",
        "PY-MAINT-005",
        "PY-PKG-001",
        "PY-PKG-002",
        "PY-PKG-003",
        "PY-PKG-004",
        "PY-PKG-005",
        "PY-PKG-006",
    )


def test_sarif_fails_closed_for_uncataloged_rule():
    with pytest.raises(ValueError, match="Missing built-in rule metadata"):
        _render(_run(_finding(rule_id="PLUGIN-001")))


def test_cli_emits_valid_sarif_before_finding_gate(project):
    root = project({
        ".code-quality.toml": (
            '[rules."PY-COR-001"]\nseverity = "error"\n'
        ),
        "pkg/a file.py": "def add(items=[]):\n    return items\n",
    })

    result = CliRunner().invoke(main, [
        str(root), "-f", "sarif", "--offline", "--fail-on", "warning",
    ])
    payload = json.loads(result.output)
    sarif_run = payload["runs"][0]

    assert result.exit_code == EXIT_FINDINGS
    assert sarif_run["results"][0]["level"] == "error"
    assert sarif_run["tool"]["driver"]["rules"][0][
        "defaultConfiguration"
    ]["level"] == "warning"
    assert sarif_run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == "pkg/a%20file.py"
    assert sarif_run["properties"]["privacy"]["offline_enforced"] is True
    assert str(root) not in result.output
    assert "file://" not in result.output


def test_cli_sarif_baseline_filters_before_render_and_gate(project, tmp_path):
    root = project({
        "existing.py": "def existing(items=[]):\n    return items\n",
    })
    baseline = tmp_path / "baseline.json"
    written = CliRunner().invoke(main, [
        str(root), "--write-baseline", str(baseline),
    ])
    assert written.exit_code == EXIT_OK

    unchanged = CliRunner().invoke(main, [
        str(root), "-f", "sarif", "--baseline", str(baseline),
        "--new-findings-only", "--fail-on", "warning",
    ])
    unchanged_payload = json.loads(unchanged.output)
    assert unchanged.exit_code == EXIT_OK
    assert unchanged_payload["runs"][0]["results"] == []

    (root / "new.py").write_text(
        "def introduced(cache={}):\n    return cache\n",
        encoding="utf-8",
    )
    changed = CliRunner().invoke(main, [
        str(root), "-f", "sarif", "--baseline", str(baseline),
        "--new-findings-only", "--fail-on", "warning",
    ])
    changed_payload = json.loads(changed.output)

    assert changed.exit_code == EXIT_FINDINGS
    assert len(changed_payload["runs"][0]["results"]) == 1
    assert changed_payload["runs"][0]["properties"]["baselineSelection"][
        "newFindingsOnly"
    ] is True


def test_cli_sarif_redaction_and_anonymization_are_privacy_bounded(project):
    root = project({
        "z/private.py": "def proprietary(secret_items=[]):\n    return secret_items\n",
        "a/internal.py": "def internal(private_cache={}):\n    return private_cache\n",
    })

    redacted = CliRunner().invoke(main, [
        str(root), "-f", "sarif", "--redact-paths",
    ])
    redacted_payload = json.loads(redacted.output)
    redacted_uris = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in redacted_payload["runs"][0]["results"]
    ]
    assert redacted.exit_code == EXIT_OK
    assert redacted_uris == ["internal.py", "private.py"]

    anonymous = CliRunner().invoke(main, [
        str(root), "-f", "sarif", "--anonymize", "--offline",
    ])
    anonymous_payload = json.loads(anonymous.output)
    anonymous_results = anonymous_payload["runs"][0]["results"]
    anonymous_uris = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in anonymous_results
    ]

    assert anonymous.exit_code == EXIT_OK
    assert anonymous_uris == ["file-0001", "file-0002"]
    assert all(
        result["message"]["text"] == "Finding reported by PY-COR-001."
        for result in anonymous_results
    )
    rendered = anonymous.output
    for sensitive in (
        "z/private.py",
        "a/internal.py",
        "proprietary",
        "secret_items",
        "private_cache",
    ):
        assert sensitive not in rendered
    for forbidden in (
        '"artifacts"',
        '"environmentVariables"',
        '"fingerprints"',
        '"invocations"',
        '"partialFingerprints"',
        '"snippet"',
    ):
        assert forbidden not in rendered


def test_cli_sarif_mixed_languages_are_sorted(project):
    root = project({
        "z.py": "def add(items=[]):\n    return items\n",
        "a.go": (
            "package worker\n\n"
            'import "os"\n\n'
            "func load(path string) []byte {\n"
            "    data, _ := os.ReadFile(path)\n"
            "    return data\n"
            "}\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "sarif"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert [
        item["ruleId"] for item in payload["runs"][0]["results"]
    ] == ["GO-COR-001", "PY-COR-001"]
