"""End-to-end CLI contract for ADR 005 (report schema 1.15.0).

Path-scoped rule policy (E8) and baseline debt visibility (E6) joined into one
report: ``findings[].policy_source``, ``scan_health.policy_dropped``,
``baseline.unmatched_count`` / ``baseline.matched``,
``changed_lines.files_config_excluded``, the ``--strict`` security line, and
the three privacy modes, each checked through the real ``main`` entry point in
JSON, SARIF and text. The unit halves live in ``test_config_overrides.py``,
``test_scanner_policy.py``, ``test_policy_privacy.py`` and ``test_baseline.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest
from clirunner import CliRunner

from cqa_analyzer import REPORT_SCHEMA_VERSION
from cqa_analyzer.__main__ import (
    EXIT_COVERAGE_GAP,
    EXIT_FINDINGS,
    EXIT_OK,
    main,
)
from cqa_analyzer.baseline import finding_fingerprint_v1
from cqa_analyzer.scanner import CodeScanner

FIXTURES = Path(__file__).parent / "fixtures"
REPORT_SCHEMA = json.loads((FIXTURES.parents[1] / "docs" / "report-schema-1.15.0.json").read_text())
SARIF_SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text())
ANSI = re.compile(r"\x1b\[[0-9;]*m")

MUTABLE_DEFAULT = "def f(cache={}):\n    return cache\n"  # PY-COR-001 (warning)
UNSAFE_PICKLE = "import pickle\nx = pickle.loads(blob)\n"  # PY-SEC-001, CWE-502
SUPPRESSED_PICKLE = (
    'import pickle\nx = pickle.loads(blob)  # cqa: ignore=PY-SEC-001 reason="trusted blob"\n'
)

# Four trees, two policies, one of them on a security rule.
OVERRIDES = """
[overrides."ext/**"]
disabled = ["PY-SEC-001"]

[overrides."tests/**"]
severity = { "PY-COR-001" = "note" }

[overrides."tests/slow/**"]
severity = { "PY-COR-001" = "error" }
"""
FILES = {
    "src/app.py": MUTABLE_DEFAULT,
    "ext/lib.py": UNSAFE_PICKLE + MUTABLE_DEFAULT,
    "tests/test_app.py": MUTABLE_DEFAULT,
    "tests/slow/test_db.py": MUTABLE_DEFAULT,
}
RAW_GLOBS = ("ext/**", "tests/**", "tests/slow/**")


def _run(root, *args):
    return CliRunner().invoke(main, [str(root), "--offline", *args])


def _json(root, *args):
    result = _run(root, "-f", "json", *args)
    return result, json.loads(result.output)


def _sarif(root, *args):
    result = _run(root, "-f", "sarif", *args)
    return result, json.loads(result.output)


def _strings(value):
    """Every string anywhere in a JSON-like value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def _by_path(payload):
    return {
        (item["location"]["path"], item["rule_id"]): (item["severity"], item["policy_source"])
        for item in payload["findings"]
    }


def _sarif_sources(sarif):
    run = sarif["runs"][0]
    return {
        (
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            result["ruleId"],
        ): (result["level"], result["properties"]["policySource"])
        for result in run["results"]
        if "suppressions" not in result
    }


# --- Plain mode: JSON, SARIF and text agree -----------------------------------


def test_json_and_sarif_name_the_same_policy_source_per_finding(project):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    result, payload = _json(root)
    sarif_result, sarif = _sarif(root)

    assert result.exit_code == EXIT_OK
    assert sarif_result.exit_code == EXIT_OK
    assert payload["schema_version"] == REPORT_SCHEMA_VERSION == "1.15.0"
    expected = {
        ("src/app.py", "PY-COR-001"): ("warning", "project"),
        ("ext/lib.py", "PY-COR-001"): ("warning", "project"),
        ("tests/test_app.py", "PY-COR-001"): ("note", "override:tests/**"),
        # Longest literal prefix wins the overlap: tests/slow/** beats tests/**.
        ("tests/slow/test_db.py", "PY-COR-001"): ("error", "override:tests/slow/**"),
    }
    assert _by_path(payload) == expected
    assert _sarif_sources(sarif) == expected
    # The security drop is counted, never listed, in both.
    dropped = payload["scan_health"]["policy_dropped"]
    assert dropped == {
        "count": 1,
        "by_rule": {"PY-SEC-001": 1},
        "by_source": {"override:ext/**": 1},
        "security": 1,
    }
    assert sarif["runs"][0]["properties"]["policyDropped"] == dropped
    assert all(item["rule_id"] != "PY-SEC-001" for item in payload["findings"])
    assert all(result["ruleId"] != "PY-SEC-001" for result in sarif["runs"][0]["results"])


def test_json_validates_against_schema_1_15_0_and_sarif_against_2_1_0(project):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    manifest = root.parent / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "files": [{"path": "src/app.py", "ranges": [{"start_line": 1, "end_line": 2}]}],
            }
        ),
        encoding="utf-8",
    )
    for mode in ((), ("--redact-paths",), ("--anonymize",)):
        _, payload = _json(
            root, "--write-baseline", str(root.parent / "b.json"), "--changed-lines-manifest",
            str(manifest), *mode,
        )
        jsonschema.Draft7Validator(REPORT_SCHEMA).validate(payload)
        _, sarif = _sarif(root, "--baseline", str(root.parent / "b.json"), *mode)
        jsonschema.Draft7Validator(SARIF_SCHEMA).validate(sarif)


def test_text_report_names_the_drop_and_strict_adds_the_security_line(project):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    plain = _run(root)
    strict = _run(root, "--strict")

    assert plain.exit_code == EXIT_OK
    assert strict.exit_code == EXIT_OK  # a declared, pinned policy is not a coverage gap
    plain_text = ANSI.sub("", plain.output)
    strict_text = ANSI.sub("", strict.output)
    assert "1 finding(s) dropped by rule policy (PY-SEC-001=1)" in plain_text
    assert "Policy-disabled security findings" not in plain_text
    assert "Policy-disabled security findings: 1" in strict_text


def test_strict_security_line_is_absent_when_no_security_rule_is_dropped(project):
    toml = '[overrides."tests/**"]\ndisabled = ["PY-COR-001"]\n'
    root = project({**FILES, ".code-quality.toml": toml})
    result = _run(root, "--strict")

    text = ANSI.sub("", result.output)
    assert result.exit_code == EXIT_OK
    assert "dropped by rule policy (PY-COR-001=2)" in text
    assert "Policy-disabled security findings" not in text


# --- Gates ---------------------------------------------------------------------


def test_dropped_and_demoted_findings_do_not_gate_but_promoted_ones_do(project):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    # vendor's PY-SEC-001 is dropped and tests/ is demoted to note; the
    # remaining warnings and the promoted error still fail --fail-on.
    assert _run(root, "--fail-on", "error").exit_code == EXIT_FINDINGS
    assert _run(root, "--fail-on", "warning").exit_code == EXIT_FINDINGS

    # Same tree without the project warnings: only the demoted note and the
    # dropped security finding remain, so the gate passes.
    for name in ("src/app.py", "tests/slow/test_db.py"):
        (root / name).unlink()
    (root / "ext/lib.py").write_text(UNSAFE_PICKLE, encoding="utf-8")
    result, payload = _json(root, "--fail-on", "warning")
    assert result.exit_code == EXIT_OK
    assert [item["severity"] for item in payload["findings"]] == ["note"]
    assert payload["scan_health"]["policy_dropped"]["security"] == 1


def test_without_overrides_every_source_is_project_and_nothing_is_dropped(project):
    root = project(FILES)
    _, payload = _json(root)
    assert {item["policy_source"] for item in payload["findings"]} == {"project"}
    assert payload["scan_health"]["policy_dropped"] == {
        "count": 0,
        "by_rule": {},
        "by_source": {},
        "security": 0,
    }
    # No [overrides] table: the fingerprint is the one a bare configuration has.
    golden = json.loads((FIXTURES / "analysis-authority.json").read_text(encoding="utf-8"))
    assert payload["configuration_fingerprint"] == golden["configuration_fingerprint"]


def test_hidden_identity_path_decides_policy_under_redaction(project):
    """Two files both display as ``app.py`` when redacted; the override applies
    to the one under ``tests/`` only, because matching uses the identity path."""
    files = {
        "src/app.py": MUTABLE_DEFAULT,
        "tests/app.py": MUTABLE_DEFAULT,
        ".code-quality.toml": '[overrides."tests/**"]\nseverity = { "PY-COR-001" = "note" }\n',
    }
    _, payload = _json(project(files), "--redact-paths")
    rows = sorted((f["severity"], f["policy_source"]) for f in payload["findings"])
    assert rows == [("note", "override:**"), ("warning", "project")]
    assert {f["location"]["path"] for f in payload["findings"]} == {"app.py"}


# --- Privacy -------------------------------------------------------------------


def test_redact_paths_keeps_only_the_last_glob_segment_everywhere(project):
    toml = (
        '[overrides."ext/libs/*.py"]\ndisabled = ["PY-SEC-001"]\n'
        '[overrides."tests/**/*_app.py"]\nseverity = { "PY-COR-001" = "note" }\n'
    )
    files = {
        "ext/libs/lib.py": UNSAFE_PICKLE,
        "tests/unit/test_app.py": MUTABLE_DEFAULT,
        ".code-quality.toml": toml,
    }
    root = project(files)
    _, payload = _json(root, "--redact-paths")
    _, sarif = _sarif(root, "--redact-paths")
    text = ANSI.sub("", _run(root, "--redact-paths").output)

    assert [f["policy_source"] for f in payload["findings"]] == ["override:*_app.py"]
    assert payload["scan_health"]["policy_dropped"]["by_source"] == {"override:*.py": 1}
    assert sarif["runs"][0]["properties"]["policyDropped"]["by_source"] == {"override:*.py": 1}
    for leaked in ("ext/libs", "tests/**", "ext/", "/*.py"):
        assert leaked not in json.dumps(payload)
        assert leaked not in json.dumps(sarif)
        assert leaked not in text


def _json_policy(payload):
    return (
        [f["policy_source"] for f in payload["findings"]],
        payload["scan_health"]["policy_dropped"],
    )


def _sarif_policy(payload):
    run = payload["runs"][0]
    return (
        [r["properties"]["policySource"] for r in run["results"]],
        run["properties"]["policyDropped"],
    )


TOKEN = re.compile(r"override:file-\d{4}")


@pytest.mark.parametrize(("fmt", "extract"), [("json", _json_policy), ("sarif", _sarif_policy)])
def test_anonymize_leaves_no_raw_glob_anywhere_and_merges_tokens(project, fmt, extract):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    result = _run(root, "-f", fmt, "--anonymize", "--write-baseline", str(root.parent / "b.json"))
    payload = json.loads(result.output)

    assert _leaks(payload, (*RAW_GLOBS, "ext/", "tests/", "src/")) == []
    sources, dropped = extract(payload)
    assert "project" in sources
    assert _only_tokens(s for s in sources if s != "project")
    assert dropped["count"] == 1
    assert dropped["security"] == 1
    assert _only_tokens(dropped["by_source"])


def _leaks(payload, needles) -> list[str]:
    """Strings anywhere in ``payload`` (keys included) containing a needle."""
    return [s for s in _strings(payload) if any(needle in s for needle in needles)]


def _only_tokens(values) -> bool:
    """Non-empty, and every value is an ``override:file-NNNN`` token."""
    values = list(values)
    return bool(values) and all(TOKEN.fullmatch(value) for value in values)


def test_anonymized_text_report_carries_no_raw_glob(project):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    text = ANSI.sub("", _run(root, "--anonymize", "--strict").output)
    assert "Policy-disabled security findings: 1" in text
    assert not any(glob in text for glob in RAW_GLOBS)
    assert "ext" not in text and "tests/" not in text


# --- Baseline (E6) -------------------------------------------------------------


def test_baseline_unmatched_count_tells_hidden_debt_from_fixed_debt(project, tmp_path):
    """Baseline of three findings; then fix one, policy-drop one, keep one.

    Schema 2.0.0 keys identity on the line's text, so a same-line directive
    changes the entry (see the legacy test below for the suppressed case)."""
    root = project({"a.py": MUTABLE_DEFAULT, "b.py": UNSAFE_PICKLE, "c.py": UNSAFE_PICKLE})
    baseline = tmp_path / "baseline.json"
    written = _run(root, "--write-baseline", str(baseline))
    assert written.exit_code == EXIT_OK
    assert len(json.loads(baseline.read_text())["fingerprints"]) == 3

    (root / "a.py").write_text("def f(cache=None):\n    return cache\n", encoding="utf-8")
    (root / ".code-quality.toml").write_text(
        '[overrides."c.py"]\ndisabled = ["PY-SEC-001"]\n', encoding="utf-8"
    )
    result, payload = _json(root, "--baseline", str(baseline))
    text = ANSI.sub("", _run(root, "--baseline", str(baseline)).output)

    assert result.exit_code == EXIT_OK
    assert [item["location"]["path"] for item in payload["findings"]] == ["b.py"]
    assert payload["baseline"] == {
        "loaded": True,
        "written": False,
        "schema_version": "2.0.0",
        "known_fingerprints": 3,
        "current_findings": 1,
        "new_findings": 0,
        "unmatched_count": 1,
        "matched": {"active": 1, "suppressed": 0, "policy_dropped": 1},
    }
    assert "Unmatched (prune candidates): 1" in text
    assert "Hidden by policy: 1" in text
    # The baseline file is untouched: nothing prunes automatically.
    assert len(json.loads(baseline.read_text())["fingerprints"]) == 3


def test_legacy_baseline_counts_a_suppressed_and_a_dropped_entry_as_matched(project, tmp_path):
    """A 1.0.0 file keys identity on line, column and message, so a same-line
    directive keeps the entry; fix one, suppress one, policy-drop one."""
    root = project({"a.py": MUTABLE_DEFAULT, "b.py": UNSAFE_PICKLE, "c.py": UNSAFE_PICKLE})
    scanner = CodeScanner(root)
    scanner.scan()
    baseline = tmp_path / "legacy.json"
    baseline.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "fingerprint_algorithm": "sha256",
                "fingerprints": [finding_fingerprint_v1(item) for item in scanner.findings],
            }
        ),
        encoding="utf-8",
    )

    (root / "a.py").write_text("def f(cache=None):\n    return cache\n", encoding="utf-8")
    (root / "b.py").write_text(SUPPRESSED_PICKLE, encoding="utf-8")
    (root / ".code-quality.toml").write_text(
        '[overrides."c.py"]\ndisabled = ["PY-SEC-001"]\n', encoding="utf-8"
    )
    result, payload = _json(root, "--baseline", str(baseline))

    assert result.exit_code == EXIT_OK
    assert payload["findings"] == []
    assert len(payload["suppressed_findings"]) == 1
    assert payload["baseline"] == {
        "loaded": True,
        "written": False,
        "schema_version": "1.0.0",
        "known_fingerprints": 3,
        "current_findings": 0,
        "new_findings": 0,
        "unmatched_count": 1,
        "matched": {"active": 0, "suppressed": 1, "policy_dropped": 1},
    }


def test_baseline_written_under_overrides_has_the_unchanged_file_shape(project, tmp_path):
    root = project({**FILES, ".code-quality.toml": OVERRIDES})
    baseline = tmp_path / "baseline.json"
    result, payload = _json(root, "--write-baseline", str(baseline))
    stored = json.loads(baseline.read_text())

    assert result.exit_code == EXIT_OK
    assert set(stored) == {"schema_version", "fingerprint_algorithm", "fingerprints"}
    assert stored["schema_version"] == "2.0.0"
    # Writing without loading compares against nothing.
    assert payload["baseline"]["known_fingerprints"] == 0
    assert payload["baseline"]["unmatched_count"] == 0
    assert payload["baseline"]["matched"] == {"active": 0, "suppressed": 0, "policy_dropped": 0}
    # The dropped security finding was never active, so it is not stored...
    assert len(stored["fingerprints"]) == len(payload["findings"]) == 4
    _, again = _json(root, "--baseline", str(baseline))
    assert again["baseline"]["matched"] == {"active": 4, "suppressed": 0, "policy_dropped": 0}
    assert again["baseline"]["unmatched_count"] == 0
    # ...and a demotion to note keeps the fingerprint the warning had.
    demoted = next(f for f in payload["findings"] if f["severity"] == "note")
    assert demoted["fingerprint"] in stored["fingerprints"]


def test_new_findings_only_sarif_inherits_the_baseline_keys(project, tmp_path):
    root = project(FILES)
    baseline = tmp_path / "baseline.json"
    _run(root, "--write-baseline", str(baseline))
    _, sarif = _sarif(root, "--baseline", str(baseline), "--new-findings-only")
    selection = sarif["runs"][0]["properties"]["baselineSelection"]
    assert selection["newFindingsOnly"] is True
    assert selection["unmatched_count"] == 0
    assert selection["matched"] == {"active": 5, "suppressed": 0, "policy_dropped": 0}


# --- Changed lines and --strict (ADR 005, decision 7) -------------------------


def _manifest(path, *files):
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "files": [
                    {"path": name, "ranges": [{"start_line": 1, "end_line": 2}]}
                    for name in files
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_config_excluded_manifest_file_is_counted_not_a_coverage_gap(project, tmp_path):
    files = {
        "src/app.py": "VALUE = 1\n",
        "generated/schema.py": "VALUE = 2\n",
        ".code-quality.toml": '[analysis]\nexclude = ["generated/**"]\n',
    }
    root = project(files)
    manifest = _manifest(tmp_path / "m.json", "src/app.py", "generated/schema.py")
    result, payload = _json(root, "--changed-lines-manifest", str(manifest), "--strict")
    text = ANSI.sub("", _run(root, "--changed-lines-manifest", str(manifest), "--strict").output)

    assert result.exit_code == EXIT_OK
    assert payload["changed_lines"]["files_not_analyzed"] == 0
    assert payload["changed_lines"]["files_not_analyzed_examples"] == []
    assert payload["changed_lines"]["files_config_excluded"] == 1
    assert "1 changed file(s) in the manifest are excluded by the project configuration" in text
    assert "generated/schema.py" not in text  # a count, never a path


def test_manifest_file_outside_any_config_exclusion_is_still_a_gap(project, tmp_path):
    root = project({"src/app.py": "VALUE = 1\n"})
    manifest = _manifest(tmp_path / "m.json", "src/app.py", "src/missing.py")
    result, payload = _json(root, "--changed-lines-manifest", str(manifest), "--strict")

    assert result.exit_code == EXIT_COVERAGE_GAP
    assert payload["changed_lines"]["files_not_analyzed"] == 1
    assert payload["changed_lines"]["files_config_excluded"] == 0


# --- Malformed input fails closed, in one line ---------------------------------


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        ('[overrides."../x/**"]\ndisabled = ["PY-COR-001"]\n', "cannot traverse parent paths"),
        ('[overrides."/abs/**"]\ndisabled = ["PY-COR-001"]\n', "must be project-relative"),
        (f'[overrides."{"a" * 513}"]\ndisabled = ["PY-COR-001"]\n', "invalid pattern"),
        (
            '[overrides."tests/**"]\nseverity = { "PY-COR-001" = "info" }\n',
            "'note', 'warning' or 'error'",
        ),
        ('[overrides."tests/**"]\nenabled = false\n', "Unknown overrides.tests/** key: enabled"),
        ('[overrides."tests/**"]\ndisabled = "PY-COR-001"\n', "must be an array of rule IDs"),
    ],
)
def test_malformed_override_is_a_one_line_error_without_a_traceback(project, toml, message):
    root = project({"a.py": MUTABLE_DEFAULT, ".code-quality.toml": toml})
    result = _run(root, "-f", "json")

    assert result.exit_code != EXIT_OK
    assert message in result.output
    assert "Traceback" not in result.output
    assert "a" * 100 not in result.output  # the oversized glob is never echoed
