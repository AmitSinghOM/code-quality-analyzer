"""Baseline fingerprints must survive line shifts (review 6, finding B1).

Before 3.4.0 the fingerprint hashed the line number and the message, so a
single inserted line above a baselined finding -- or a reworded rule message
in a release -- made ``--new-findings-only`` re-report it as new. Schema
2.0.0 hashes the rule, the path, the whitespace-collapsed text of the reported
line and an ordinal among identical lines instead.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from clirunner import CliRunner

from cqa_analyzer.__main__ import EXIT_OK, main
from cqa_analyzer.baseline import (
    BASELINE_SCHEMA_VERSION,
    LEGACY_BASELINE_SCHEMA_VERSION,
    Baseline,
    compare_findings,
    finding_fingerprint,
    finding_fingerprint_v1,
    fingerprints_for,
    load_baseline,
    write_baseline,
)
from cqa_analyzer.findings import Finding, Location

OFFENDING = "    return subprocess.run(cmd, shell=True)\n"
ORIGINAL = "import subprocess\n\ndef run(cmd):\n" + OFFENDING


def _project(tmp_path: Path, source: str) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "a.py").write_text(source, encoding="utf-8")
    return root


def _scan(root: Path, *extra: str) -> dict:
    result = CliRunner().invoke(main, [str(root), "-f", "json", *extra])
    assert result.exit_code == EXIT_OK, result.output
    return json.loads(result.output)


def _baseline(root: Path, tmp_path: Path) -> Path:
    path = tmp_path / "baseline.json"
    result = CliRunner().invoke(main, [str(root), "--write-baseline", str(path)])
    assert result.exit_code == EXIT_OK, result.output
    return path


def _new_findings(root: Path, baseline: Path) -> dict:
    return _scan(root, "--baseline", str(baseline), "--new-findings-only")


def test_written_baseline_uses_schema_2(tmp_path):
    root = _project(tmp_path, ORIGINAL)
    baseline = _baseline(root, tmp_path)

    payload = json.loads(baseline.read_text(encoding="utf-8"))

    assert payload["schema_version"] == BASELINE_SCHEMA_VERSION == "2.0.0"
    assert len(payload["fingerprints"]) == 1
    # Only hashes: no path, rule id or source text ever reaches the file.
    assert "src/a.py" not in baseline.read_text(encoding="utf-8")
    assert "subprocess" not in baseline.read_text(encoding="utf-8")


def test_inserted_lines_and_reformatting_do_not_create_new_findings(tmp_path):
    root = _project(tmp_path, ORIGINAL)
    baseline = _baseline(root, tmp_path)

    shifted = (
        "# copyright header\n# second header line\n"
        "import subprocess\n\n\ndef run(cmd):\n"
        "        return   subprocess.run(cmd,  shell=True)\n"
    )
    (root / "src" / "a.py").write_text(shifted, encoding="utf-8")
    report = _new_findings(root, baseline)

    assert report["baseline"]["current_findings"] == 1
    assert report["baseline"]["new_findings"] == 0
    assert report["findings"] == []


def test_renamed_file_is_reported_as_new(tmp_path):
    root = _project(tmp_path, ORIGINAL)
    baseline = _baseline(root, tmp_path)

    (root / "src" / "a.py").rename(root / "src" / "b.py")
    report = _new_findings(root, baseline)

    assert report["baseline"]["new_findings"] == 1
    assert report["findings"][0]["location"]["path"] == "src/b.py"


def test_changed_offending_line_is_reported_as_new(tmp_path):
    root = _project(tmp_path, ORIGINAL)
    baseline = _baseline(root, tmp_path)

    changed = ORIGINAL.replace("shell=True", 'shell=True, cwd="/tmp"')
    (root / "src" / "a.py").write_text(changed, encoding="utf-8")
    report = _new_findings(root, baseline)

    assert report["baseline"]["new_findings"] == 1


def test_identical_lines_are_baselined_individually(tmp_path):
    twice = (
        "import subprocess\n\ndef run(cmd):\n" + OFFENDING + "\n"
        "def run_again(cmd):\n" + OFFENDING
    )
    root = _project(tmp_path, twice)
    baseline_path = _baseline(root, tmp_path)
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert len(payload["fingerprints"]) == 2, "ordinal must separate twins"

    # Deleting the first twin leaves the survivor known (it becomes ordinal 0).
    once = "import subprocess\n\ndef run_again(cmd):\n" + OFFENDING
    (root / "src" / "a.py").write_text(once, encoding="utf-8")
    report = _new_findings(root, baseline_path)
    assert report["baseline"]["new_findings"] == 0

    # Adding a third identical line is genuinely new.
    thrice = twice + "\ndef run_thrice(cmd):\n" + OFFENDING
    (root / "src" / "a.py").write_text(thrice, encoding="utf-8")
    report = _new_findings(root, baseline_path)
    assert report["baseline"]["current_findings"] == 3
    assert report["baseline"]["new_findings"] == 1


def test_legacy_schema_1_baseline_still_loads_and_compares(tmp_path):
    root = _project(tmp_path, ORIGINAL)
    report = _scan(root)
    finding = report["findings"][0]
    legacy = Finding(
        rule_id=finding["rule_id"],
        category=finding["category"],
        severity=finding["severity"],
        confidence=finding["confidence"],
        message=finding["message"],
        location=Location(
            path=finding["location"]["path"],
            line=finding["location"]["line"],
            column=finding["location"]["column"],
        ),
        remediation=finding["remediation"],
    )
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(
        json.dumps(
            {
                "schema_version": LEGACY_BASELINE_SCHEMA_VERSION,
                "fingerprint_algorithm": "sha256",
                "fingerprints": [finding_fingerprint_v1(legacy)],
            }
        ),
        encoding="utf-8",
    )

    loaded = load_baseline(legacy_path)
    assert loaded.schema_version == "1.0.0"

    report = _new_findings(root, legacy_path)
    assert report["baseline"]["schema_version"] == "1.0.0"
    assert report["baseline"]["new_findings"] == 0


def test_unknown_schema_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"schema_version": "9.0.0", "fingerprints": []}),
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, [str(tmp_path), "--baseline", str(path), "-f", "json"])
    assert result.exit_code != EXIT_OK
    assert "Unsupported baseline schema" in result.output


def _finding(line: int, context: str | None, path: str = "pkg/a.py") -> Finding:
    return Finding(
        rule_id="PY-SEC-002",
        category="security",
        severity="warning",
        confidence="high",
        message="msg",
        location=Location(path=path, line=line, column=12, context=context),
        remediation="fix",
    )


def test_fingerprint_ignores_line_and_message_when_context_present():
    first = _finding(4, "return subprocess.run(cmd, shell=True)")
    shifted = replace(
        replace(first, message="reworded in a later release"),
        location=replace(first.location, line=40, column=1),
    )

    assert finding_fingerprint(first) == finding_fingerprint(shifted)
    assert finding_fingerprint_v1(first) != finding_fingerprint_v1(shifted)


def test_fingerprint_falls_back_to_line_without_context():
    first = _finding(4, None)
    moved = replace(first, location=replace(first.location, line=5))

    assert finding_fingerprint(first) != finding_fingerprint(moved)


def test_fingerprints_for_assigns_ordinals_in_order():
    twin_a = _finding(4, "x()")
    twin_b = _finding(9, "x()")
    other = _finding(6, "y()")

    hashes = fingerprints_for([twin_a, other, twin_b])

    assert hashes[0] == finding_fingerprint(twin_a, 0)
    assert hashes[1] == finding_fingerprint(other, 0)
    assert hashes[2] == finding_fingerprint(twin_b, 1)
    assert len(set(hashes)) == 3


def test_compare_accepts_bare_set_and_baseline_record():
    finding = _finding(4, "x()")
    known = {finding_fingerprint(finding)}

    assert compare_findings([finding], known).new_findings == ()
    record = Baseline(frozenset(known), BASELINE_SCHEMA_VERSION)
    assert compare_findings([finding], record).new_findings == ()
    legacy = Baseline(frozenset({finding_fingerprint_v1(finding)}), "1.0.0")
    assert compare_findings([finding], legacy).new_findings == ()
    assert compare_findings([finding], legacy).schema_version == "1.0.0"


def test_context_is_never_serialised(tmp_path):
    finding = _finding(4, "return subprocess.run(cmd, shell=True)")

    assert "context" not in finding.location.as_dict()
    assert "context" not in finding.as_dict().get("location", {})
    path = tmp_path / "b.json"
    write_baseline(path, [finding])
    assert "subprocess" not in path.read_text(encoding="utf-8")


# --- C1: fingerprints surfaced in reports so alert identity survives shifts ---


def test_json_and_sarif_fingerprints_match_the_written_baseline(tmp_path):
    root = _project(tmp_path, ORIGINAL)
    baseline = _baseline(root, tmp_path)
    stored = json.loads(baseline.read_text(encoding="utf-8"))["fingerprints"]

    report = _scan(root)
    sarif = CliRunner().invoke(main, [str(root), "-f", "sarif"])
    assert sarif.exit_code == EXIT_OK, sarif.output
    results = json.loads(sarif.output)["runs"][0]["results"]

    assert [f["fingerprint"] for f in report["findings"]] == stored
    assert [r["partialFingerprints"]["cqaFingerprint/v2"] for r in results] == stored


def test_fingerprints_are_omitted_from_anonymized_reports(tmp_path):
    root = _project(tmp_path, ORIGINAL)

    report = _scan(root, "--anonymize")
    sarif = CliRunner().invoke(main, [str(root), "-f", "sarif", "--anonymize"])

    assert report["findings"] and all("fingerprint" not in f for f in report["findings"])
    assert "partialFingerprints" not in sarif.output


def test_filtered_report_keeps_baseline_ordinals(tmp_path):
    """A --new-findings-only report must not renumber twins.

    Ordinals are assigned over every finding of the scan, so the surviving
    twin in a filtered report carries the same fingerprint the full baseline
    stored for it, not ordinal 0 recomputed over the subset.
    """
    twice = (
        "import subprocess\n\ndef run(cmd):\n" + OFFENDING + "\n"
        "def run_again(cmd):\n" + OFFENDING
    )
    root = _project(tmp_path, twice)
    baseline_path = _baseline(root, tmp_path)
    stored = set(json.loads(baseline_path.read_text(encoding="utf-8"))["fingerprints"])

    # Baseline only the first twin, then report new findings: the second twin
    # must be reported under its ordinal-1 fingerprint.
    first_only = _scan(root)["findings"][0]["fingerprint"]
    partial = tmp_path / "partial.json"
    partial.write_text(
        json.dumps(
            {
                "schema_version": BASELINE_SCHEMA_VERSION,
                "fingerprint_algorithm": "sha256",
                "fingerprints": [first_only],
            }
        ),
        encoding="utf-8",
    )
    report = _new_findings(root, partial)

    assert report["baseline"]["new_findings"] == 1
    reported = report["findings"][0]["fingerprint"]
    assert reported != first_only
    assert reported in stored
