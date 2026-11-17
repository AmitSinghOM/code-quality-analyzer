"""Path-scoped rule policy sources must honour the report's privacy mode.

ADR 005, decision 4. A policy source is ``"project"`` or ``"override:<glob>"``;
the glob is author-written and path-shaped, so it is treated as a path:

* plain: emitted as written;
* ``--redact-paths``: the scanner keeps only the glob's last segment and the
  reporters pass that value through untouched;
* ``--anonymize``: ``ReportAnonymizer.policy_source`` maps the glob through the
  same per-report file map as artifact paths, so the raw glob appears nowhere
  in JSON, SARIF or ``scan_health.policy_dropped.by_source``.

These tests drive the anonymizer and the SARIF reporter directly with the
payload shapes the CLI attaches (``policy_source`` beside ``fingerprint``,
``scan_health["policy_dropped"]`` beside ``suppressed``). The end-to-end CLI
run with an ``[overrides]`` table belongs to the integration change.
"""

from __future__ import annotations

import json

from cqa_analyzer.anonymize import ReportAnonymizer
from cqa_analyzer.findings import Finding, Location
from cqa_analyzer.reporters import AnalysisReport, SarifReporter, SarifRun

RAW_GLOBS = ("tests/**/*_test.py", "vendor/", "src/db/**")
RAW_SOURCES = tuple(f"override:{glob}" for glob in RAW_GLOBS)


def _finding(rule_id, path, line):
    return Finding(
        rule_id=rule_id,
        category="maintainability",
        severity="note",
        confidence="high",
        message=f"Reported in {path}.",
        location=Location(path, line, 1, identity_path=path),
        remediation=f"Fix {path}.",
    )


def _strings(value):
    """Yield every string anywhere in a JSON-like value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def _raw_leaks(payload) -> list[str]:
    return [text for text in _strings(payload) if any(glob in text for glob in RAW_GLOBS)]


def _sarif(findings, health, anonymized):
    run = SarifRun(
        analyzer_version="3.6.0",
        configuration_fingerprint="c" * 64,
        analysis_health={"complete": True, "authoritative": True},
        privacy={
            "anonymized": anonymized,
            "paths_redacted": not anonymized,
            "offline_enforced": True,
        },
        baseline_selection={"newFindingsOnly": False},
        findings=tuple(findings),
        policy_dropped=health.get("policy_dropped"),
    )
    return json.loads(SarifReporter().render(AnalysisReport(sarif=run)))


def _raw_health():
    return {
        "skipped_examples": {},
        "unparsed_examples": [],
        "excluded_generated_examples": {},
        "suppressed": {"count": 0, "by_rule": {}},
        "policy_dropped": {
            "count": 6,
            "by_rule": {"PY-MAINT-003": 4, "PY-SEC-002": 2},
            "by_source": {RAW_SOURCES[0]: 4, RAW_SOURCES[1]: 1, "project": 1},
            "security": 2,
        },
    }


def test_anonymized_json_and_sarif_carry_no_raw_glob_anywhere():
    anonymizer = ReportAnonymizer()
    findings = [
        _finding("PY-MAINT-003", "tests/unit/service_test.py", 3),
        _finding("PY-COR-007", "src/db/query.py", 9),
        _finding("PY-COR-001", "src/app.py", 1),
    ]
    sources = (RAW_SOURCES[0], RAW_SOURCES[2], "project")

    # Mirror the CLI: anonymize the finding, then attach the policy source
    # through the same anonymizer, beside where ``fingerprint`` would go.
    finding_payload = []
    for finding, source in zip(findings, sources, strict=True):
        item = anonymizer.finding(finding)
        item["policy_source"] = anonymizer.policy_source(source)
        finding_payload.append(item)
    health = anonymizer.scan_health(_raw_health())
    json_shaped = {
        "privacy": {"anonymized": True},
        "scan_health": health,
        "findings": finding_payload,
    }
    sarif = _sarif(finding_payload, health, anonymized=True)

    assert _raw_leaks(json_shaped) == []
    assert _raw_leaks(sarif) == []
    for rendered in (json.dumps(json_shaped), json.dumps(sarif)):
        for raw in RAW_GLOBS:
            assert raw not in rendered
    # Token order follows first use: finding paths and globs share one counter.
    assert [item["policy_source"] for item in finding_payload] == [
        "override:file-0002",
        "override:file-0004",
        "project",
    ]
    assert health["policy_dropped"]["by_source"] == {
        "override:file-0002": 4,
        "override:file-0006": 1,
        "project": 1,
    }
    assert health["policy_dropped"]["count"] == 6
    assert health["policy_dropped"]["security"] == 2
    assert [r["properties"]["policySource"] for r in sarif["runs"][0]["results"]] == [
        "override:file-0002",
        "override:file-0004",
        "project",
    ]
    assert sarif["runs"][0]["properties"]["policyDropped"] == health["policy_dropped"]
    assert any(text.startswith("override:file-") for text in _strings(sarif))


def test_redacted_policy_sources_pass_through_the_reporters_untouched():
    # Under --redact-paths the scanner has already reduced the glob to its
    # last segment; reporters never transform the value.
    redacted = "override:*_test.py"
    payload = _finding("PY-MAINT-003", "service_test.py", 3).as_dict()
    payload["policy_source"] = redacted
    health = {
        "policy_dropped": {
            "count": 2,
            "by_rule": {"PY-MAINT-003": 2},
            "by_source": {redacted: 2},
            "security": 0,
        }
    }

    sarif = _sarif([payload], health, anonymized=False)
    run = sarif["runs"][0]

    assert run["results"][0]["properties"]["policySource"] == redacted
    assert run["properties"]["policyDropped"]["by_source"] == {redacted: 2}
    assert payload["policy_source"] == redacted


def test_plain_policy_sources_are_emitted_as_written():
    payload = _finding("PY-COR-007", "src/db/query.py", 9).as_dict()
    payload["policy_source"] = RAW_SOURCES[2]

    sarif = _sarif([payload], _raw_health(), anonymized=False)
    run = sarif["runs"][0]

    assert run["results"][0]["properties"]["policySource"] == "override:src/db/**"
    assert run["properties"]["policyDropped"]["by_source"] == {
        RAW_SOURCES[0]: 4,
        RAW_SOURCES[1]: 1,
        "project": 1,
    }
