"""Review 5, A6/A9: suppressions are visible evidence, not an absence.

On 3.2.1 a ``cqa: ignore=RULE reason="..."`` directive made a finding vanish
from JSON, SARIF and the text summary with no trace. bandit counts ``nosec``
hits and gosec emits SARIF ``suppressions[]`` with the justification; cqa now
does both, and never lets a suppressed finding reach the score or the exit
code.
"""

from __future__ import annotations

import json

from cqa_analyzer.languages._suppressions import comment_suppression_lines, comment_suppressions
from cqa_analyzer.python_suppressions import suppressions as python_suppressions
from tests.test_cli import run  # noqa: E402 - shared CLI harness

GO_TLS = (
    "package p\n"
    'import "crypto/tls"\n'
    "func f() { _ = &tls.Config{InsecureSkipVerify: true} "
    '// cqa: ignore=GO-SEC-001 reason="self-signed in dev"\n'
    "}\n"
)
PY_SHELL = (
    "import subprocess\n"
    "def f(u):\n"
    "    subprocess.run('ls ' + u, shell=True)  "
    '# cqa: ignore=PY-SEC-002 reason="u is an allowlisted constant"\n'
)


def test_json_reports_suppressed_findings_and_counts(project):
    root = project({"tls.go": GO_TLS, "sh.py": PY_SHELL})

    result = run([str(root), "-f", "json", "--offline", "--fail-on", "warning"])
    payload = json.loads(result.output)

    assert result.exit_code == 0, "suppressed findings never reach the exit code"
    assert payload["findings"] == []
    assert payload["scan_health"]["suppressed"] == {
        "count": 2,
        "by_rule": {"GO-SEC-001": 1, "PY-SEC-002": 1},
    }
    suppressed = payload["suppressed_findings"]
    assert [(f["rule_id"], f["location"]["line"], f["suppression_reason"]) for f in suppressed] == [
        ("PY-SEC-002", 3, "u is an allowlisted constant"),
        ("GO-SEC-001", 3, "self-signed in dev"),
    ]


def test_sarif_marks_suppressed_results_in_source(project):
    root = project({"tls.go": GO_TLS})

    result = run([str(root), "-f", "sarif", "--offline"])
    sarif_run = json.loads(result.output)["runs"][0]

    assert result.exit_code == 0
    assert [rule["id"] for rule in sarif_run["tool"]["driver"]["rules"]] == ["GO-SEC-001"]
    (item,) = sarif_run["results"]
    assert item["ruleId"] == "GO-SEC-001" and item["ruleIndex"] == 0
    assert item["suppressions"] == [{"kind": "inSource", "justification": "self-signed in dev"}]


def test_unsuppressed_sarif_results_carry_no_suppressions_key(project):
    root = project({"tls.go": GO_TLS.replace(" // cqa: ignore", " // was: cqa: ignore")})

    result = run([str(root), "-f", "sarif", "--offline"])
    (item,) = json.loads(result.output)["runs"][0]["results"]

    assert "suppressions" not in item


def test_text_report_mentions_suppressed_count(project):
    root = project({"tls.go": GO_TLS})

    result = run([str(root), "--offline"])

    assert result.exit_code == 0
    assert "1 finding(s) suppressed by in-source directives (GO-SEC-001=1)" in result.output


def test_anonymized_suppressed_findings_leak_neither_paths_nor_reasons(project):
    root = project({"tls.go": GO_TLS})

    result = run([str(root), "-f", "json", "--offline", "--anonymize"])
    payload = json.loads(result.output)

    (item,) = payload["suppressed_findings"]
    assert "tls.go" not in item["location"]["path"]
    assert item["suppression_reason"] == "[redacted]", "author free text is redacted"


def test_report_without_directives_has_empty_suppression_keys(project):
    root = project({"lib.py": "x = 1\n"})

    payload = json.loads(run([str(root), "-f", "json", "--offline"]).output)

    assert payload["suppressed_findings"] == []
    assert payload["scan_health"]["suppressed"] == {"count": 0, "by_rule": {}}


# ---- A9: directive line numbers are counted incrementally ---------------------


def test_comment_suppressions_line_numbers_and_reasons():
    source = (
        "a\n"
        'b // cqa: ignore=GO-SEC-001 reason="one"\n'
        "c\n"
        "d\n"
        "e /* cqa: ignore=GO-SEC-002, GO-COR-002 reason='two' */\n"
        'f // cqa: ignore=GO-SEC-003 reason=""\n'
    )
    assert comment_suppressions(source) == {
        (2, "GO-SEC-001"): "one",
        (5, "GO-SEC-002"): "two",
        (5, "GO-COR-002"): "two",
    }
    assert comment_suppression_lines(source) == {
        (2, "GO-SEC-001"),
        (5, "GO-SEC-002"),
        (5, "GO-COR-002"),
    }


def test_comment_suppressions_many_directives_stay_correct():
    lines = [f'x{i} // cqa: ignore=GO-SEC-001 reason="r{i}"' for i in range(3_000)]
    found = comment_suppressions("\n".join(lines) + "\n")
    assert len(found) == 3_000
    assert found[(1, "GO-SEC-001")] == "r0"
    assert found[(3_000, "GO-SEC-001")] == "r2999"


def test_python_suppressions_return_reasons():
    source = (
        'import os\nos.system(cmd)  # cqa: ignore=PY-SEC-002 reason="cmd is a literal upstream"\n'
    )
    assert python_suppressions(source) == {(2, "PY-SEC-002"): "cmd is a literal upstream"}
