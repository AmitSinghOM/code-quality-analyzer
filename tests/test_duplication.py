"""Duplicate function implementation detection (PY-DUP-001)."""

from __future__ import annotations

from cqa_analyzer.rule_metadata import rule_metadata
from cqa_analyzer.scanner import CodeScanner

# A body significant enough to pass both thresholds (>=3 statements,
# >=40 AST nodes), used verbatim and with renamed definitions.
_SIGNIFICANT_BODY = '''
    totals = {}
    for item in records:
        key = item.get("region", "unknown")
        totals[key] = totals.get(key, 0) + int(item.get("amount", 0))
    ranked = sorted(totals.items(), key=lambda pair: (-pair[1], pair[0]))
    return [
        {"region": region, "amount": amount}
        for region, amount in ranked
        if amount > threshold
    ]
'''

_TRIVIAL_BODY = """
    a = 1
    b = 2
    return a + b
"""


def _function(name: str, body: str, docstring: str | None = None) -> str:
    doc = f'    """{docstring}"""\n' if docstring else ""
    return f"def {name}(records, threshold=0):\n{doc}{body}\n"


def _scan(root):
    scanner = CodeScanner(root)
    scanner.scan()
    return scanner


def _dup_findings(scanner):
    return [f for f in scanner.findings if f.rule_id == "PY-DUP-001"]


def test_identical_functions_across_files_are_reported(project):
    root = project({
        "a.py": _function("summarize", _SIGNIFICANT_BODY),
        "b.py": _function("summarize", _SIGNIFICANT_BODY),
    })
    findings = _dup_findings(_scan(root))
    assert len(findings) == 2
    assert {f.location.path for f in findings} == {"a.py", "b.py"}
    first, second = findings
    assert "b.py:1" in first.message
    assert "a.py:1" in second.message
    assert first.severity == "warning"
    assert first.category == "duplication"


def test_renamed_copy_is_still_reported(project):
    root = project({
        "a.py": _function("summarize", _SIGNIFICANT_BODY),
        "b.py": _function("aggregate", _SIGNIFICANT_BODY),
    })
    findings = _dup_findings(_scan(root))
    assert len(findings) == 2
    assert "'aggregate'" in findings[0].message


def test_docstring_difference_does_not_hide_duplicates(project):
    root = project({
        "a.py": _function("summarize", _SIGNIFICANT_BODY, docstring="One."),
        "b.py": _function("summarize", _SIGNIFICANT_BODY, docstring="Two."),
    })
    assert len(_dup_findings(_scan(root))) == 2


def test_trivial_duplicates_are_not_reported(project):
    root = project({
        "a.py": f"def small():\n{_TRIVIAL_BODY}\n",
        "b.py": f"def small():\n{_TRIVIAL_BODY}\n",
    })
    assert _dup_findings(_scan(root)) == []


def test_different_bodies_are_not_reported(project):
    other_body = _SIGNIFICANT_BODY.replace("amount > threshold", "amount >= threshold")
    root = project({
        "a.py": _function("summarize", _SIGNIFICANT_BODY),
        "b.py": _function("summarize", other_body),
    })
    assert _dup_findings(_scan(root)) == []


def test_duplicates_within_one_file_are_reported(project):
    source = (
        _function("summarize", _SIGNIFICANT_BODY)
        + "\n\n"
        + _function("aggregate", _SIGNIFICANT_BODY)
    )
    root = project({"a.py": source})
    findings = _dup_findings(_scan(root))
    assert len(findings) == 2
    assert findings[0].location.line != findings[1].location.line


def test_suppression_comment_removes_one_occurrence(project):
    suppressed = _function("summarize", _SIGNIFICANT_BODY).replace(
        "def summarize(records, threshold=0):",
        'def summarize(records, threshold=0):  '
        '# cqa: ignore=PY-DUP-001 reason="generated"',
        1,
    )
    root = project({
        "a.py": suppressed,
        "b.py": _function("summarize", _SIGNIFICANT_BODY),
    })
    findings = _dup_findings(_scan(root))
    assert len(findings) == 1
    assert findings[0].location.path == "b.py"


def test_nested_duplicates_report_only_the_outer_function(project):
    inner = "".join(
        f"    {line}\n" for line in _function("inner", _SIGNIFICANT_BODY).splitlines()
    )
    outer = (
        "def outer(records, threshold=0):\n"
        + inner
        + "    checked = bool(records)\n"
        + "    assert checked or threshold >= 0\n"
        + "    return inner(records, threshold)\n"
    )
    root = project({"a.py": outer, "b.py": outer})
    findings = _dup_findings(_scan(root))
    assert len(findings) == 2
    assert all("'outer'" in f.message for f in findings)


def test_rule_policy_can_disable_duplication(project):
    root = project({
        "a.py": _function("summarize", _SIGNIFICANT_BODY),
        "b.py": _function("summarize", _SIGNIFICANT_BODY),
        ".code-quality.toml": '[rules."PY-DUP-001"]\nenabled = false\n',
    })
    from cqa_analyzer.config import load_config

    configuration = load_config(root)
    scanner = CodeScanner(root, configuration=configuration)
    scanner.scan()
    assert _dup_findings(scanner) == []


def test_payload_and_health_are_deterministic(project):
    root = project({
        "a.py": _function("summarize", _SIGNIFICANT_BODY),
        "b.py": _function("summarize", _SIGNIFICANT_BODY),
    })
    scanner = _scan(root)
    result = scanner.project_results[("python", "duplication")]
    assert result.payload["duplicate_groups"] == 1
    assert result.payload["duplicated_functions"] == 2
    assert result.payload["functions_analyzed"] == 2
    assert result.payload["groups_truncated"] is False
    group = result.payload["groups"][0]
    assert group["function_count"] == 2
    assert group["occurrences"][0] == {
        "path": "a.py",
        "line": 1,
        "function": "summarize",
    }
    assert result.health == {
        "complete": True,
        "errors": 0,
        "functions_analyzed": 2,
    }


def test_rule_metadata_is_cataloged():
    metadata = rule_metadata("PY-DUP-001")
    assert metadata.category == "duplication"
    assert metadata.default_severity == "warning"
    assert metadata.language == "python"
