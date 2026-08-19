"""Actionable Python findings and their report contract."""

import ast

from analyzer.python_rules import PythonRuleAnalyzer
from analyzer.scanner import CodeScanner


def findings_for(source: str, path: str = "sample.py"):
    return PythonRuleAnalyzer().analyze(ast.parse(source), path)


def test_mutable_literal_default_has_precise_actionable_finding():
    findings = findings_for("def add(item, items=[]):\n    items.append(item)\n")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "PY-COR-001"
    assert finding.category == "correctness"
    assert finding.severity == "warning"
    assert finding.confidence == "high"
    assert finding.location.path == "sample.py"
    assert finding.location.line == 1
    assert finding.location.column == 21
    assert "items" in finding.message
    assert "add" in finding.message
    assert "Use None" in finding.remediation


def test_builtin_and_comprehension_defaults_are_detected():
    findings = findings_for(
        "def first(cache=dict()):\n    return cache\n\n"
        "def second(*, values={x for x in range(3)}):\n    return values\n"
    )

    assert [finding.location.line for finding in findings] == [1, 4]


def test_immutable_and_none_defaults_are_not_reported():
    findings = findings_for(
        "def safe(items=None, names=(), limit=3, label='x'):\n"
        "    return items, names, limit, label\n"
    )

    assert findings == []


def test_scanner_emits_relative_findings_without_reparsing(project, monkeypatch):
    root = project({"pkg/service.py": "def add(item, items=[]):\n    return items\n"})
    real_parse = ast.parse
    parse_calls = 0

    def counting_parse(*args, **kwargs):
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting_parse)
    scanner = CodeScanner(root)
    scanner.scan()

    assert parse_calls == 1
    assert len(scanner.findings) == 1
    assert scanner.findings[0].location.path == "pkg/service.py"


def test_findings_are_deterministic_by_location():
    findings = findings_for(
        "def second(cache={}):\n    return cache\n\n"
        "def fourth(values=set()):\n    return values\n"
    )

    assert [finding.location.line for finding in findings] == [1, 4]
