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


def test_inline_suppression_requires_same_line_and_nonempty_reason(project):
    root = project({
        "valid.py": (
            "def valid(cache={}):  # cqa: ignore=PY-COR-001 "
            "reason=\"legacy API\"\n    return cache\n"
        ),
        "missing.py": (
            "def missing(cache={}):  # cqa: ignore=PY-COR-001\n"
            "    return cache\n"
        ),
        "blank.py": (
            "def blank(cache={}):  # cqa: ignore=PY-COR-001 reason='   '\n"
            "    return cache\n"
        ),
        "wrong_line.py": (
            "# cqa: ignore=PY-COR-001 reason='not same line'\n"
            "def wrong_line(cache={}):\n    return cache\n"
        ),
    })
    scanner = CodeScanner(root)

    scanner.scan()

    assert [finding.location.path for finding in scanner.findings] == [
        "blank.py",
        "missing.py",
        "wrong_line.py",
    ]


def test_suppression_directive_inside_string_is_ignored(project):
    root = project({
        "module.py": (
            "DIRECTIVE = '# cqa: ignore=PY-COR-001 reason=\"not a comment\"'\n"
            "def f(cache={}):\n    return cache\n"
        ),
    })
    scanner = CodeScanner(root)

    scanner.scan()

    assert len(scanner.findings) == 1


def test_suppression_accepts_explicit_rule_list_on_multiline_default(project):
    root = project({
        "module.py": (
            "def f(\n"
            "    cache={}  # cqa: ignore=PY-COR-001,PY-COR-999 "
            "reason='reviewed compatibility'\n"
            "):\n"
            "    return cache\n"
        ),
    })
    scanner = CodeScanner(root)

    scanner.scan()

    assert scanner.findings == []
