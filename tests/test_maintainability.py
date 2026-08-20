"""Measured cyclomatic and cognitive complexity findings."""

import ast

from analyzer.maintainability import function_complexities
from analyzer.python_rules import PythonRuleAnalyzer
from analyzer.scanner import CodeScanner


def _function_source(name: str, decisions: int) -> str:
    lines = [f"def {name}(value):", "    result = 0"]
    for index in range(decisions):
        lines.extend((
            f"    if value == {index}:",
            "        result += 1",
        ))
    lines.append("    return result")
    return "\n".join(lines) + "\n"


def _nested_source(depth: int) -> str:
    lines = ["def nested(value):"]
    indent = "    "
    for _ in range(depth):
        lines.append(f"{indent}if value:")
        indent += "    "
    lines.append(f"{indent}return value")
    return "\n".join(lines) + "\n"


def test_complexity_measurement_counts_paths_and_nesting():
    tree = ast.parse(
        "def choose(a, b):\n"
        "    if a and b:\n"
        "        if b:\n"
        "            return 1\n"
        "    return 0\n"
    )

    metric = function_complexities(tree)[0]

    assert metric.cyclomatic == 4
    assert metric.cognitive == 4


def test_cyclomatic_rule_reports_only_above_limit():
    source = _function_source("boundary", 9)
    source += "\n" + _function_source("too_many", 10)

    findings = PythonRuleAnalyzer().analyze(ast.parse(source), "module.py")

    assert [finding.rule_id for finding in findings] == ["PY-MAINT-001"]
    assert "11" in findings[0].message
    assert "limit 10" in findings[0].message


def test_cognitive_rule_reports_only_above_limit():
    source = _nested_source(5)
    source += "\n" + _nested_source(6).replace("nested", "too_nested")

    findings = PythonRuleAnalyzer().analyze(ast.parse(source), "module.py")

    assert [finding.rule_id for finding in findings] == ["PY-MAINT-002"]
    assert "21" in findings[0].message
    assert "limit 15" in findings[0].message


def test_nested_functions_are_measured_as_independent_units():
    inner = _function_source("inner", 10)
    nested_inner = "\n".join(
        f"    {line}" if line else line
        for line in inner.splitlines()
    )
    source = (
        "def outer(value):\n"
        f"{nested_inner}\n"
        "    return inner(value)\n"
    )

    metrics = function_complexities(ast.parse(source))
    findings = PythonRuleAnalyzer().analyze(ast.parse(source), "module.py")

    assert [(metric.name, metric.cyclomatic) for metric in metrics] == [
        ("outer", 1),
        ("inner", 11),
    ]
    assert len(findings) == 1
    assert "inner" in findings[0].message


def test_complexity_findings_support_same_line_suppression(project):
    independent = _function_source("wide", 10).replace(
        "def wide(value):",
        "def wide(value):  # cqa: ignore=PY-MAINT-001 reason='dispatcher'",
    )
    nested = _nested_source(6).replace(
        "def nested(value):",
        "def nested(value):  # cqa: ignore=PY-MAINT-002 reason='parser'",
    )
    root = project({"module.py": independent + "\n" + nested})
    scanner = CodeScanner(root)

    scanner.scan()

    assert scanner.findings == []
