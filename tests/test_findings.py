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


def test_broad_exception_handlers_are_reported_precisely():
    findings = findings_for(
        "try:\n    operation()\n"
        "except Exception:\n    recover()\n"
        "try:\n    other()\n"
        "except:\n    recover()\n"
    )

    assert [finding.rule_id for finding in findings] == [
        "PY-COR-002",
        "PY-COR-002",
    ]
    assert [finding.location.line for finding in findings] == [3, 7]
    assert "Exception" in findings[0].message
    assert "bare except" in findings[1].message


def test_narrow_and_specific_exception_handlers_are_not_broad():
    findings = findings_for(
        "try:\n    operation()\n"
        "except (ValueError, LookupError):\n    recover()\n"
    )

    assert findings == []


def test_pass_and_ellipsis_exception_handlers_are_swallowed():
    findings = findings_for(
        "try:\n    first()\nexcept ValueError:\n    pass\n"
        "try:\n    second()\nexcept LookupError:\n    ...\n"
    )

    assert [finding.rule_id for finding in findings] == [
        "PY-COR-003",
        "PY-COR-003",
    ]
    assert [finding.location.line for finding in findings] == [3, 7]


def test_handlers_with_recovery_or_reraise_are_not_swallowed():
    findings = findings_for(
        "try:\n    first()\nexcept ValueError:\n    recover()\n"
        "try:\n    second()\nexcept LookupError:\n    raise\n"
    )

    assert findings == []


def test_unreachable_statement_after_direct_control_transfer_is_reported():
    findings = findings_for(
        "def choose(value):\n"
        "    if value:\n"
        "        return value\n"
        "        audit(value)\n"
        "    while value:\n"
        "        break\n"
        "        value -= 1\n"
        "    raise RuntimeError()\n"
        "    cleanup()\n"
    )

    assert [finding.rule_id for finding in findings] == [
        "PY-COR-004",
        "PY-COR-004",
        "PY-COR-004",
    ]
    assert [finding.location.line for finding in findings] == [4, 7, 9]


def test_conditional_control_transfer_does_not_mark_following_code_unreachable():
    findings = findings_for(
        "def choose(value):\n"
        "    if value:\n"
        "        return value\n"
        "    audit(value)\n"
        "    return None\n"
    )

    assert findings == []


def test_new_rules_use_reason_required_same_line_suppressions(project):
    root = project({
        "module.py": (
            "def load():\n"
            "    try:\n"
            "        operation()\n"
            "    except Exception:  # cqa: ignore=PY-COR-002,PY-COR-003 "
            "reason='process boundary'\n"
            "        pass\n"
            "    return None\n"
            "    cleanup()  # cqa: ignore=PY-COR-004 reason='dead fixture'\n"
        ),
    })
    scanner = CodeScanner(root)

    scanner.scan()

    assert scanner.findings == []
