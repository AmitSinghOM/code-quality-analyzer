"""Bounded Go pilot adapter and correctness rule."""

from pathlib import Path

from analyzer.languages.go import GoFacts, GoLanguageAdapter, GoRulePack
from analyzer.protocols import SourceFile
from analyzer.scanner import CodeScanner


def parse_go(source: str):
    source_file = SourceFile(
        path=Path("service.go"),
        display_path="service.go",
        identity_path="pkg/service.go",
        content=source,
    )
    return GoLanguageAdapter().parse(source_file)


def test_go_adapter_extracts_package_and_import_facts():
    parsed = parse_go(
        'package service\n\nimport (\n    "encoding/json"\n    "os"\n)\n'
    )

    assert parsed.complete is True
    assert parsed.line_count == 6
    assert isinstance(parsed.facts, GoFacts)
    assert parsed.facts.package_name == "service"
    assert parsed.facts.imports == ("encoding/json", "os")


def test_go_rule_reports_ignored_known_standard_library_errors():
    parsed = parse_go(
        "package service\n\n"
        "import (\n"
        '    "encoding/json"\n'
        '    "os"\n'
        ")\n\n"
        "func load(path string) []byte {\n"
        "    data, _ := os.ReadFile(path)\n"
        "    encoded, _ := json.Marshal(data)\n"
        "    return encoded\n"
        "}\n"
    )

    findings = list(GoRulePack().evaluate(parsed))

    assert [finding.rule_id for finding in findings] == [
        "GO-COR-001",
        "GO-COR-001",
    ]
    assert [finding.location.line for finding in findings] == [9, 10]
    assert findings[0].location.identity_path == "pkg/service.go"
    assert "os.ReadFile" in findings[0].message


def test_go_rule_ignores_comments_strings_unknown_calls_and_ok_values():
    parsed = parse_go(
        "package service\n\n"
        'import "os"\n\n'
        "func load() {\n"
        '    sample := "data, _ := os.ReadFile(path)"\n'
        "    // data, _ := os.ReadFile(path)\n"
        "    value, ok := lookup()\n"
        "    data, _ := client.ReadFile(path)\n"
        "    _, _, _, _ = sample, value, ok, data\n"
        "}\n"
    )

    assert list(GoRulePack().evaluate(parsed)) == []


def test_go_adapter_marks_missing_package_or_unclosed_literal_incomplete():
    missing_package = parse_go("func main() {}\n")
    unclosed_literal = parse_go('package main\nvar value = "unterminated\n')

    assert missing_package.complete is False
    assert unclosed_literal.complete is False


def test_scanner_handles_mixed_python_and_go_findings(project):
    root = project({
        "service.py": "def add(items=[]):\n    return items\n",
        "worker.go": (
            "package worker\n\n"
            'import "os"\n\n'
            "func load(path string) []byte {\n"
            "    data, _ := os.ReadFile(path)\n"
            "    return data\n"
            "}\n"
        ),
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert scanner.language_counts == {"go": 1, "python": 1}
    assert [finding.rule_id for finding in scanner.findings] == [
        "PY-COR-001",
        "GO-COR-001",
    ]
