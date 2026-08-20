"""Bounded Go pilot adapter and correctness rule."""

from pathlib import Path

from analyzer.languages.go import (
    GoFacts,
    GoImport,
    GoLanguageAdapter,
    GoPackageGraph,
    GoRulePack,
)
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
    assert parsed.facts.imports == (
        GoImport("encoding/json", "json", "default"),
        GoImport("os", "os", "default"),
    )


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
    missing_package = parse_go("// package fake\nfunc main() {}\n")
    unclosed_literal = parse_go('package main\nvar value = "unterminated\n')

    assert missing_package.complete is False
    assert unclosed_literal.complete is False


def test_go_rule_does_not_trust_commented_imports():
    parsed = parse_go(
        "package service\n\n"
        '// import "os"\n\n'
        "func load(path string) []byte {\n"
        "    data, _ := os.ReadFile(path)\n"
        "    return data\n"
        "}\n"
    )

    assert parsed.facts.imports == ()
    assert list(GoRulePack().evaluate(parsed)) == []


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


def test_go_rule_respects_explicit_blank_and_dot_import_aliases():
    parsed = parse_go(
        "package service\n\n"
        "import (\n"
        '    codec "encoding/json"\n'
        '    _ "os"\n'
        '    . "strconv"\n'
        ")\n\n"
        "func encode(value any) []byte {\n"
        "    encoded, _ := codec.Marshal(value)\n"
        "    data, _ := os.ReadFile(\"ignored\")\n"
        "    parsed, _ := strconv.Atoi(\"1\")\n"
        "    _, _ = data, parsed\n"
        "    return encoded\n"
        "}\n"
    )

    assert parsed.facts.imports == (
        GoImport("encoding/json", "codec", "alias"),
        GoImport("os", None, "blank"),
        GoImport("strconv", None, "dot"),
    )
    findings = list(GoRulePack().evaluate(parsed))
    assert len(findings) == 1
    assert "codec.Marshal" in findings[0].message


def test_go_package_graph_aggregates_files_and_local_imports(project):
    root = project({
        "go.mod": "module example.com/demo\n\ngo 1.22\n",
        "cmd/app/main.go": (
            "package main\n\n"
            'import "example.com/demo/internal/store"\n'
        ),
        "internal/store/read.go": "package store\n",
        "internal/store/write.go": "package store\n",
    })
    scanner = CodeScanner(root)

    scanner.scan()
    result = scanner.project_results[("go", "package-graph")]

    assert isinstance(result.payload, GoPackageGraph)
    assert result.payload.module_path == "example.com/demo"
    assert [package.directory for package in result.payload.packages] == [
        "cmd/app",
        "internal/store",
    ]
    assert result.payload.local_edges == (("cmd/app", "internal/store"),)
    assert result.health == {
        "errors": 0,
        "complete": True,
        "package_count": 2,
        "local_edge_count": 1,
    }


def test_go_package_graph_reports_conflicting_packages(project):
    root = project({
        "go.mod": "module example.com/demo\n",
        "pkg/first.go": "package first\n",
        "pkg/second.go": "package second\n",
    })
    scanner = CodeScanner(root)

    scanner.scan()
    result = scanner.project_results[("go", "package-graph")]

    assert result.payload.conflicts == ("pkg",)
    assert result.health["complete"] is False
    assert scanner.has_coverage_gaps is True
