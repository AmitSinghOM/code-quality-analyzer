"""CLI contract: exit codes, JSON shape, path handling."""

import json

from click.testing import CliRunner

from analyzer.__main__ import (
    EXIT_BELOW_THRESHOLD,
    EXIT_COVERAGE_GAP,
    EXIT_NOTHING_ANALYZED,
    EXIT_OK,
    main,
)

RICH_SOURCE = (
    "from functools import lru_cache\n"
    "from collections import deque\n\n"
    "@lru_cache\n"
    "def fib(n):\n"
    "    return n if n < 2 else fib(n - 1) + fib(n - 2)\n\n"
    "def bfs(graph, start):\n"
    "    visited = set()\n"
    "    queue = deque([start])\n"
    "    while queue:\n"
    "        node = queue.popleft()\n"
    "        for n in graph.neighbors(node):\n"
    "            visited.add(n)\n"
    "    return visited\n"
)


def run(args):
    return CliRunner().invoke(main, args)


def test_json_output_is_valid_and_includes_health(project):
    root = project({"lib.py": RICH_SOURCE})

    result = run([str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["schema_version"] == "1.2.0"
    assert payload["analyzer_version"] == "2.2.0"
    assert payload["ruleset_version"] == "2.2.0"
    assert payload["project"] == root.name
    assert 1.0 <= payload["rating"] <= 10.0
    assert payload["scan_health"]["files_scanned"] == 1
    assert "evidence" not in payload["dsa_patterns"]["dynamic_programming"]


def test_verbose_json_includes_evidence(project):
    root = project({"lib.py": RICH_SOURCE})

    result = run([str(root), "-f", "json", "--verbose"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert "evidence" in payload["dsa_patterns"]["dynamic_programming"]


def test_directory_with_no_python_files_exits_two(project):
    root = project({"README.md": "nothing here\n"})

    result = run([str(root)])

    assert result.exit_code == EXIT_NOTHING_ANALYZED


def test_passing_a_file_is_rejected(project):
    root = project({"lib.py": RICH_SOURCE})

    result = run([str(root / "lib.py")])

    assert result.exit_code != EXIT_OK
    assert "directory" in result.output.lower() or "file" in result.output.lower()


def test_fail_under_gates_ci(project):
    root = project({"trivial.py": "def add(a, b):\n    return a + b\n"})

    result = run([str(root), "--fail-under", "9"])

    assert result.exit_code == EXIT_BELOW_THRESHOLD


def test_strict_flags_unreadable_files(project):
    root = project({
        "ok.py": RICH_SOURCE,
        "broken.py": "def f(:\n    pass\n",
    })

    result = run([str(root), "--strict"])

    assert result.exit_code == EXIT_COVERAGE_GAP


def test_report_paths_are_project_relative_and_never_absolute(project):
    root = project({
        "ok.py": "\n",
        "pkg/too_large.py": RICH_SOURCE,
    })

    result = run([str(root), "-f", "json", "--max-file-size", "1"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert str(root) not in result.output
    assert payload["project"] == root.name
    assert payload["scan_health"]["skipped_examples"]["too_large"] == [
        "pkg/too_large.py"
    ]


def test_redact_paths_keeps_absolute_paths_out_of_json(project):
    root = project({
        "ok.py": "\n",
        "pkg/too_large.py": RICH_SOURCE,
    })

    result = run([
        str(root), "-f", "json", "--redact-paths", "--max-file-size", "1",
    ])
    payload = json.loads(result.output)

    assert str(root) not in result.output
    assert payload["project"] == root.name
    assert payload["scan_health"]["skipped_examples"]["too_large"] == [
        "too_large.py"
    ]


def test_complexity_flag_adds_a_section(project):
    root = project({"lib.py": RICH_SOURCE})

    result = run([str(root), "-f", "json", "-c"])
    payload = json.loads(result.output)

    assert payload["complexity"]["total_functions"] == 2
    assert "complexity_health" in payload


def test_strict_flags_truncated_scan(project):
    root = project({
        "a.py": "x = 1\n",
        "b.py": "y = 2\n",
    })

    result = run([str(root), "--strict", "--max-files", "1"])

    assert result.exit_code == EXIT_COVERAGE_GAP


def test_strict_includes_complexity_health(project, monkeypatch):
    from analyzer.complexity import ProjectComplexityAnalyzer

    root = project({"lib.py": "def f():\n    return 1\n"})
    monkeypatch.setattr(ProjectComplexityAnalyzer, "MAX_FUNCTIONS_PER_FILE", 0)

    result = run([str(root), "--strict", "--complexity"])

    assert result.exit_code == EXIT_COVERAGE_GAP


def test_numeric_options_reject_out_of_range_values(project):
    root = project({"lib.py": "x = 1\n"})

    for option, value in (
        ("--max-file-size", "0"),
        ("--max-files", "0"),
        ("--fail-under", "0"),
        ("--fail-under", "11"),
    ):
        result = run([str(root), option, value])

        assert result.exit_code != EXIT_OK
        assert "invalid value" in result.output.lower()


def test_text_output_does_not_print_absolute_project_path(project):
    root = project({"lib.py": "x = 1\n"})

    result = run([str(root)])

    assert result.exit_code == EXIT_OK
    assert str(root) not in result.output
    assert root.name in result.output


def test_json_includes_actionable_findings(project):
    root = project({
        "service.py": "def add(item, items=[]):\n    items.append(item)\n",
    })

    result = run([str(root), "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["finding_summary"] == {
        "total": 1,
        "by_severity": {"warning": 1},
        "by_category": {"correctness": 1},
    }
    finding = payload["findings"][0]
    assert finding["rule_id"] == "PY-COR-001"
    assert finding["location"]["path"] == "service.py"
    assert finding["location"]["line"] == 1
    assert finding["location"]["column"] == 21
    assert "Use None" in finding["remediation"]


def test_text_output_shows_actionable_finding(project):
    root = project({"service.py": "def f(cache={}):\n    return cache\n"})

    result = run([str(root)])

    assert result.exit_code == EXIT_OK
    assert "Actionable Findings" in result.output
    assert "PY-COR-001" in result.output
    assert "service.py:1:13" in result.output


def test_json_includes_package_intelligence(project):
    root = project({
        "pyproject.toml": "[project]\nname = 'demo'\ndependencies = ['click']\n",
        "demo/__init__.py": "",
        "demo/core.py": "VALUE = 1\n",
    })

    result = run([str(root), "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    package = payload["package_intelligence"]
    assert package["project_name"] == "demo"
    assert package["layout"] == "flat"
    assert package["modules"] == ["demo", "demo.core"]
    assert package["dependencies"] == ["click"]


def test_strict_fails_for_invalid_package_metadata(project):
    root = project({
        "pyproject.toml": "[project\nname = 'broken'\n",
        "module.py": "VALUE = 1\n",
    })

    result = run([str(root), "--strict", "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_COVERAGE_GAP
    assert payload["scan_health"]["package_analysis"] == {
        "errors": 1,
        "complete": False,
    }
    assert payload["findings"][0]["rule_id"] == "PY-PKG-003"
