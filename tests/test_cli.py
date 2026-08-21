"""CLI contract: exit codes, JSON shape, path handling."""

import json

from click.testing import CliRunner

from analyzer.__main__ import (
    EXIT_BELOW_THRESHOLD,
    EXIT_COVERAGE_GAP,
    EXIT_FINDINGS,
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
    assert payload["schema_version"] == "1.9.0"
    assert payload["analyzer_version"] == "2.25.0"
    assert payload["ruleset_version"] == "2.12.0"
    assert payload["scoring_policy_version"] == "1.0.0"
    assert len(payload["configuration_fingerprint"]) == 64
    assert payload["language_adapters"] == {
        "go": "1.0.0",
        "python": "1.0.0",
    }
    assert payload["project"] == root.name
    assert 1.0 <= payload["architecture_signal_score"] <= 10.0
    assert payload["rating"] == payload["architecture_signal_score"]
    assert payload["analysis_health"] == {
        "complete": True,
        "authoritative": True,
        "source_candidates": 1,
        "files_read": 1,
        "files_successfully_analyzed": 1,
        "completeness_ratio": 1.0,
        "reasons": [],
    }
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

    result = run([
        str(root), "--strict", "--complexity", "--output-format", "json",
    ])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_COVERAGE_GAP
    assert payload["analysis_health"]["authoritative"] is False
    assert payload["analysis_health"]["reasons"] == [
        "project_analysis_incomplete"
    ]


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


def test_baseline_supports_new_findings_only_ci_gate(project, tmp_path):
    root = project({
        "existing.py": "def existing(items=[]):\n    return items\n",
    })
    baseline = tmp_path / "baseline.json"

    written = run([
        str(root), "--output-format", "json", "--write-baseline", str(baseline),
    ])
    written_payload = json.loads(written.output)

    assert written.exit_code == EXIT_OK
    assert written_payload["baseline"]["written"] is True
    assert "existing.py" not in baseline.read_text(encoding="utf-8")

    unchanged = run([
        str(root), "--output-format", "json", "--baseline", str(baseline),
        "--new-findings-only", "--fail-on", "warning",
    ])
    unchanged_payload = json.loads(unchanged.output)

    assert unchanged.exit_code == EXIT_OK
    assert unchanged_payload["findings"] == []
    assert unchanged_payload["baseline"]["new_findings"] == 0

    (root / "new.py").write_text(
        "def introduced(cache={}):\n    return cache\n",
        encoding="utf-8",
    )
    changed = run([
        str(root), "--output-format", "json", "--baseline", str(baseline),
        "--new-findings-only", "--fail-on", "warning",
    ])
    changed_payload = json.loads(changed.output)

    assert changed.exit_code == EXIT_FINDINGS
    assert changed_payload["baseline"]["new_findings"] == 1
    assert len(changed_payload["findings"]) == 1
    assert changed_payload["findings"][0]["location"]["path"] == "new.py"


def test_error_gate_ignores_warning_findings(project):
    root = project({"service.py": "def f(cache={}):\n    return cache\n"})

    result = run([str(root), "--fail-on", "error"])

    assert result.exit_code == EXIT_OK


def test_warning_gate_fails_for_warning_findings(project):
    root = project({"service.py": "def f(cache={}):\n    return cache\n"})

    result = run([str(root), "--fail-on", "warning"])

    assert result.exit_code == EXIT_FINDINGS


def test_new_findings_only_requires_baseline(project):
    root = project({"service.py": "VALUE = 1\n"})

    result = run([str(root), "--new-findings-only"])

    assert result.exit_code != EXIT_OK
    assert "requires --baseline" in result.output


def test_invalid_baseline_fails_without_traceback(project, tmp_path):
    root = project({"service.py": "VALUE = 1\n"})
    baseline = tmp_path / "baseline.json"
    baseline.write_text("not-json", encoding="utf-8")

    result = run([str(root), "--baseline", str(baseline)])

    assert result.exit_code != EXIT_OK
    assert "Baseline is not readable valid JSON" in result.output
    assert "Traceback" not in result.output


def test_error_gate_fails_for_package_error(project):
    root = project({
        "pyproject.toml": (
            "[project]\n"
            "name = 'demo'\n\n"
            "[project.scripts]\n"
            "demo = 'demo.missing:main'\n"
        ),
        "demo/__init__.py": "",
    })

    result = run([str(root), "--fail-on", "error"])

    assert result.exit_code == EXIT_FINDINGS


def _private_project(project):
    return project({
        "pyproject.toml": (
            "[project]\n"
            "name = 'acme-private'\n"
            "dependencies = ['internal-dependency']\n\n"
            "[project.scripts]\n"
            "secret-command = 'secret_pkg.missing:main'\n"
        ),
        "secret_pkg/__init__.py": "",
        "secret_pkg/private_module.py": (
            "def proprietary_engine(secret_items=[]):\n"
            "    dp = {}\n"
            "    for secret_outer in secret_items:\n"
            "        for secret_inner in secret_items:\n"
            "            dp[secret_outer] = secret_inner\n"
            "    return dp\n"
        ),
        "private/oversized.py": "PRIVATE_MARKER = '" + ("x" * 2000) + "'\n",
    })


def test_anonymized_json_removes_source_identifiers(project):
    root = _private_project(project)

    result = run([
        str(root), "--output-format", "json", "--anonymize", "--offline",
        "--verbose", "--complexity", "--max-file-size", "500",
    ])
    payload = json.loads(result.output)
    rendered = result.output

    assert result.exit_code == EXIT_OK
    assert payload["project"] == "anonymized-project"
    assert payload["privacy"] == {
        "anonymized": True,
        "paths_redacted": True,
        "offline_enforced": True,
    }
    assert payload["scan_health"]["skipped_examples"]["too_large"] == [
        "file-0001"
    ]
    finding = payload["findings"][0]
    assert finding["location"]["path"].startswith("file-")
    evidence = payload["dsa_patterns"]["dynamic_programming"]["evidence"][0]
    assert "signal_count" in evidence
    assert "signals" not in evidence
    high = payload["complexity"]["high_complexity_functions"][0]
    assert high["name"].startswith("function-")
    assert high["file"].startswith("file-")

    for sensitive in (
        "acme-private",
        "internal-dependency",
        "secret-command",
        "secret_pkg",
        "private_module.py",
        "private/oversized.py",
        "proprietary_engine",
        "secret_items",
        "secret_outer",
        "secret_inner",
        "PRIVATE_MARKER",
    ):
        assert sensitive not in rendered


def test_anonymized_text_removes_source_identifiers(project):
    root = _private_project(project)

    result = run([
        str(root), "--anonymize", "--offline", "--verbose", "--complexity",
        "--max-file-size", "500",
    ])

    assert result.exit_code == EXIT_OK
    assert "Analyzing: anonymized-project" in result.output
    assert "offline enforced=yes" in result.output
    assert "function-" in result.output
    assert "signal(s) redacted" in result.output
    for sensitive in (
        "acme-private",
        "internal-dependency",
        "secret-command",
        "secret_pkg",
        "private_module.py",
        "proprietary_engine",
        "secret_items",
    ):
        assert sensitive not in result.output


def test_anonymization_does_not_change_baseline_fingerprints(project, tmp_path):
    root = _private_project(project)
    normal = tmp_path / "normal.json"
    anonymous = tmp_path / "anonymous.json"

    first = run([str(root), "--write-baseline", str(normal)])
    second = run([
        str(root), "--anonymize", "--write-baseline", str(anonymous),
    ])

    assert first.exit_code == EXIT_OK
    assert second.exit_code == EXIT_OK
    assert normal.read_bytes() == anonymous.read_bytes()


def test_offline_metadata_is_reported(project):
    root = project({"module.py": "VALUE = 1\n"})

    result = run([str(root), "--output-format", "json", "--offline"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["privacy"]["offline_enforced"] is True


def test_offline_cli_stops_network_attempt_before_connection(project, monkeypatch):
    import socket

    from analyzer.scanner import CodeScanner

    root = project({"module.py": "VALUE = 1\n"})

    def attempt_network(_scanner):
        socket.create_connection(("127.0.0.1", 9))

    monkeypatch.setattr(CodeScanner, "scan", attempt_network)

    result = run([str(root), "--offline"])

    assert result.exit_code != EXIT_OK
    assert "Network access was attempted" in result.output
    assert "Traceback" not in result.output


def test_mixed_python_go_report_uses_one_findings_contract(project):
    root = project({
        "service.py": "def add(items=[]):\n    return items\n",
        "worker.go": (
            "package worker\n\n"
            'import "os"\n\n'
            "func load(privatePath string) []byte {\n"
            "    privateData, _ := os.ReadFile(privatePath)\n"
            "    return privateData\n"
            "}\n"
        ),
    })

    result = run([str(root), "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["scan_health"]["languages"] == {"go": 1, "python": 1}
    go_graph = payload["project_analyses"]["go:package-graph"]
    assert go_graph["health"]["package_count"] == 1
    assert go_graph["result"]["packages"][0]["directory"] == "."
    assert [finding["rule_id"] for finding in payload["findings"]] == [
        "PY-COR-001",
        "GO-COR-001",
    ]


def test_anonymized_go_finding_removes_source_identifiers(project):
    root = project({
        "private/worker.go": (
            "package privateworker\n\n"
            'import "os"\n\n'
            "func load(privatePath string) []byte {\n"
            "    privateData, _ := os.ReadFile(privatePath)\n"
            "    return privateData\n"
            "}\n"
        ),
    })

    result = run([
        str(root), "--output-format", "json", "--anonymize", "--offline",
    ])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["findings"][0]["rule_id"] == "GO-COR-001"
    assert payload["findings"][0]["location"]["path"] == "file-0001"
    assert payload["project_analyses"]["go:package-graph"] == {
        "health": {
            "errors": 0,
            "complete": True,
            "package_count": 1,
            "local_edge_count": 0,
        },
    }
    for sensitive in (
        "private/worker.go",
        "privateworker",
        "privatePath",
        "privateData",
        "os.ReadFile",
    ):
        assert sensitive not in result.output


def test_strict_fails_for_incomplete_go_source(project):
    root = project({"broken.go": "func main() {}\n"})

    result = run([str(root), "--strict", "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_COVERAGE_GAP
    assert payload["scan_health"]["languages"] == {"go": 1}
    assert payload["scan_health"]["unparsed_files"] == 1


def test_unknown_output_format_lists_registered_reporters(project):
    root = project({"module.py": "VALUE = 1\n"})

    result = run([str(root), "--output-format", "yaml"])

    assert result.exit_code != EXIT_OK
    assert "Unknown output format 'yaml'" in result.output
    assert "json, sarif, text" in result.output


def test_all_skipped_sources_exit_three_and_are_non_authoritative(project):
    root = project({"large.py": "VALUE = '" + ("x" * 100) + "'\n"})

    result = run([
        str(root), "--output-format", "json", "--max-file-size", "8",
    ])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_COVERAGE_GAP
    assert payload["analysis_health"] == {
        "complete": False,
        "authoritative": False,
        "source_candidates": 1,
        "files_read": 0,
        "files_successfully_analyzed": 0,
        "completeness_ratio": 0.0,
        "reasons": ["source_files_skipped", "no_successful_analysis"],
    }


def test_all_malformed_sources_exit_three_without_strict(project):
    root = project({"broken.py": "def broken(:\n"})

    result = run([str(root), "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_COVERAGE_GAP
    assert payload["analysis_health"]["files_read"] == 1
    assert payload["analysis_health"]["files_successfully_analyzed"] == 0
    assert payload["analysis_health"]["reasons"] == [
        "parse_failures",
        "no_successful_analysis",
    ]


def test_partial_analysis_is_qualified_without_forcing_non_strict_failure(project):
    root = project({
        "good.py": "VALUE = 1\n",
        "broken.py": "def broken(:\n",
    })

    result = run([str(root), "--output-format", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["analysis_health"] == {
        "complete": False,
        "authoritative": False,
        "source_candidates": 2,
        "files_read": 2,
        "files_successfully_analyzed": 1,
        "completeness_ratio": 0.5,
        "reasons": ["parse_failures"],
    }


def test_anonymization_preserves_analysis_authority_contract(project):
    root = project({
        "private/good.py": "VALUE = 1\n",
        "private/broken.py": "def broken(:\n",
    })

    normal = run([str(root), "--output-format", "json"])
    anonymous = run([
        str(root), "--output-format", "json", "--anonymize", "--offline",
    ])

    assert json.loads(normal.output)["analysis_health"] == (
        json.loads(anonymous.output)["analysis_health"]
    )
