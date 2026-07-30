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
    assert 1.0 <= payload["rating"] <= 10.0
    assert payload["scan_health"]["files_scanned"] == 1
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


def test_redact_paths_keeps_absolute_paths_out_of_json(project):
    root = project({"pkg/lib.py": RICH_SOURCE})

    result = run([str(root), "-f", "json", "--redact-paths"])

    assert str(root) not in result.output
    assert json.loads(result.output)["project"] == root.name


def test_complexity_flag_adds_a_section(project):
    root = project({"lib.py": RICH_SOURCE})

    result = run([str(root), "-f", "json", "-c"])
    payload = json.loads(result.output)

    assert payload["complexity"]["total_functions"] == 2
    assert "complexity_health" in payload
