"""Scanner behaviour: per-file isolation, corroboration, safe reads."""

import os
import sys

import pytest

from analyzer.scanner import CodeScanner


def test_imports_do_not_leak_between_files(project):
    """Regression: a project-wide import set made one `import heapq` mark
    every later file as using heaps."""
    root = project({
        "a_uses_heap.py": "import heapq\n\ndef f(xs):\n    heapq.heappush(xs, 1)\n",
        "z_plain.py": "def add(a, b):\n    return a + b\n",
    })

    scanner = CodeScanner(root)
    dsa, _ = scanner.scan()

    assert scanner.files_scanned == 2
    assert dsa["heap_priority"] == ["a_uses_heap.py"]


def test_prose_only_file_reports_nothing(project):
    root = project({
        "notes.py": '''
"""Plan: add a Trie, use dp[] memoization, then Dijkstra.

We also want a bloom filter and a segment tree eventually.
"""
'''
    })

    scanner = CodeScanner(root)
    dsa, design = scanner.scan()

    assert dsa == {}
    assert design == {}


def test_generic_pattern_requires_corroboration(project):
    """`visited` alone is not a graph traversal."""
    root = project({
        "weak.py": "def f(rows):\n    visited = set()\n    return visited\n",
        "strong.py": (
            "from collections import deque\n\n"
            "def bfs(graph, start):\n"
            "    visited = set()\n"
            "    queue = deque([start])\n"
            "    while queue:\n"
            "        node = queue.popleft()\n"
            "        for n in graph.neighbors(node):\n"
            "            visited.add(n)\n"
            "    return visited\n"
        ),
    })

    scanner = CodeScanner(root)
    dsa, _ = scanner.scan()

    assert dsa["graph_traversal"] == ["strong.py"]


def test_evidence_explains_each_match(project):
    root = project({
        "dp.py": "def f(n):\n    dp = [0] * n\n    dp[0] = 1\n    return dp\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    signals = scanner.dsa_evidence["dynamic_programming"][0].signals
    assert "code:dp[" in signals


def test_oversized_file_is_skipped_and_counted(project):
    root = project({
        "big.py": "x = 1\n" + ("# padding\n" * 200),
        "small.py": "import heapq\nheapq.heapify([])\n",
    })

    scanner = CodeScanner(root, max_file_size=64)
    scanner.scan()
    health = scanner.scan_health()

    assert scanner.files_scanned == 1
    assert health["skipped_by_reason"]["too_large"] == 1
    assert scanner.has_coverage_gaps is True


def test_symlink_escaping_project_is_not_read(project, tmp_path):
    secret = tmp_path / "outside_secret.py"
    secret.write_text("import heapq\nheapq.heappush([], 1)\n", encoding="utf-8")

    root = project({"real.py": "def f():\n    return 1\n"})
    try:
        (root / "link.py").symlink_to(secret)
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks unavailable")

    scanner = CodeScanner(root)
    dsa, _ = scanner.scan()
    health = scanner.scan_health()

    assert health["skipped_by_reason"]["outside_project_root"] == 1
    assert "heap_priority" not in dsa


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
def test_fifo_is_not_read(project):
    """Reading a FIFO with no writer blocks forever."""
    root = project({"real.py": "x = 1\n"})
    os.mkfifo(root / "pipe.py")

    scanner = CodeScanner(root)
    scanner.scan()

    assert scanner.scan_health()["skipped_by_reason"]["not_regular_file"] == 1


def test_excluded_directories_are_not_walked(project):
    root = project({
        "app.py": "x = 1\n",
        "venv/lib/thing.py": "import heapq\nheapq.heapify([])\n",
        "__pycache__/cached.py": "import heapq\n",
    })

    scanner = CodeScanner(root)
    dsa, _ = scanner.scan()

    assert scanner.files_scanned == 1
    assert dsa == {}


def test_max_files_marks_result_truncated(project):
    root = project({f"m{i}.py": "x = 1\n" for i in range(5)})

    scanner = CodeScanner(root, max_files=2)
    scanner.scan()

    assert scanner.files_scanned == 2
    assert scanner.scan_health()["truncated"] is True


def test_redacted_paths_drop_directories(project):
    root = project({"pkg/mod.py": "import heapq\nheapq.heapify([])\n"})

    scanner = CodeScanner(root, redact_paths=True)
    dsa, _ = scanner.scan()

    assert dsa["heap_priority"] == ["mod.py"]


def test_syntax_error_file_is_counted_as_unparsed(project):
    root = project({"broken.py": "def f(:\n    pass\n"})

    scanner = CodeScanner(root)
    scanner.scan()

    assert scanner.unparsed_files == 1
    assert scanner.has_coverage_gaps is True


def test_scanner_is_deterministic(project):
    files = {
        "b.py": "import heapq\nheapq.heapify([])\n",
        "a.py": "from collections import defaultdict\nd = defaultdict(int)\n",
    }
    root = project(files)

    first = CodeScanner(root).scan()
    second = CodeScanner(root).scan()

    assert first == second
