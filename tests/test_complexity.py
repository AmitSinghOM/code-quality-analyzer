"""Complexity analysis: async loops, scoped early exit, isolated scopes."""

from pathlib import Path

from conftest import function_node

from analyzer.complexity import (
    AdvancedComplexityAnalyzer,
    ProjectComplexityAnalyzer,
    loop_has_early_exit,
)


def analyze(source: str, name: str):
    analyzer = AdvancedComplexityAnalyzer()
    return analyzer.analyze_function(function_node(source, name), Path("sample.py"))


def test_async_for_counts_as_a_loop():
    """Regression: no visit_AsyncFor meant async code was reported as O(1)."""
    result = analyze(
        "async def consume(items):\n"
        "    total = 0\n"
        "    async for item in items:\n"
        "        total += item\n"
        "    return total\n",
        "consume",
    )

    assert result.time_complexity == "O(n)"


def test_nested_async_for_is_quadratic():
    result = analyze(
        "async def pairs(rows):\n"
        "    async for a in rows:\n"
        "        async for b in rows:\n"
        "            print(a, b)\n",
        "pairs",
    )

    assert result.time_complexity == "O(n\u00b2)"


def test_inner_break_does_not_mark_outer_loop():
    """Regression: ast.walk found the inner break from the outer loop."""
    source = (
        "def scan(rows, cols):\n"
        "    for row in rows:\n"
        "        for col in cols:\n"
        "            if col:\n"
        "                break\n"
    )
    outer = function_node(source, "scan").body[0]

    assert loop_has_early_exit(outer) is False


def test_return_inside_nested_loop_still_exits_outer():
    source = (
        "def find(rows, cols):\n"
        "    for row in rows:\n"
        "        for col in cols:\n"
        "            if col:\n"
        "                return col\n"
    )
    outer = function_node(source, "find").body[0]

    assert loop_has_early_exit(outer) is True


def test_nested_function_loops_do_not_inflate_the_parent():
    """Regression: the parent absorbed the nested definition's loop depth."""
    result = analyze(
        "def outer(rows):\n"
        "    def inner(items):\n"
        "        for a in items:\n"
        "            for b in items:\n"
        "                print(a, b)\n"
        "    return inner(rows)\n",
        "outer",
    )

    assert result.time_complexity == "O(1)"


def test_nested_function_is_analyzed_on_its_own():
    result = analyze(
        "def outer(rows):\n"
        "    def inner(items):\n"
        "        for a in items:\n"
        "            for b in items:\n"
        "                print(a, b)\n"
        "    return inner(rows)\n",
        "inner",
    )

    assert result.time_complexity == "O(n\u00b2)"


def test_recursion_inside_a_loop_is_not_called_linear():
    """A DFS fan-out has a data-dependent branching factor."""
    result = analyze(
        "def walk(node):\n"
        "    for child in node.children:\n"
        "        walk(child)\n",
        "walk",
    )

    assert result.recursion_type == "fan_out"
    assert result.time_complexity == "O(n)"
    assert result.confidence < 0.6


def test_binary_recursion_without_memo_is_exponential():
    result = analyze(
        "def fib(n):\n"
        "    if n < 2:\n"
        "        return n\n"
        "    return fib(n - 1) + fib(n - 2)\n",
        "fib",
    )

    assert result.time_complexity == "O(2^n)"


def test_memoized_recursion_is_linear():
    result = analyze(
        "from functools import lru_cache\n\n"
        "@lru_cache\n"
        "def fib(n):\n"
        "    if n < 2:\n"
        "        return n\n"
        "    return fib(n - 1) + fib(n - 2)\n",
        "fib",
    )

    assert result.uses_memoization is True
    assert result.time_complexity == "O(n)"


def test_keyword_only_params_are_seen():
    result = analyze("def f(*, rows: list, limit: int = 5):\n    return rows[:limit]\n", "f")

    assert any("Parameters: 2" in reason for reason in result.reasoning)


def test_project_analysis_reports_skips(project):
    root = project({
        "ok.py": "def f(xs):\n    for x in xs:\n        print(x)\n",
        "broken.py": "def f(:\n    pass\n",
    })

    analyzer = ProjectComplexityAnalyzer(root)
    analyzer.analyze()
    health = analyzer.analysis_health()

    assert analyzer.get_summary()["total_functions"] == 1
    assert health["skipped_by_reason"]["syntax_error"] == 1


def test_project_analysis_respects_size_cap(project):
    root = project({"big.py": "def f():\n    pass\n" + ("# pad\n" * 100)})

    analyzer = ProjectComplexityAnalyzer(root, max_file_size=32)
    analyzer.analyze()

    assert analyzer.get_summary()["total_functions"] == 0
    assert analyzer.analysis_health()["skipped_by_reason"]["too_large"] == 1
