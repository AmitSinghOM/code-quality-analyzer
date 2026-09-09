"""TypeScript/JavaScript architecture signal patterns and provider."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.languages.typescript import (
    TsArchitectureSignalProvider,
    TypeScriptLanguageAdapter,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile
from cqa_analyzer.ts_patterns import TS_DESIGN_PATTERNS, TS_DSA_PATTERNS


def observations_for(source: str, name: str = "service.ts"):
    source_file = SourceFile(
        path=Path(name),
        display_path=name,
        identity_path=f"src/{name}",
        content=source,
    )
    parsed = TypeScriptLanguageAdapter().parse(source_file)
    return list(TsArchitectureSignalProvider().evaluate(parsed))


def signal_ids(observations, category):
    return {
        observation.signal_id
        for observation in observations
        if observation.category == category
    }


def test_every_ts_pattern_id_is_scored_by_the_shared_catalog():
    # The rater resolves weights from the Python definitions; a TS-only
    # ID would silently contribute nothing to the score.
    assert set(TS_DSA_PATTERNS) <= set(DSA_PATTERNS)
    assert set(TS_DESIGN_PATTERNS) <= set(SYSTEM_DESIGN_PATTERNS)
    for definition in (
        list(TS_DSA_PATTERNS.values()) + list(TS_DESIGN_PATTERNS.values())
    ):
        assert definition["description"]
        assert definition["min_signals"] >= 1


def test_express_import_fires_api_design():
    observations = observations_for(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.get('/health', handler);\n"
    )

    design = signal_ids(observations, "architecture.design")
    assert "api_design" in design
    api = next(o for o in observations if o.signal_id == "api_design")
    assert api.evidence
    assert api.path == "service.ts"


def test_new_map_and_memo_fire_dsa_patterns():
    observations = observations_for(
        "export function fib(n: number): number {\n"
        "  const memo = new Map<number, number>();\n"
        "  return solve(n, memo);\n"
        "}\n"
    )

    dsa = signal_ids(observations, "architecture.dsa")
    assert "hash_map" in dsa
    assert "dynamic_programming" in dsa


def test_comment_and_string_mentions_are_not_evidence():
    observations = observations_for(
        "// use dijkstra and a trie here\n"
        "const label = 'backtracking bloom_filter';\n"
        "const tpl = `sliding_window ${'monotonic'}`;\n"
        "export const value = 1;\n"
    )

    dsa = signal_ids(observations, "architecture.dsa")
    assert "dijkstra" not in dsa
    assert "trie" not in dsa
    assert "backtracking" not in dsa
    assert "bloom_filter" not in dsa
    assert "sliding_window" not in dsa
    assert "monotonic_stack" not in dsa


def test_generic_patterns_require_corroboration():
    # A lone "visited" identifier is not a graph traversal.
    observations = observations_for(
        "export function track(visited: Set<string>) {\n"
        "  return visited.size;\n"
        "}\n"
    )

    assert "graph_traversal" not in signal_ids(
        observations, "architecture.dsa"
    )


def test_javascript_files_produce_signals_too():
    observations = observations_for(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(middleware);\n",
        name="server.js",
    )

    assert "api_design" in signal_ids(observations, "architecture.design")


def test_mixed_ts_go_python_project_aggregates_signals(project):
    root = project({
        "api.ts": (
            "import express from 'express';\n"
            "const app = express();\napp.get('/x', h);\n"
        ),
        "pq.go": (
            "package pq\n\n"
            'import "container/heap"\n\n'
            "func Take(h heap.Interface) any {\n"
            "\theap.Init(h)\n"
            "\treturn heap.Pop(h)\n"
            "}\n"
        ),
        "module.py": "import heapq\nheapq.heappush([], 1)\n",
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == 0
    assert "api_design" in payload["design_patterns"]
    assert "heap_priority" in payload["dsa_patterns"]
    # The heap pattern is corroborated from two languages' files.
    assert len(payload["dsa_patterns"]["heap_priority"]["files"]) == 2
