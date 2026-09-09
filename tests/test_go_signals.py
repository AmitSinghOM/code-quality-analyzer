"""Go architecture signal patterns and provider."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.go_patterns import GO_DESIGN_PATTERNS, GO_DSA_PATTERNS
from cqa_analyzer.languages.go import (
    GoArchitectureSignalProvider,
    GoLanguageAdapter,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile


def observations_for(source: str):
    source_file = SourceFile(
        path=Path("service.go"),
        display_path="service.go",
        identity_path="pkg/service.go",
        content=source,
    )
    parsed = GoLanguageAdapter().parse(source_file)
    return list(GoArchitectureSignalProvider().evaluate(parsed))


def signal_ids(observations, category):
    return {
        observation.signal_id
        for observation in observations
        if observation.category == category
    }


def test_every_go_pattern_id_is_scored_by_the_shared_catalog():
    # The rater resolves weights from the Python definitions; a Go-only
    # ID would silently contribute nothing to the score.
    assert set(GO_DSA_PATTERNS) <= set(DSA_PATTERNS)
    assert set(GO_DESIGN_PATTERNS) <= set(SYSTEM_DESIGN_PATTERNS)
    for definition in (
        list(GO_DSA_PATTERNS.values()) + list(GO_DESIGN_PATTERNS.values())
    ):
        assert definition["description"]
        assert definition["min_signals"] >= 1


def test_container_heap_usage_fires_heap_priority():
    observations = observations_for(
        "package pq\n"
        "\n"
        'import "container/heap"\n'
        "\n"
        "type PriorityQueue []int\n"
        "\n"
        "func Take(pq *PriorityQueue) int {\n"
        "\theap.Init(pq)\n"
        "\treturn heap.Pop(pq).(int)\n"
        "}\n"
    )

    dsa = signal_ids(observations, "architecture.dsa")
    assert "heap_priority" in dsa
    heap = next(
        observation
        for observation in observations
        if observation.signal_id == "heap_priority"
    )
    assert heap.evidence
    assert heap.path == "service.go"


def test_comment_and_string_mentions_are_not_evidence():
    observations = observations_for(
        "package svc\n"
        "\n"
        "// We should use dijkstra and a trie here.\n"
        "func Describe() string {\n"
        '\treturn "backtracking with a bloom_filter"\n'
        "}\n"
    )

    dsa = signal_ids(observations, "architecture.dsa")
    assert "dijkstra" not in dsa
    assert "trie" not in dsa
    assert "backtracking" not in dsa
    assert "bloom_filter" not in dsa


def test_generic_patterns_require_corroboration():
    # A lone "visited" identifier is not a graph traversal (min_signals 2).
    observations = observations_for(
        "package svc\n"
        "\n"
        "func Track(visited map[string]bool) int {\n"
        "\treturn len(visited)\n"
        "}\n"
    )

    assert "graph_traversal" not in signal_ids(
        observations, "architecture.dsa"
    )


def test_corroborated_graph_traversal_fires():
    observations = observations_for(
        "package svc\n"
        "\n"
        "func BFS(graph map[string][]string, start string) []string {\n"
        "\tvisited := map[string]bool{start: true}\n"
        "\tqueue := []string{start}\n"
        "\tfor len(queue) > 0 {\n"
        "\t\tnode := queue[0]\n"
        "\t\tqueue = queue[1:]\n"
        "\t\tfor _, next := range graph[node] {\n"
        "\t\t\tif !visited[next] {\n"
        "\t\t\t\tvisited[next] = true\n"
        "\t\t\t\tqueue = append(queue, next)\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "\treturn nil\n"
        "}\n"
    )

    assert "graph_traversal" in signal_ids(observations, "architecture.dsa")


def test_net_http_import_fires_api_design():
    observations = observations_for(
        "package api\n"
        "\n"
        'import "net/http"\n'
        "\n"
        "func Register(mux *http.ServeMux) {\n"
        "\tmux.HandleFunc(\"/health\", nil)\n"
        "}\n"
    )

    assert "api_design" in signal_ids(observations, "architecture.design")


def test_go_only_project_earns_a_real_score(project):
    root = project({
        "pq.go": (
            "package pq\n"
            "\n"
            'import "container/heap"\n'
            "\n"
            "func Take(h heap.Interface) any {\n"
            "\theap.Init(h)\n"
            "\treturn heap.Pop(h)\n"
            "}\n"
        ),
        "api.go": (
            "package pq\n"
            "\n"
            'import "net/http"\n'
            "\n"
            "func Register(mux *http.ServeMux) {\n"
            "\tmux.HandleFunc(\"/health\", nil)\n"
            "}\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == 0
    assert payload["architecture_signal_score"] > 1.0
    assert "heap_priority" in payload["dsa_patterns"]
    assert "api_design" in payload["design_patterns"]
