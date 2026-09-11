"""Bounded C/C++ pilot: lexer, facts, rule, signals, and CMake drift."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.c_patterns import C_DESIGN_PATTERNS, C_DSA_PATTERNS
from cqa_analyzer.languages.c_family import (
    CArchitectureSignalProvider,
    CLanguageAdapter,
    CRulePack,
    _strip_c_comments_and_strings,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile


def parse_c(source: str, name: str = "main.cpp"):
    return CLanguageAdapter().parse(SourceFile(Path(name), name, f"src/{name}", source))


def signal_ids(parsed, category):
    return {
        o.signal_id
        for o in CArchitectureSignalProvider().evaluate(parsed)
        if o.category == category
    }


def scan_json(root):
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    return result, json.loads(result.output)


def test_directives_are_blanked_but_includes_are_captured():
    parsed = parse_c(
        "#include <unordered_map>\n"
        '#include "util/trie.h"\n'
        "#  include <boost/asio.hpp>\n"
        "#define DIJKSTRA(x) \\\n    run_dijkstra(x)\n"
        "int main() { return 0; }\n"
    )
    assert parsed.complete
    assert set(parsed.facts.includes) == {"unordered_map", "util/trie.h", "boost/asio.hpp"}
    # Macro bodies are never evidence.
    assert "dijkstra" not in parsed.facts.code_text.lower()
    assert "run_dijkstra" not in parsed.facts.identifiers


def test_lexer_handles_raw_strings_digit_separators_and_continued_comments():
    source = (
        'auto s = R"json({"trie": "dijkstra"})json";\n'
        "constexpr int big = 1'000'000;\n"
        "// comment continues on next line \\\n   BloomFilter here\n"
        "int after = 1;\n"
        'auto t = u8R"x(backtracking)x";\n'
        "char c = '\\'';\n"
        'BAR"not raw" ;\n'
        "run();\n"
    )
    blanked, complete = _strip_c_comments_and_strings(source)
    assert complete
    for word in ("trie", "dijkstra", "BloomFilter", "backtracking", "not raw"):
        assert word not in blanked, word
    assert "big = 1'000'000" in blanked
    assert "after" in blanked and "run" in blanked and "BAR" in blanked
    assert len(blanked.splitlines()) == len(source.splitlines())


def test_digit_separators_versus_char_literals():
    # Staff review B4/B5: `case'a'` and `u8'a'` were read as digit
    # separators because `e`/`8` and `a` are hex digits.
    source = (
        "switch (c) {\ncase'a': x = 1; break;\n}\n"
        "char8_t c = u8'a'; const char* s = \"trie\";\n"
        "auto big = 1'000'000 + 0xFF'FFu;\n"
        "run();\n"
    )
    blanked, complete = _strip_c_comments_and_strings(source)
    assert complete
    assert "trie" not in blanked and "run" in blanked and "break" in blanked
    assert "1'000'000 + 0xFF'FFu" in blanked


def test_metadata_pass_keeps_directives_and_strings():
    source = '#include <vector>\nconst char* s = "x";\n'
    kept, complete = _strip_c_comments_and_strings(
        source,
        blank_strings=False,
        blank_directives=False,
    )
    assert complete and kept == source


def test_identifier_extraction_covers_cpp_shapes():
    parsed = parse_c(
        "namespace svc {\n"
        "struct TreeNode { TreeNode* left; };\n"
        "class LruCache final : public Base {};\n"
        "typedef struct list_node { int v; } ListNode;\n"
        "using std::priority_queue;\n"
        "std::unordered_map<int, int> memo;\n"
        "void bfs(const Graph& graph) {\n"
        "  std::sort(v.begin(), v.end());\n"
        "  queue.push_back(1); ptr->pop_front();\n"
        "  auto visited = std::vector<bool>(n);\n"
        "}\n}\n"
    )
    identifiers = set(parsed.facts.identifiers)
    assert {
        "svc",
        "TreeNode",
        "LruCache",
        "ListNode",
        "list_node",
        "std::priority_queue",
        "priority_queue",
        "std::unordered_map",
        "unordered_map",
        "memo",
        "bfs",
        "graph",
        "std::sort",
        "sort",
        "push_back",
        "pop_front",
        "visited",
    } <= identifiers
    assert "struct" not in identifiers and "std" not in identifiers


def test_empty_catch_rule():
    bad = parse_c("void f() {\n  try { g(); } catch (const std::exception&) {}\n}\n")
    good = parse_c("void f() {\n  try { g(); } catch (const std::exception&) { log(); }\n}\n")
    findings = list(CRulePack().evaluate(bad))
    assert [f.rule_id for f in findings] == ["C-COR-001"]
    assert findings[0].location.line == 2
    assert list(CRulePack().evaluate(good)) == []


def test_catalog_ids_are_in_the_shared_catalog():
    assert set(C_DSA_PATTERNS) <= set(DSA_PATTERNS)
    assert set(C_DESIGN_PATTERNS) <= set(SYSTEM_DESIGN_PATTERNS)
    assert len(C_DSA_PATTERNS) == 29 and len(C_DESIGN_PATTERNS) == 27


def test_includes_and_identifiers_fire_signals():
    parsed = parse_c(
        "#include <unordered_map>\n#include <thread>\n#include <mutex>\n"
        "#include <spdlog/spdlog.h>\n#include <gtest/gtest.h>\n"
        "#include <grpcpp/grpcpp.h>\n"
        "std::unordered_map<int, int> memo;\n"
        "std::mutex m; std::lock_guard<std::mutex> g(m);\n"
        "std::priority_queue<int> pq;\n"
        "TEST_F(Suite, Case) {}\n"
    )
    dsa = signal_ids(parsed, "architecture.dsa")
    assert {"hash_map", "heap_priority", "dynamic_programming"} <= dsa
    design = signal_ids(parsed, "architecture.design")
    assert {"concurrency", "logging", "testing", "api_design"} <= design


def test_literals_macros_and_lone_queue_include_are_not_evidence():
    parsed = parse_c(
        "#include <queue>\n"
        '#define TRIE_SIZE 26\nconst char* s = "dijkstra bloom_filter";\n'
        "/* BloomFilter */\nint x;\n"
    )
    dsa = signal_ids(parsed, "architecture.dsa")
    assert not ({"trie", "dijkstra", "bloom_filter", "heap_priority"} & dsa)


def test_shared_catalog_precision_regressions_from_c_calibration():
    # hiredis: `redisContextSSLFuncs` contains "lfu"; keepalive `interval`.
    parsed = parse_c(
        "static redisContextFuncs redisContextSSLFuncs;\n"
        "int interval = 15; setKeepAlive(fd, interval);\n"
    )
    dsa = signal_ids(parsed, "architecture.dsa")
    assert "lfu_cache" not in dsa and "interval_operations" not in dsa
    real = parse_c("struct LFUCache { int min_freq; }; std::vector<Interval> intervals;\n")
    assert {"lfu_cache", "interval_operations"} <= signal_ids(real, "architecture.dsa")


def test_cache_codec_round_trips_facts():
    adapter = CLanguageAdapter()
    src = SourceFile(Path("a.c"), "a.c", "a.c", "#include <stdio.h>\nint f(void) { return g(); }\n")
    parsed = adapter.parse(src)
    restored = adapter.deserialize_parsed(src, adapter.serialize_parsed(parsed))
    assert restored.facts == parsed.facts


def test_cmake_drift_is_conservative(project):
    root = project(
        {
            "CMakeLists.txt": (
                "cmake_minimum_required(VERSION 3.20)\nproject(demo CXX)\n"
                "find_package(fmt REQUIRED)\n"
                "FetchContent_Declare(googletest GIT_REPOSITORY x)\n"
                "target_link_libraries(demo PRIVATE fmt::fmt)\n"
            ),
            "src/main.cpp": (
                "#include <fmt/core.h>\n#include <gtest/gtest.h>\n"
                "#include <spdlog/spdlog.h>\n#include <vector>\nint main() {}\n"
            ),
            "tools/sub/x.cpp": "#include <boost/asio.hpp>\nint y;\n",
        }
    )
    result, payload = scan_json(root)
    assert result.exit_code == 0
    drift = [f for f in payload["findings"] if f["rule_id"] == "C-PKG-001"]
    # fmt via find_package, gtest via FetchContent: declared. spdlog and
    # boost (governed by the root manifest) are not.
    assert [f["message"].split("'")[1] for f in drift] == ["boost/", "spdlog/"]
    assert drift[0]["confidence"] == "medium"
    manifest = payload["project_analyses"]["c_cpp:package"]["result"]["manifests"][0]
    assert manifest["kind"] == "cmake" and manifest["project"] == "demo"
    assert manifest["find_packages"] == ["fmt"]
    assert manifest["undeclared_headers"] == ["boost/", "spdlog/"]


def test_cmake_tokens_are_whole_words_and_comments_do_not_declare(project):
    # Staff review C2: `"z" in text` made zlib undetectable; a URL in a
    # comment "declared" curl.
    root = project(
        {
            "CMakeLists.txt": (
                "project(demo C)\n"
                "# see https://curl.se for curl docs\n"
                "add_executable(demo main.c)\n"
                "target_link_libraries(demo PRIVATE ZLIB::ZLIB)\n"
            ),
            "main.c": (
                "#include <zlib.h>\n#include <curl/curl.h>\n" "#include <openssl/ssl.h>\nint x;\n"
            ),
        }
    )
    _, payload = scan_json(root)
    drift = sorted(
        f["message"].split("'")[1] for f in payload["findings"] if f["rule_id"] == "C-PKG-001"
    )
    # zlib declared via imported target; curl only in a comment; openssl absent.
    assert drift == ["curl/curl.h", "openssl/"]


def test_c_only_project_earns_a_real_score_and_reports_language(project):
    root = project(
        {
            "lib.c": (
                "#include <pthread.h>\n#include <syslog.h>\n"
                "static pthread_mutex_t lock;\n"
                'void worker(void) { pthread_mutex_lock(&lock); syslog(1, "x"); }\n'
                "int visited[64]; int adjacency[8][8];\n"
            ),
        }
    )
    result, payload = scan_json(root)
    assert result.exit_code == 0
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["scan_health"]["languages"] == {"c_cpp": 1}
    assert "graph_traversal" in payload["dsa_patterns"]
    assert {"concurrency", "logging"} <= set(payload["design_patterns"])


def test_variable_bound_link_lines_suppress_drift_claims(project):
    # Round 2, C4: `target_link_libraries(x ${DEPS})` may bind anything.
    root = project(
        {
            "CMakeLists.txt": (
                "project(demo C)\nset(DEPS CURL::libcurl)\n"
                "add_executable(demo main.c)\ntarget_link_libraries(demo PRIVATE ${DEPS})\n"
            ),
            "main.c": "#include <curl/curl.h>\nint x;\n",
        }
    )
    _, payload = scan_json(root)
    assert not [f for f in payload["findings"] if f["rule_id"] == "C-PKG-001"]
    manifest = payload["project_analyses"]["c_cpp:package"]["result"]["manifests"][0]
    assert manifest["variable_bound_links"] is True
