"""Bounded Kotlin pilot: adapter, rules, signals, and JVM package reuse."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.kotlin_patterns import KOTLIN_DESIGN_PATTERNS, KOTLIN_DSA_PATTERNS
from cqa_analyzer.languages.kotlin import (
    KotlinArchitectureSignalProvider,
    KotlinLanguageAdapter,
    KotlinRulePack,
    _strip_kotlin_comments_and_strings,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile


def parse_kt(source: str, name: str = "Service.kt"):
    return KotlinLanguageAdapter().parse(SourceFile(Path(name), name, f"src/{name}", source))


def signal_ids(parsed, category):
    return {
        o.signal_id
        for o in KotlinArchitectureSignalProvider().evaluate(parsed)
        if o.category == category
    }


def scan_json(root):
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    return result, json.loads(result.output)


def test_adapter_extracts_package_imports_and_identifiers():
    parsed = parse_kt(
        "package com.example.svc\n"
        "import kotlinx.coroutines.launch\n"
        "import java.util.PriorityQueue as PQ\n"
        "import io.ktor.server.routing.*\n"
        "@Serializable\n"
        "data class Order(val id: Int, var total: Double)\n"
        "object Registry { fun <T> register(item: T) = items.add(item) }\n"
        "fun String.slug(): String = lowercase()\n"
        "val queue: PriorityQueue<Int> = PriorityQueue()\n"
    )
    assert parsed.complete
    assert parsed.facts.package_name == "com.example.svc"
    assert set(parsed.facts.imports) == {
        "kotlinx.coroutines.launch",
        "java.util.PriorityQueue",
        "io.ktor.server.routing",
    }
    identifiers = set(parsed.facts.identifiers)
    assert {
        "Order",
        "Registry",
        "register",
        "slug",
        "queue",
        "total",
        "id",
        "Serializable",
        "PriorityQueue",
        "Int",
        "Double",
        "items",
        "add",
        "items.add",
    } <= identifiers
    assert "fun" not in identifiers and "val" not in identifiers


def test_templates_raw_strings_and_nested_comments_are_blanked():
    source = (
        "/* outer /* nested dijkstra */ still comment */\n"
        'val a = "bloomFilter $name and ${compute("}")} tail"\n'
        'val b = """\n  raw backtracking ${Trie()}\n  """\n'
        "run()\n"
    )
    blanked, complete = _strip_kotlin_comments_and_strings(source)
    assert complete
    for word in ("dijkstra", "bloomFilter", "compute", "tail", "backtracking", "Trie"):
        assert word not in blanked, word
    assert "run" in blanked
    assert len(blanked.splitlines()) == len(source.splitlines())


def test_raw_string_with_trailing_quote_content_terminates_correctly():
    # Kotlin: `"""a "$x""""` ends at the LAST three quotes; the extra one
    # is content. Found live in ktor-samples.
    source = 'val s = """result is: "$response""""\nrun()\n'
    blanked, complete = _strip_kotlin_comments_and_strings(source)
    assert complete
    assert "result" not in blanked and "response" not in blanked
    assert "run" in blanked


def test_backtick_identifiers_with_apostrophes_are_code():
    # javalin: fun `can't set duplicate cookies`() left 15 test files
    # incomplete because the apostrophe opened a char literal.
    source = "@Test\nfun `headers aren't set when origin doesn't match`() = run {\n  verify()\n}\n"
    blanked, complete = _strip_kotlin_comments_and_strings(source)
    assert complete
    assert "verify" in blanked
    assert len(blanked.splitlines()) == len(source.splitlines())


def test_multi_dollar_interpolation_treats_single_dollar_as_literal():
    # Kotlin 2.2 `$$"""..."""`: `${` is text, `$${` is the template. Found
    # live in ktor's YamlConfigTest.
    source = 'val c = $$"""\n  ktor: ${unclosed\n  port: $${port}\n"""\nrun()\n'
    blanked, complete = _strip_kotlin_comments_and_strings(source)
    assert complete
    assert "unclosed" not in blanked and "port" not in blanked
    assert "run" in blanked


def test_metadata_pass_preserves_content_with_same_structure():
    source = 'val s = "x ${f("}")} y"\nimport org.koin.core.Koin\n'
    kept, complete = _strip_kotlin_comments_and_strings(source, blank_strings=False)
    assert complete and kept == source


def test_empty_catch_is_reported_and_handled_catch_is_not():
    bad = parse_kt("fun f() {\n  try { g() } catch (e: Exception) {}\n}\n")
    good = parse_kt("fun f() {\n  try { g() } catch (e: Exception) { log(e) }\n}\n")
    findings = [f for f in KotlinRulePack().evaluate(bad) if f.rule_id == "KT-COR-001"]
    assert [f.rule_id for f in findings] == ["KT-COR-001"]
    assert findings[0].location.line == 2
    assert [f for f in KotlinRulePack().evaluate(good) if f.rule_id == "KT-COR-001"] == []


def test_kotlin_catalog_extends_java_and_stays_in_shared_catalog():
    from cqa_analyzer.java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS

    assert set(KOTLIN_DSA_PATTERNS) == set(JAVA_DSA_PATTERNS)
    assert set(KOTLIN_DESIGN_PATTERNS) == set(JAVA_DESIGN_PATTERNS)
    assert set(KOTLIN_DSA_PATTERNS) <= set(DSA_PATTERNS)
    assert set(KOTLIN_DESIGN_PATTERNS) <= set(SYSTEM_DESIGN_PATTERNS)
    # Kotlin additions are present without mutating the Java catalog.
    assert "io.ktor" in KOTLIN_DESIGN_PATTERNS["api_design"]["imports"]
    assert "io.ktor" not in JAVA_DESIGN_PATTERNS["api_design"]["imports"]


def test_coroutines_ktor_and_collection_builders_fire_signals():
    parsed = parse_kt(
        "import kotlinx.coroutines.launch\n"
        "import kotlinx.coroutines.coroutineScope\n"
        "import io.ktor.server.application.*\n"
        "import org.jetbrains.exposed.sql.Database\n"
        "fun main() = coroutineScope { launch { } }\n"
        "val counts = mutableMapOf<String, Int>()\n"
    )
    assert "hash_map" in signal_ids(parsed, "architecture.dsa")
    design = signal_ids(parsed, "architecture.design")
    assert {"concurrency", "api_design", "database_orm"} <= design


def test_literal_mentions_are_not_evidence():
    parsed = parse_kt('val s = "dijkstra trie CircuitBreaker"\nval visited = setOf(1)\n')
    dsa = signal_ids(parsed, "architecture.dsa")
    assert not ({"dijkstra", "trie", "graph_traversal"} & dsa)
    assert "resilience" not in signal_ids(parsed, "architecture.design")


def test_cache_codec_round_trips_facts():
    adapter = KotlinLanguageAdapter()
    src = SourceFile(Path("A.kt"), "A.kt", "A.kt", "package p\nimport a.B\nfun f() = g()\n")
    parsed = adapter.parse(src)
    restored = adapter.deserialize_parsed(src, adapter.serialize_parsed(parsed))
    assert restored.facts == parsed.facts


def test_gradle_kts_drift_uses_kotlin_rule_ids(project):
    root = project(
        {
            "build.gradle.kts": (
                "dependencies {\n"
                '    implementation("com.google.guava:guava:33.0.0-jre")\n'
                "}\n"
            ),
            "src/main/kotlin/A.kt": (
                "import com.google.common.collect.Lists\n" "import com.google.gson.Gson\nclass A\n"
            ),
        }
    )
    result, payload = scan_json(root)
    assert result.exit_code == 0
    drift = [f for f in payload["findings"] if f["rule_id"].endswith("PKG-001")]
    assert [f["rule_id"] for f in drift] == ["KT-PKG-001"]
    assert "'com.google.gson'" in drift[0]["message"]
    manifest = payload["project_analyses"]["kotlin:package"]["result"]["manifests"][0]
    assert manifest["kind"] == "gradle"


def test_kotlin_only_project_earns_a_real_score(project):
    root = project(
        {
            "A.kt": (
                "import java.util.PriorityQueue\n"
                "import io.github.oshai.kotlinlogging.KotlinLogging\n"
                "private val logger = KotlinLogging.logger {}\n"
                "val pq = PriorityQueue<Int>()\n"
            ),
        }
    )
    result, payload = scan_json(root)
    assert result.exit_code == 0
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["scan_health"]["languages"] == {"kotlin": 1}
    assert "heap_priority" in payload["dsa_patterns"]
    assert "logging" in payload["design_patterns"]
