"""Bounded Java pilot adapter, rules, signals, and package provider."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS
from cqa_analyzer.languages.java import (
    JavaArchitectureSignalProvider,
    JavaLanguageAdapter,
    JavaRulePack,
    _strip_java_comments_and_strings,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile


def parse_java(source: str, name: str = "Service.java"):
    source_file = SourceFile(
        path=Path(name),
        display_path=name,
        identity_path=f"src/{name}",
        content=source,
    )
    return JavaLanguageAdapter().parse(source_file)


def signal_ids(parsed, category):
    return {
        o.signal_id
        for o in JavaArchitectureSignalProvider().evaluate(parsed)
        if o.category == category
    }


def scan_json(root):
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    return result, json.loads(result.output)


_POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
"""


def test_adapter_extracts_package_imports_and_identifiers():
    parsed = parse_java(
        "package com.example.svc;\n"
        "import java.util.PriorityQueue;\n"
        "import static org.junit.jupiter.api.Assertions.assertEquals;\n"
        "import com.google.common.collect.*;\n"
        "@RestController\n"
        "public class OrderService {\n"
        "  private final PriorityQueue<Integer> queue = new PriorityQueue<>();\n"
        "  public void run() { Collections.sort(items); }\n"
        "}\n"
    )
    assert parsed.complete
    assert parsed.facts.package_name == "com.example.svc"
    assert set(parsed.facts.imports) == {
        "java.util.PriorityQueue",
        "org.junit.jupiter.api.Assertions.assertEquals",
        "com.google.common.collect",
    }
    identifiers = set(parsed.facts.identifiers)
    assert {
        "OrderService",
        "RestController",
        "PriorityQueue",
        "Collections",
        "sort",
        "Collections.sort",
        "run",
    } <= identifiers
    assert "class" not in identifiers
    assert "new" not in identifiers


def test_comments_strings_chars_and_text_blocks_are_blanked():
    source = (
        "// dijkstra here\n"
        "/* new Trie() */\n"
        'String a = "bloomFilter";\n'
        "char c = '\"';\n"
        'String tb = """\n  backtracking\n  """;\n'
        "run();\n"
    )
    blanked, complete = _strip_java_comments_and_strings(source)
    assert complete
    for word in ("dijkstra", "Trie", "bloomFilter", "backtracking"):
        assert word not in blanked
    assert "run" in blanked
    assert len(blanked.splitlines()) == len(source.splitlines())


def test_empty_catch_is_reported_and_handled_catch_is_not():
    bad = parse_java("class A {\n  void f() {\n    try { g(); } catch (Exception e) {}\n  }\n}\n")
    good = parse_java(
        "class A {\n  void f() {\n    try { g(); } catch (Exception e) { log(e); }\n  }\n}\n"
    )
    findings = [f for f in JavaRulePack().evaluate(bad) if f.rule_id == "JAVA-COR-001"]
    assert [f.rule_id for f in findings] == ["JAVA-COR-001"]
    assert findings[0].location.line == 3
    assert [f for f in JavaRulePack().evaluate(good) if f.rule_id == "JAVA-COR-001"] == []


def test_every_java_pattern_id_is_scored_by_the_shared_catalog():
    assert set(JAVA_DSA_PATTERNS) <= set(DSA_PATTERNS)
    assert set(JAVA_DESIGN_PATTERNS) <= set(SYSTEM_DESIGN_PATTERNS)


def test_spring_and_collections_fire_signals():
    parsed = parse_java(
        "package x;\n"
        "import org.springframework.web.bind.annotation.RestController;\n"
        "import jakarta.persistence.Entity;\n"
        "import java.util.HashMap;\n"
        "@RestController\n"
        "class C { HashMap<String, Integer> m = new HashMap<>(); }\n"
    )
    assert "hash_map" in signal_ids(parsed, "architecture.dsa")
    design = signal_ids(parsed, "architecture.design")
    assert {"api_design", "database_orm"} <= design


def test_literal_mentions_are_not_evidence_and_generic_needs_corroboration():
    parsed = parse_java('class C { String s = "dijkstra trie"; Set<String> visited; }\n')
    dsa = signal_ids(parsed, "architecture.dsa")
    assert "dijkstra" not in dsa
    assert "trie" not in dsa
    assert "graph_traversal" not in dsa


def test_cache_codec_round_trips_facts():
    adapter = JavaLanguageAdapter()
    source_file = SourceFile(
        path=Path("A.java"),
        display_path="A.java",
        identity_path="A.java",
        content="package p;\nimport java.util.List;\nclass A { void f() { g(); } }\n",
    )
    parsed = adapter.parse(source_file)
    restored = adapter.deserialize_parsed(source_file, adapter.serialize_parsed(parsed))
    assert restored.facts == parsed.facts
    assert restored.complete == parsed.complete


def test_pom_dependencies_and_conservative_drift(project):
    root = project(
        {
            "pom.xml": _POM,
            "src/main/java/com/example/A.java": (
                "package com.example;\n"
                "import com.google.common.collect.Lists;\n"
                "import com.google.gson.Gson;\n"
                "import com.fasterxml.jackson.databind.ObjectMapper;\n"
                "class A {}\n"
            ),
        }
    )
    result, payload = scan_json(root)
    assert result.exit_code == 0
    drift = [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]
    # guava declared -> fine; gson is a curated direct library -> flagged;
    # jackson is transitive-typical -> deliberately never flagged.
    assert len(drift) == 1
    assert "'com.google.gson'" in drift[0]["message"]
    assert drift[0]["location"]["path"] == "pom.xml"
    manifest = payload["project_analyses"]["java:package"]["result"]["manifests"][0]
    assert manifest["kind"] == "maven"
    assert manifest["artifact"] == "demo"
    assert manifest["declared_dependencies"] == ["com.google.guava:guava"]


def test_gradle_manifest_is_parsed(project):
    root = project(
        {
            "build.gradle.kts": (
                "dependencies {\n"
                '    implementation("com.google.code.gson:gson:2.11.0")\n'
                '    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")\n'
                "}\n"
            ),
            "src/A.java": "import com.google.gson.Gson;\nclass A {}\n",
        }
    )
    _, payload = scan_json(root)
    assert not [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]
    manifest = payload["project_analyses"]["java:package"]["result"]["manifests"][0]
    assert manifest["kind"] == "gradle"
    assert "com.google.code.gson:gson" in manifest["declared_dependencies"]


def test_gradle_version_catalog_and_platform_bom_declare_dependencies(project):
    # Staff review C1: `implementation(libs.gson)` declared nothing, so
    # every catalog-using project drifted on every curated library.
    root = project(
        {
            "gradle/libs.versions.toml": (
                '[versions]\ngson = "2.11.0"\n\n[libraries]\n'
                'gson = { module = "com.google.code.gson:gson", version.ref = "gson" }\n'
                'guava-core = { group = "com.google.guava", name = "guava", '
                'version = "33.0.0-jre" }\n'
                'jackson = "com.fasterxml.jackson.core:jackson-databind:2.17.0"\n\n'
                '[bundles]\njson = ["gson", "jackson"]\n'
            ),
            "build.gradle.kts": (
                "dependencies {\n"
                "    implementation(libs.gson)\n"
                "    implementation(libs.guava.core)\n"
                "    testImplementation(libs.bundles.json)\n"
                "    implementation(platform("
                '"org.springframework.boot:spring-boot-dependencies:3.3.0"))\n'
                "}\n"
            ),
            "src/A.java": (
                "import com.google.gson.Gson;\nimport com.google.common.collect.Lists;\n"
                "import com.fasterxml.jackson.databind.ObjectMapper;\nclass A {}\n"
            ),
        }
    )
    _, payload = scan_json(root)
    assert not [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]
    manifest = payload["project_analyses"]["java:package"]["result"]["manifests"][0]
    declared = manifest["declared_dependencies"]
    assert {
        "com.google.code.gson:gson",
        "com.google.guava:guava",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.springframework.boot:spring-boot-dependencies",
    } <= set(declared)
    assert manifest["unresolved_catalog_refs"] == 0


def test_gradle_unresolvable_catalog_accessor_suppresses_drift_claims(project):
    root = project(
        {
            "build.gradle.kts": "dependencies {\n    implementation(libs.mystery)\n}\n",
            "src/A.java": "import com.google.gson.Gson;\nclass A {}\n",
        }
    )
    _, payload = scan_json(root)
    # No catalog file: we cannot know what libs.mystery is, so no claim.
    assert not [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]
    manifest = payload["project_analyses"]["java:package"]["result"]["manifests"][0]
    assert manifest["unresolved_catalog_refs"] == 1


def test_nested_module_uses_nearest_manifest_and_parent_chain(project):
    root = project(
        {
            "pom.xml": _POM.replace("guava", "guava"),
            "svc/pom.xml": _POM.replace(
                "<groupId>com.google.guava</groupId>\n      <artifactId>guava</artifactId>",
                "<groupId>com.google.code.gson</groupId>\n      <artifactId>gson</artifactId>",
            ),
            "svc/src/A.java": (
                "import com.google.common.collect.Lists;\n"
                "import com.google.gson.Gson;\nclass A {}\n"
            ),
        }
    )
    _, payload = scan_json(root)
    # guava comes from the parent pom, gson from the module pom: no drift.
    assert not [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]


def test_starter_provided_test_libraries_are_never_flagged(project):
    # AssertJ and Mockito arrive via spring-boot-starter-test; a missing
    # direct declaration is normal and must not be reported.
    root = project(
        {
            "pom.xml": _POM,
            "src/test/java/T.java": (
                "import org.assertj.core.api.Assertions;\n"
                "import org.mockito.Mockito;\nclass T {}\n"
            ),
        }
    )
    _, payload = scan_json(root)
    assert not [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]


def test_pom_with_doctype_is_rejected_fail_closed(project):
    root = project(
        {
            "pom.xml": '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><project/>',
            "A.java": "import com.google.gson.Gson;\nclass A {}\n",
        }
    )
    _, payload = scan_json(root)
    rules = [f["rule_id"] for f in payload["findings"] if f["rule_id"].startswith("JAVA-PKG")]
    assert rules == ["JAVA-PKG-002"]
    assert payload["analysis_health"]["authoritative"] is False


def test_java_only_project_earns_a_real_score(project):
    root = project(
        {
            "A.java": (
                "import java.util.PriorityQueue;\n"
                "import org.slf4j.Logger;\n"
                "class A { PriorityQueue<Integer> pq = new PriorityQueue<>(); Logger logger; }\n"
            ),
        }
    )
    result, payload = scan_json(root)
    assert result.exit_code == 0
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["scan_health"]["languages"] == {"java": 1}
    assert "heap_priority" in payload["dsa_patterns"]


def test_version_catalog_dotted_keys_flatten_to_dashed_aliases(project):
    # Round 2, C3: `groovy.core = {...}` is TOML nesting; Gradle reads it as
    # alias `groovy-core`, accessor `libs.groovy.core`.
    root = project(
        {
            "gradle/libs.versions.toml": (
                "[libraries]\n"
                'groovy.core = { module = "org.codehaus.groovy:groovy", version = "3.0.5" }\n'
                'groovy.json = { module = "org.codehaus.groovy:groovy-json", version = "3.0.5" }\n'
                'gson = "com.google.code.gson:gson:2.11.0"\n'
            ),
            "build.gradle.kts": (
                "dependencies {\n    implementation(libs.groovy.core)\n"
                "    implementation(libs.gson)\n}\n"
            ),
            "src/A.java": "import com.google.gson.Gson;\nclass A {}\n",
        }
    )
    _, payload = scan_json(root)
    manifest = payload["project_analyses"]["java:package"]["result"]["manifests"][0]
    assert manifest["unresolved_catalog_refs"] == 0
    assert {"org.codehaus.groovy:groovy", "com.google.code.gson:gson"} <= set(
        manifest["declared_dependencies"]
    )
    assert not [f for f in payload["findings"] if f["rule_id"] == "JAVA-PKG-001"]
