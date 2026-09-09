"""Bounded C#/.NET pilot adapter, rules, signals, and package provider."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.csharp_patterns import (
    CSHARP_DESIGN_PATTERNS,
    CSHARP_DSA_PATTERNS,
)
from cqa_analyzer.languages.csharp import (
    CSharpArchitectureSignalProvider,
    CSharpLanguageAdapter,
    CSharpRulePack,
    _strip_csharp_comments_and_strings,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile


def parse_cs(source: str, name: str = "Service.cs"):
    source_file = SourceFile(
        path=Path(name), display_path=name, identity_path=f"src/{name}",
        content=source,
    )
    return CSharpLanguageAdapter().parse(source_file)


def signal_ids(parsed, category):
    return {
        o.signal_id
        for o in CSharpArchitectureSignalProvider().evaluate(parsed)
        if o.category == category
    }


def scan_json(root):
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    return result, json.loads(result.output)


_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <RootNamespace>Shop.Api</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="9.0.0" />
    <PackageReference Include="Serilog" Version="4.0.0" />
  </ItemGroup>
</Project>
"""


def test_adapter_extracts_usings_namespaces_and_identifiers():
    parsed = parse_cs(
        "global using System.Collections.Generic;\n"
        "using static System.Math;\n"
        "using Json = Newtonsoft.Json;\n"
        "using Microsoft.AspNetCore.Mvc;\n"
        "namespace Shop.Api.Controllers;\n"
        "[ApiController]\n"
        "public class OrdersController : ControllerBase\n"
        "{\n"
        "    private readonly Dictionary<int, string> _names = new();\n"
        "    [HttpGet] public void Get() { using var x = Open(); Console.WriteLine(1); }\n"
        "}\n"
    )
    assert parsed.complete
    assert set(parsed.facts.usings) == {
        "System.Collections.Generic", "System.Math", "Newtonsoft.Json",
        "Microsoft.AspNetCore.Mvc",
    }
    assert parsed.facts.namespaces == ("Shop.Api.Controllers",)
    identifiers = set(parsed.facts.identifiers)
    assert {
        "OrdersController", "ApiController", "HttpGet", "Dictionary",
        "Console", "WriteLine", "Console.WriteLine", "Get",
    } <= identifiers
    assert "class" not in identifiers
    assert "var" not in identifiers


def test_all_string_forms_and_comments_are_blanked():
    source = (
        "// dijkstra\n"
        "/* new Trie() */\n"
        'var a = "bloomFilter";\n'
        'var b = @"verbatim ""quoted"" backtracking";\n'
        'var c = $"interp {Compute(new[] {1, 2})} monotonic";\n'
        'var d = $@"mixed {{literal}} {x} fenwick";\n'
        'var e = """\n  raw segmentTree\n  """;\n'
        "var f = '\"';\n"
        "run();\n"
    )
    blanked, complete = _strip_csharp_comments_and_strings(source)
    assert complete
    for word in (
        "dijkstra", "Trie", "bloomFilter", "verbatim", "quoted", "backtracking",
        "interp", "Compute", "monotonic", "literal", "fenwick", "segmentTree",
    ):
        assert word not in blanked, word
    assert "run" in blanked
    assert len(blanked.splitlines()) == len(source.splitlines())


def test_metadata_pass_preserves_content_with_same_structure():
    source = 'var c = $"x {Compute("}")} y"; using Serilog;\n'
    kept, complete = _strip_csharp_comments_and_strings(source, blank_strings=False)
    assert complete
    assert kept == source


def test_empty_catch_including_filter_is_reported():
    bad = parse_cs(
        "class A { void F() {\n"
        "  try { G(); } catch (Exception e) when (e is IOException) {}\n"
        "  try { G(); } catch {}\n"
        "} }\n"
    )
    good = parse_cs("class A { void F() { try { G(); } catch (Exception e) { Log(e); } } }\n")
    findings = list(CSharpRulePack().evaluate(bad))
    assert [f.location.line for f in findings] == [2, 3]
    assert list(CSharpRulePack().evaluate(good)) == []


def test_every_csharp_pattern_id_is_scored_by_the_shared_catalog():
    assert set(CSHARP_DSA_PATTERNS) <= set(DSA_PATTERNS)
    assert set(CSHARP_DESIGN_PATTERNS) <= set(SYSTEM_DESIGN_PATTERNS)


def test_aspnet_and_collections_fire_signals():
    parsed = parse_cs(
        "using Microsoft.AspNetCore.Mvc;\n"
        "using Microsoft.EntityFrameworkCore;\n"
        "[ApiController] class C { PriorityQueue<int, int> pq = new(); }\n"
    )
    assert "heap_priority" in signal_ids(parsed, "architecture.dsa")
    assert {"api_design", "database_orm"} <= signal_ids(parsed, "architecture.design")


def test_literal_mentions_are_not_evidence():
    parsed = parse_cs('class C { string s = "dijkstra trie"; HashSet<int> visited; }\n')
    dsa = signal_ids(parsed, "architecture.dsa")
    assert "dijkstra" not in dsa and "trie" not in dsa
    assert "graph_traversal" not in dsa


def test_cache_codec_round_trips_facts():
    adapter = CSharpLanguageAdapter()
    source_file = SourceFile(
        path=Path("A.cs"), display_path="A.cs", identity_path="A.cs",
        content="using Serilog;\nnamespace P;\nclass A { void F() { G(); } }\n",
    )
    parsed = adapter.parse(source_file)
    restored = adapter.deserialize_parsed(source_file, adapter.serialize_parsed(parsed))
    assert restored.facts == parsed.facts


def test_csproj_drift_matches_prefix_both_ways_and_skips_own_and_framework(project):
    root = project({
        "Shop.Api.csproj": _CSPROJ,
        "Program.cs": (
            "using System.Linq;\n"
            "using Microsoft.AspNetCore.Builder;\n"
            "using Microsoft.EntityFrameworkCore;\n"   # package is ...SqlServer -> covered
            "using Serilog.Events;\n"                  # package Serilog -> covered
            "using Shop.Api.Data;\n"                   # own namespace -> skipped
            "using Dapper;\n"                          # not declared -> drift
            "namespace Shop.Api;\nclass Program {}\n"
        ),
    })
    result, payload = scan_json(root)
    assert result.exit_code == 0
    drift = [f for f in payload["findings"] if f["rule_id"] == "CS-PKG-001"]
    assert len(drift) == 1
    assert "'Dapper'" in drift[0]["message"]
    assert drift[0]["location"]["path"] == "Shop.Api.csproj"
    proj = payload["project_analyses"]["csharp:package"]["result"]["projects"][0]
    assert proj["assembly"] == "Shop.Api"
    assert proj["package_references"] == [
        "Microsoft.EntityFrameworkCore.SqlServer", "Serilog",
    ]


def test_nested_project_uses_nearest_csproj(project):
    root = project({
        "src/Web/Web.csproj": _CSPROJ.replace("Serilog", "Dapper"),
        "src/Web/Handler.cs": "using Dapper;\nnamespace Web;\nclass H {}\n",
        "src/Core/Core.csproj": _CSPROJ,
        "src/Core/Model.cs": "using Dapper;\nnamespace Core;\nclass M {}\n",
    })
    _, payload = scan_json(root)
    drift = [f for f in payload["findings"] if f["rule_id"] == "CS-PKG-001"]
    assert [f["location"]["path"] for f in drift] == ["src/Core/Core.csproj"]


def test_project_reference_packages_flow_transitively(project):
    root = project({
        "src/Core/Core.csproj": _CSPROJ.replace("Serilog", "FluentValidation"),
        "src/Web/Web.csproj": _CSPROJ.replace(
            "</ItemGroup>",
            '<ProjectReference Include="..\\Core\\Core.csproj" /></ItemGroup>',
        ),
        "src/Web/Handler.cs": "using FluentValidation;\nnamespace Web;\nclass H {}\n",
    })
    _, payload = scan_json(root)
    assert not [f for f in payload["findings"] if f["rule_id"] == "CS-PKG-001"]


def test_shared_root_namespace_counts_as_coverage(project):
    root = project({
        "App.csproj": _CSPROJ.replace(
            'Include="Serilog"', 'Include="OpenTelemetry.Extensions.Hosting"',
        ),
        "Telemetry.cs": "using OpenTelemetry.Metrics;\nnamespace App;\nclass T {}\n",
    })
    _, payload = scan_json(root)
    assert not [f for f in payload["findings"] if f["rule_id"] == "CS-PKG-001"]


def test_csproj_with_doctype_is_rejected_fail_closed(project):
    root = project({
        "Bad.csproj": '<!DOCTYPE p [<!ENTITY e SYSTEM "file:///etc/passwd">]><Project/>',
        "A.cs": "using Dapper;\nclass A {}\n",
    })
    _, payload = scan_json(root)
    rules = [f["rule_id"] for f in payload["findings"] if f["rule_id"].startswith("CS-PKG")]
    assert rules == ["CS-PKG-002"]


def test_csharp_only_project_earns_a_real_score(project):
    root = project({
        "A.cs": (
            "using Serilog;\nusing Xunit;\n"
            "class A { Dictionary<int,int> d = new(); ILogger<A> _log;\n"
            '  [Fact] void T() { _log.LogInformation("x"); } }\n'
        ),
    })
    result, payload = scan_json(root)
    assert result.exit_code == 0
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["scan_health"]["languages"] == {"csharp": 1}
    assert "hash_map" in payload["dsa_patterns"]
    assert {"logging", "testing"} <= set(payload["design_patterns"])
