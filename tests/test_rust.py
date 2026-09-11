"""Rust pilot (experimental, gated on the ``[deep]`` extra).

The adapter, rules and Cargo provider are pure Python and are tested
unconditionally; registration and the tree-sitter providers are tested only
when ``tree-sitter-rust`` is installed, and their *absence* is tested the
other way round (no `.rs` discovery without the grammar).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import cqa_analyzer.deep as deep
from cqa_analyzer.__main__ import main
from cqa_analyzer.languages.rust import (
    RustArchitectureSignalProvider,
    RustLanguageAdapter,
    RustRulePack,
    _strip_rust_comments_and_strings,
)
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.protocols import SourceFile
from cqa_analyzer.rust_patterns import RUST_DESIGN_PATTERNS, RUST_DSA_PATTERNS

HAS_RUST = deep.deep_available("tree-sitter-rust")
needs_rust = pytest.mark.skipif(not HAS_RUST, reason="tree-sitter-rust not installed")


def parse_rs(source: str, name: str = "src/lib.rs"):
    return RustLanguageAdapter().parse(SourceFile(Path(name), name, name, source))


def scan_json(root):
    result = CliRunner().invoke(main, [str(root), "-f", "json", "--offline"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


# ---- lexer ---------------------------------------------------------------------


def test_lexer_blanks_nested_comments_strings_and_chars_but_keeps_lifetimes():
    src = (
        "fn f<'a>(s: &'a str) -> &'static str { /* outer /* inner */ tail */ let q = \"x\\\"y\"; "
        'let r = r#"raw "quoted" .unwrap()"#; let c = \'"\'; let e = \'\\\'\'; b"bytes"; s } // c\n'
    )
    code, complete = _strip_rust_comments_and_strings(src)
    assert complete and len(code) == len(src)
    assert "'a" in code and "'static" in code  # lifetimes are code
    assert "inner" not in code and "tail" not in code and "raw" not in code
    assert "unwrap" not in code and "bytes" not in code and "// c" not in code
    assert code.count("{") == code.count("}") == 1


def test_lexer_reports_unterminated_string_as_incomplete():
    _, complete = _strip_rust_comments_and_strings('let s = "open;\n')
    assert complete is False


def test_adapter_extracts_imports_identifiers_and_external_crates():
    parsed = parse_rs(
        "use std::collections::HashMap;\nuse tokio::sync::Mutex;\nextern crate serde;\n"
        "mod local;\npub(crate) use crate::x::Y;\n"
        'fn go() { let m = HashMap::new(); regex::Regex::new("a"); }\n'
    )
    facts = parsed.facts
    assert {"tokio", "tokio::sync::mutex", "std", "serde", "regex"} <= set(facts.imports)
    assert set(facts.external_crates) == {"tokio", "serde"}  # `crate::` and `std::` excluded
    assert facts.local_modules == ("local",)
    assert {"go", "m", "HashMap", "new"} <= set(facts.identifiers)


def test_cache_codec_round_trips():
    adapter = RustLanguageAdapter()
    parsed = parse_rs("use tokio::spawn;\nfn f() {}\n")
    payload = json.loads(json.dumps(adapter.serialize_parsed(parsed)))
    restored = adapter.deserialize_parsed(parsed.source, payload)
    assert restored.facts == parsed.facts and restored.complete == parsed.complete


# ---- rules ------------------------------------------------------------------------


def test_unwrap_density_excludes_test_code_and_documented_expect():
    body = "".join(f"    let v{i} = Some({i}).unwrap();\n" for i in range(5))
    src = (
        "fn prod() {\n" + body + '    let e = Some(0).expect("never empty");\n}\n'
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n" + body + "    }\n}\n"
    )
    found = [f for f in RustRulePack().evaluate(parse_rs(src)) if f.rule_id == "RS-COR-001"]
    assert len(found) == 1
    assert found[0].message.startswith("File uses 5 .unwrap() calls outside test code")
    assert found[0].location.line == 2
    assert found[0].severity == "warning"

    only_tests = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n" + body + "    }\n}\n"
    assert list(RustRulePack().evaluate(parse_rs(only_tests))) == []
    assert list(RustRulePack().evaluate(parse_rs("fn f() {\n" + body + "}\n", "tests/it.rs"))) == []
    assert (
        list(RustRulePack().evaluate(parse_rs("fn f() {\n" + body + "}\n", "benches/b.rs"))) == []
    )


def test_tokio_test_attribute_is_test_code():
    body = "".join(f"    let v{i} = Some({i}).unwrap();\n" for i in range(5))
    src = "#[tokio::test]\nasync fn t() {\n" + body + "}\n"
    assert list(RustRulePack().evaluate(parse_rs(src))) == []


# ---- catalog -----------------------------------------------------------------------


def test_catalog_reaches_every_shared_id():
    assert set(RUST_DSA_PATTERNS) == set(DSA_PATTERNS)
    assert set(RUST_DESIGN_PATTERNS) == set(SYSTEM_DESIGN_PATTERNS)


def test_signals_from_std_collections_and_crates():
    parsed = parse_rs(
        "use std::collections::{BinaryHeap, VecDeque, HashMap};\nuse tokio::sync::Mutex;\n"
        "use sqlx::PgPool;\nuse tracing::{info, instrument};\nuse anyhow::{Context, Result};\n"
        "#[instrument]\nasync fn f() -> Result<()> { let h: BinaryHeap<i32> = BinaryHeap::new(); "
        "let q = VecDeque::new(); let m = HashMap::new(); "
        "let mut v = vec![3,1]; v.sort(); v.dedup(); "
        'info!("x"); tokio::spawn(async {}); Ok(()) }\n'
    )
    observations = list(RustArchitectureSignalProvider().evaluate(parsed))
    dsa = {o.signal_id for o in observations if o.category == "architecture.dsa"}
    design = {o.signal_id for o in observations if o.category == "architecture.design"}
    assert {"heap_priority", "queue_stack", "hash_map", "sorting"} <= dsa
    assert {"database_orm", "concurrency", "logging", "observability", "error_handling"} <= design
    assert "idempotency" not in design  # Vec::dedup is not an idempotency signal


# ---- Cargo provider + gating (CLI) ---------------------------------------------------

CARGO = (
    '[package]\nname = "demo-svc"\nversion = "0.1.0"\n[dependencies]\n'
    'tokio = { version = "1", features = ["full"] }\nserde_json = "1"\n'
    'renamed = { package = "real-crate", version = "1" }\n[dev-dependencies]\nproptest = "1"\n'
)


@needs_rust
def test_cargo_drift_and_own_crate_and_renames(project):
    root = project(
        {
            "Cargo.toml": CARGO,
            "src/lib.rs": "pub mod util;\nuse tokio::spawn;\nuse anyhow::Result;\n"
            "use real_crate::X;\n"
            "use demo_svc::util::y;\nuse crate::util::z;\n",
            "src/util.rs": "pub fn y() {}\npub fn z() {}\n",
            "tests/it.rs": "use proptest::prelude::*;\nuse demo_svc::util::y;\n",
            "member/Cargo.toml": "[package\nname = broken\n",
            "member/src/m.rs": "pub fn m() {}\n",  # manifests are discovered where sources are
        }
    )
    payload = scan_json(root)
    ids = sorted(f["rule_id"] for f in payload["findings"] if f["rule_id"].startswith("RS-PKG"))
    assert ids == ["RS-PKG-001", "RS-PKG-002"]
    drift = next(f for f in payload["findings"] if f["rule_id"] == "RS-PKG-001")
    assert "'anyhow'" in drift["message"] and drift["location"]["path"] == "Cargo.toml"
    assert payload["scan_health"]["languages"] == {"rust": 4}


@needs_rust
def test_deep_rust_duplication_and_complexity(project):
    # while(+1) containing if(+2): 3 per block, 6 blocks -> cognitive 18 > 15;
    # cyclomatic 1 + 12 decisions = 13 > 10.
    body = "".join(
        f"    while acc > {i * 10} {{ if x > {i} {{ acc -= 1; }} else {{ acc -= 2; }} }}\n"
        for i in range(6)
    )
    root = project(
        {
            "Cargo.toml": CARGO,
            "src/lib.rs": (
                "pub fn a(x: i32) -> i32 {\n    let mut acc = 0;\n" + body + "    acc\n}\n"
                # Same body and parameters, different name: a structural duplicate
                # (leaf text counts, so renamed variables are *not* duplicates).
                "pub fn b(x: i32) -> i32 {\n    let mut acc = 0;\n" + body + "    acc\n}\n"
                "pub fn c(v: i32) -> &'static str {\n"
                '    match v { 1 => "a", 2 => "b", _ => "c" }\n}\n'
                "pub fn d(v: i32) -> i32 {\n"
                "    let f = |k: i32| if k > 0 { 1 } else { 0 };\n    f(v)\n}\n"
            ),
        }
    )
    payload = scan_json(root)
    ids = {f["rule_id"] for f in payload["findings"]}
    assert {"RS-DUP-001", "RS-MAINT-001", "RS-MAINT-002"} <= ids
    complexity = payload["project_analyses"]["rust:complexity"]["result"]
    assert complexity["available"] is True and complexity["engine"]["tree-sitter-rust"]
    reported = {f["function"]: f for f in complexity["functions"]}
    assert reported["a"]["cyclomatic"] == 13 and reported["a"]["cognitive"] == 18
    assert reported["b"]["cyclomatic"] == 13
    # ``_`` arm is the default; closures are not entered: c and d stay under limit.
    assert "c" not in reported and "d" not in reported
    dup = payload["project_analyses"]["rust:duplication"]["result"]
    # c and d are below the significance threshold, exactly as in Go.
    assert dup["duplicate_groups"] == 1 and dup["functions_analyzed"] == 2


@pytest.mark.skipif(HAS_RUST, reason="checks behaviour without the grammar")
def test_rust_is_not_discovered_without_the_grammar(project):
    root = project({"Cargo.toml": CARGO, "src/lib.rs": "fn f() {}\n"})
    result = CliRunner().invoke(main, [str(root), "-f", "json", "--offline"])
    payload = json.loads(result.output)
    # No adapter, so a Rust-only tree has no source candidates: the existing
    # "nothing to analyse" verdict (exit 2, non-authoritative), not a crash.
    assert result.exit_code == 2
    assert "rust" not in payload["language_adapters"]
    assert payload["scan_health"]["languages"] == {}
    assert payload["analysis_health"]["reasons"] == ["no_source_candidates"]


@needs_rust
def test_rust_availability_is_reported():
    versions = deep.availability()
    assert versions["tree-sitter-rust"] is not None


# ---- calibration-driven fixes (ripgrep, sqlx) ---------------------------------------

def test_use_inside_string_literals_is_not_an_import():
    # ripgrep: `const CODE: &str = "extern crate snap;\nuse std::io;"` and long
    # raw-string docs containing "use the ... flag".
    src = (
        'const CODE: &str = "\\\nextern crate snap;\\n\\nuse std::io;\\n";\n'
        'const DOC: &str = r"\nuse the --glob flag.\nuse more memory.\n";\n'
        "use tokio::spawn;\n"
    )
    facts = parse_rs(src).facts
    assert set(facts.external_crates) == {"tokio"}
    # Raw identifiers: `mod r#type;` is a local module named `type`, not crate `r`.
    raw = parse_rs("mod r#type;\npub use r#type::expand;\nuse r#match::x;\n").facts
    assert raw.local_modules == ("type",) and "r" not in raw.external_crates
    # `type` is filtered later by the Cargo provider (it is a declared module).
    assert set(raw.external_crates) == {"match", "type"}
    assert "snap" not in facts.imports and "the" not in facts.imports


@needs_rust
def test_hyphenated_package_matches_its_lib_name(project):
    # sqlx-postgres declares `md-5` and imports `md5::Md5`.
    root = project(
        {
            "Cargo.toml": (
                '[package]\nname = "p"\nversion = "0.1.0"\n[dependencies]\nmd-5 = "0.10"\n'
            ),
            "src/lib.rs": "use md5::Md5;\n",
        }
    )
    payload = scan_json(root)
    assert [f for f in payload["findings"] if f["rule_id"] == "RS-PKG-001"] == []
