"""Optional [deep] extra: tree-sitter duplication and complexity for Go and C/C++.

Tests that need the grammars skip cleanly when the extra is absent; the
unavailable path is exercised by monkeypatching so it is covered in both
CI legs.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

import cqa_analyzer.deep as deep
from cqa_analyzer.__main__ import main

HAS_DEEP = deep.deep_available("tree-sitter-go", "tree-sitter-c", "tree-sitter-cpp")
needs_deep = pytest.mark.skipif(not HAS_DEEP, reason="cqa-analyzer[deep] not installed")


def scan_json(root):
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


GO_BIG_BODY = """
    total := 0
    for i := 0; i < n; i++ {
        if i%2 == 0 && i > 3 {
            total += i * 2
        } else if i%3 == 0 || i > 10 {
            total -= i
        } else {
            total += 1
        }
    }
    values := []int{total, n, total + n}
    return values[0] + values[1] + values[2]
"""


def test_unavailable_extra_is_reported_not_faked(project, monkeypatch):
    monkeypatch.setattr(deep, "deep_available", lambda *g: False)
    root = project({"go.mod": "module x\n", "a.go": "package x\nfunc F() int { return 1 }\n"})
    payload = scan_json(root)
    dup = payload["project_analyses"]["go:duplication"]
    assert dup["result"]["available"] is False
    assert dup["result"]["install"] == "pip install 'cqa-analyzer[deep]'"
    assert dup["health"]["available"] is False and dup["health"]["complete"] is True
    assert payload["analysis_health"]["authoritative"] is True
    assert not [f for f in payload["findings"] if f["rule_id"].startswith(("GO-DUP", "GO-MAINT"))]


@needs_deep
def test_go_duplicates_ignore_names_and_require_significance(project):
    root = project(
        {
            "go.mod": "module x\n",
            "a.go": f"package x\n\nfunc Alpha(n int) int {{{GO_BIG_BODY}}}\n",
            "b.go": (
                f"package x\n\n// renamed copy\nfunc Beta(n int) int {{{GO_BIG_BODY}}}\n"
                "func tiny() int { return 1 }\nfunc tiny2() int { return 1 }\n"
            ),
        }
    )
    payload = scan_json(root)
    findings = [f for f in payload["findings"] if f["rule_id"] == "GO-DUP-001"]
    assert sorted(f["location"]["path"] for f in findings) == ["a.go", "b.go"]
    assert "'Beta' at b.go:4" in findings[0]["message"]
    result = payload["project_analyses"]["go:duplication"]["result"]
    assert result["available"] is True and result["duplicate_groups"] == 1
    assert result["functions_analyzed"] == 2  # tiny() and tiny2() are below significance
    assert result["engine"]["tree-sitter-go"]


@needs_deep
def test_go_cyclomatic_complexity_matches_gocyclo_rules(project):
    branches = "\n".join(f"    if x == {i} || x == {i + 100} {{ return {i} }}" for i in range(6))
    root = project(
        {
            "go.mod": "module x\n",
            "a.go": (
                "package x\n\nfunc Complex(x int) int {\n"
                f"{branches}\n    switch x {{\n    case 1:\n        return 1\n"
                "    default:\n        return 0\n    }\n}\n"
                "func Simple() int { return 1 }\n"
            ),
        }
    )
    payload = scan_json(root)
    findings = [f for f in payload["findings"] if f["rule_id"] == "GO-MAINT-001"]
    assert len(findings) == 1 and "'Complex'" in findings[0]["message"]
    # 1 + 6 ifs + 6 `||` + 1 non-default case = 14; default case does not count.
    assert "complexity 14" in findings[0]["message"]
    result = payload["project_analyses"]["go:complexity"]["result"]
    assert result["functions_analyzed"] == 2 and result["over_limit"] == 1
    assert result["functions"][0] == {
        "path": "a.go",
        "line": 3,
        "function": "Complex",
        "cyclomatic": 14,
    }


@needs_deep
def test_c_and_cpp_grammars_are_selected_by_extension(project):
    body = "\n".join(f"    if (x == {i} && y) return {i};" for i in range(11))
    root = project(
        {
            "CMakeLists.txt": "project(d)\n",
            "a.c": f"int f(int x, int y) {{\n{body}\n    return -1;\n}}\n",
            "b.cpp": (
                "namespace n {\nclass K {\npublic:\n  int m(int x, int y);\n};\n"
                f"int K::m(int x, int y) {{\n{body}\n    return -1;\n}}\n}}\n"
                "void g() { try { h(); } catch (...) {} }\n"
            ),
        }
    )
    payload = scan_json(root)
    maint = {
        f["location"]["path"]: f["message"]
        for f in payload["findings"]
        if f["rule_id"] == "C-MAINT-001"
    }
    assert set(maint) == {"a.c", "b.cpp"}
    assert "'f' has cyclomatic complexity 23" in maint["a.c"]
    assert "'K::m' has cyclomatic complexity 23" in maint["b.cpp"]
    result = payload["project_analyses"]["c_cpp:complexity"]["result"]
    assert result["functions_analyzed"] == 3  # f, K::m, g
    assert result["files_with_parse_errors"] == 0


@needs_deep
def test_c_duplicates_across_files_and_parse_error_files_are_excluded(project):
    body = "\n".join(f"    acc += buf[{i}] * {i};" for i in range(12))
    fn = "int sum(const int* buf) {{\n    int acc = 0;\n{body}\n    return acc;\n}}\n"
    broken_fn = (
        "int oops(int n) {\n    int a = 1;\n    int b = va_arg(ap, char*);\n"
        + "\n".join(f"    a += b * {i};" for i in range(12))
        + "\n    return a;\n}\n"
    )
    root = project(
        {
            "CMakeLists.txt": "project(d)\n",
            "x.c": fn.format(body=body),
            "y.c": fn.format(body=body).replace("sum", "total"),
            # A localized parse error (va_arg with a type) excludes only that
            # function; the healthy copy in the same file still participates.
            "z.c": broken_fn + fn.format(body=body).replace("sum", "third"),
            "w.c": broken_fn.replace("oops", "oops2"),
        }
    )
    payload = scan_json(root)
    dup = [f for f in payload["findings"] if f["rule_id"] == "C-DUP-001"]
    assert sorted(f["location"]["path"] for f in dup) == ["x.c", "y.c", "z.c"]
    result = payload["project_analyses"]["c_cpp:duplication"]["result"]
    assert result["files_with_parse_errors"] == 2
    assert result["functions_excluded_for_parse_errors"] == 2  # oops, oops2 never match
    assert result["duplicate_groups"] == 1
    assert payload["analysis_health"]["authoritative"] is True


@needs_deep
def test_dot_h_uses_c_grammar_unless_it_is_visibly_cpp():
    from pathlib import Path

    from cqa_analyzer.protocols import SourceFile

    def spec_for(name, content):
        parsed = deep.ParsedFile(SourceFile(Path(name), name, name, content), None, None, 1, True)
        return deep._spec_for(parsed, "c_cpp")

    # hiredis ffc.h: macro attributes in declarators defeat the C++ grammar.
    assert spec_for("ffc.h", "ffc_internal ffc_inline int f(void) { return 1; }\n") is deep.C_SPEC
    # `std::` in a comment is not C++ (hiredis ffc.h).
    assert (
        spec_for("ffc.h", "// like std::fill(a, b, 0)\nint f(void) { return 1; }\n") is deep.C_SPEC
    )
    assert (
        spec_for("api.h", '#ifdef __cplusplus\nextern "C" {\n#endif\nint f(void);\n') is deep.C_SPEC
    )
    assert spec_for("k.h", "namespace n {\nclass K { int m(); };\n}\n") is deep.CPP_SPEC
    assert spec_for("t.h", "template <typename T> T id(T x) { return x; }\n") is deep.CPP_SPEC
    assert spec_for("k.hpp", "int f();\n") is deep.CPP_SPEC
    assert spec_for("k.c", "int f();\n") is deep.C_SPEC


@needs_deep
def test_deep_and_python_thresholds_are_shared():
    from cqa_analyzer.duplication import MIN_BODY_NODES, MIN_BODY_STATEMENTS
    from cqa_analyzer.maintainability import CYCLOMATIC_COMPLEXITY_LIMIT

    assert (MIN_BODY_STATEMENTS, MIN_BODY_NODES, CYCLOMATIC_COMPLEXITY_LIMIT) == (3, 40, 10)
    assert deep.availability()["tree-sitter"]
