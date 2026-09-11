"""Parity correctness rules for the regex languages.

Each rule mirrors a Python rule that has existed since 2.x (PY-COR-002 broad
catch, PY-COR-005 blocking in async) or answers a top-voted Stack Overflow
question for that language. Tests pin: the positive case fires with the
expected grading, the idiomatic alternative is silent, and nested scopes are
not mis-attributed.
"""

from __future__ import annotations

from pathlib import Path

from cqa_analyzer.languages._parity import (
    NON_NULL_LIMIT,
    block_end,
    strip_nested_blocks,
)
from cqa_analyzer.languages.c_family import CLanguageAdapter, CRulePack
from cqa_analyzer.languages.csharp import CSharpLanguageAdapter, CSharpRulePack
from cqa_analyzer.languages.go import GoLanguageAdapter, GoRulePack
from cqa_analyzer.languages.java import JavaLanguageAdapter, JavaRulePack
from cqa_analyzer.languages.kotlin import KotlinLanguageAdapter, KotlinRulePack
from cqa_analyzer.languages.typescript import TypeScriptLanguageAdapter, TypeScriptRulePack
from cqa_analyzer.protocols import SourceFile

import re


def _run(adapter_cls, pack_cls, name: str, source: str, rule_id: str):
    parsed = adapter_cls().parse(SourceFile(Path(name), name, name, source))
    assert parsed.complete, "fixture must lex cleanly"
    return [f for f in pack_cls().evaluate(parsed) if f.rule_id == rule_id]


def java(source, rule_id, name="A.java"):
    return _run(JavaLanguageAdapter, JavaRulePack, name, source, rule_id)


def kotlin(source, rule_id, name="a.kt"):
    return _run(KotlinLanguageAdapter, KotlinRulePack, name, source, rule_id)


def csharp(source, rule_id, name="a.cs"):
    return _run(CSharpLanguageAdapter, CSharpRulePack, name, source, rule_id)


def ts(source, rule_id, name="a.ts"):
    return _run(TypeScriptLanguageAdapter, TypeScriptRulePack, name, source, rule_id)


def go(source, rule_id, name="a.go"):
    return _run(GoLanguageAdapter, GoRulePack, name, source, rule_id)


def cpp(source, rule_id, name="a.cpp"):
    return _run(CLanguageAdapter, CRulePack, name, source, rule_id)


# ---- helpers ---------------------------------------------------------------

def test_block_end_matches_nested_braces_and_tolerates_unbalanced_input():
    assert block_end("{ a { b } c } d", 0) == 13
    assert block_end("{ a { b ", 0) == 8  # falls back to end of text


def test_strip_nested_blocks_blanks_only_brace_bodies():
    body = "x => 1; y => { inner }; z"
    stripped = strip_nested_blocks(body, re.compile(r"=>\s*\{"))
    assert stripped == "x => 1; y =>          ; z"
    assert len(stripped) == len(body)


# ---- broad catch -------------------------------------------------------------

def test_java_broad_catch_grades_rethrow_as_note():
    src = (
        "class A { void f() {\n"
        "  try { g(); } catch (Exception e) { log(e); }\n"
        "  try { g(); } catch (final Throwable t) { throw new RuntimeException(t); }\n"
        "  try { g(); } catch (IOException | java.lang.Error e) { log(e); }\n"
        "  try { g(); } catch (IOException e) { log(e); }\n"
        "} }\n"
    )
    found = java(src, "JAVA-COR-003")
    assert [(f.location.line, f.severity) for f in found] == [
        (2, "warning"),
        (3, "note"),
        (4, "warning"),
    ]
    assert found[0].message == "Exception handler catches Exception."
    assert "rethrows" in found[1].message
    assert found[2].message == "Exception handler catches java.lang.Error."


def test_kotlin_broad_catch():
    src = (
        "fun f() {\n"
        "  try { g() } catch (e: Exception) { log(e) }\n"
        "  try { g() } catch (t: Throwable) { throw Wrapped(t) }\n"
        "  try { g() } catch (e: IOException) { log(e) }\n"
        "}\n"
    )
    assert [(f.location.line, f.severity) for f in kotlin(src, "KT-COR-003")] == [
        (2, "warning"),
        (3, "note"),
    ]


def test_csharp_broad_catch_includes_bare_catch_but_not_filtered_catch():
    src = (
        "class A { void F() {\n"
        "  try { G(); } catch (Exception e) { Log(e); }\n"
        "  try { G(); } catch { Log(); }\n"
        "  try { G(); } catch (System.Exception) { throw; }\n"
        "  try { G(); } catch (Exception e) when (e is IOException) { Log(e); }\n"
        "  try { G(); } catch (IOException e) { Log(e); }\n"
        "} }\n"
    )
    found = csharp(src, "CS-COR-003")
    assert [(f.location.line, f.severity) for f in found] == [
        (2, "warning"),
        (3, "warning"),
        (4, "note"),
    ]
    assert found[1].message == "Exception handler catches all exceptions."


def test_cpp_catch_all():
    src = (
        "void f() {\n"
        "  try { g(); } catch (...) { }\n"
        "  try { g(); } catch (...) { cleanup(); throw; }\n"
        "  try { g(); } catch (const std::exception& e) { log(e); }\n"
        "}\n"
    )
    assert [(f.location.line, f.severity) for f in cpp(src, "C-COR-003")] == [
        (2, "warning"),
        (3, "note"),
    ]


# ---- blocking in async --------------------------------------------------------

def test_csharp_blocking_in_async_ignores_sync_methods_and_nested_lambdas():
    src = (
        "class A {\n"
        "  async Task F() {\n"
        "    var x = G().Result;\n"
        "    H().Wait();\n"
        "    var y = I().GetAwaiter().GetResult();\n"
        "    Run(() => { var z = J().Result; });\n"  # nested lambda: not attributed
        "    result.Result = 1;\n"  # assignment to a property named Result
        "  }\n"
        "  void Sync() { var x = G().Result; }\n"  # not async
        "  async Task<int> Expr() => await K();\n"
        "  Task L() { return Task.Run(async () => { var q = M().Result; }); }\n"
        "}\n"
    )
    found = csharp(src, "CS-COR-004")
    assert [f.location.line for f in found] == [3, 4, 5, 11]
    assert found[0].message == "A synchronous wait on a Task blocks inside an asynchronous body."
    assert all(f.confidence == "medium" for f in found)


def test_kotlin_blocking_in_suspend_including_expression_body():
    src = (
        "suspend fun a() {\n"
        "  runBlocking { b() }\n"
        "  Thread.sleep(10)\n"
        "}\n"
        "suspend fun c() = runBlocking { d() }\n"
        "fun e() { runBlocking { f() } }\n"  # not suspend: fine
        "suspend fun g(x: Int = 1): Int { return withContext(IO) { h() } }\n"
    )
    assert [f.location.line for f in kotlin(src, "KT-COR-004")] == [2, 3, 5]


def test_typescript_sync_io_in_async_function():
    src = (
        "async function load(p: string) {\n"
        "  const raw = fs.readFileSync(p);\n"
        "  const out = execSync('ls');\n"
        "  items.forEach((i) => { fs.writeFileSync(i, raw); });\n"  # nested arrow
        "  return raw;\n"
        "}\n"
        "function syncLoad(p: string) { return fs.readFileSync(p); }\n"
        "const g = async (p: string) => { return fs.existsSync(p); };\n"
        "class C { async m() { return fs.statSync('x'); } }\n"
    )
    assert [f.location.line for f in ts(src, "TS-COR-003")] == [2, 3, 8, 9]


# ---- TypeScript suppressions and non-null assertions -------------------------

def test_typescript_unexplained_suppression():
    src = (
        "// @ts-ignore\n"
        "const a = b as any;\n"
        "// @ts-ignore: legacy widget typings are wrong\n"
        "const c = d;\n"
        "// @ts-expect-error\n"
        "const e = f;\n"
        "/* @ts-nocheck */\n"
        "// @ts-expect-error -- upstream types lag the runtime\n"
    )
    found = ts(src, "TS-COR-004")
    assert [(f.location.line, f.message.split()[0]) for f in found] == [
        (1, "@ts-ignore"),
        (5, "@ts-expect-error"),
        (7, "@ts-nocheck"),
    ]
    assert found[0].severity == "warning"


def test_typescript_non_null_density_threshold_and_js_exemption():
    many = "".join(f"const v{i} = maybe{i}!.value;\n" for i in range(NON_NULL_LIMIT + 1))
    found = ts(many, "TS-COR-005")
    assert len(found) == 1
    assert found[0].location.line == 1
    assert f"{NON_NULL_LIMIT + 1} non-null assertions (!)" in found[0].message

    few = "".join(f"const v{i} = maybe{i}!.value;\n" for i in range(NON_NULL_LIMIT))
    assert ts(few, "TS-COR-005") == []

    negations = "".join(f"if (a{i} != b{i} && !c{i}) {{ x(); }}\n" for i in range(10))
    assert ts(negations, "TS-COR-005") == []

    assert ts(many, "TS-COR-005", name="a.js") == []


def test_kotlin_non_null_density():
    many = "".join(f"val v{i} = maybe{i}!!.value\n" for i in range(NON_NULL_LIMIT + 2))
    found = kotlin(many, "KT-COR-005")
    assert len(found) == 1
    assert f"{NON_NULL_LIMIT + 2} non-null assertions (!!)" in found[0].message
    assert kotlin('val s = "a!!b!!c!!d!!e!!f"\n', "KT-COR-005") == []  # strings blanked


# ---- Go ----------------------------------------------------------------------

def test_go_unchecked_type_assertion():
    src = (
        "package p\n"
        "func f(x any) {\n"
        "  s := x.(string)\n"
        "  if n, ok := x.(int); ok { use(n) }\n"
        "  v, _ := x.(*T)\n"
        "  switch t := x.(type) { case int: use(t) }\n"
        "  use(x.([]byte))\n"
        "  return x.(fmt.Stringer).String()\n"
        "}\n"
    )
    found = go(src, "GO-COR-003")
    assert [f.location.line for f in found] == [3, 7, 8]
    assert found[0].message == "Type assertion to string is unchecked and panics on mismatch."
    assert found[1].message.startswith("Type assertion to []byte")


def test_go_defer_in_loop_ignores_func_literals():
    src = (
        "package p\n"
        "func f(paths []string) {\n"
        "  for _, p := range paths {\n"
        "    fh, _ := os.Open(p)\n"
        "    defer fh.Close()\n"
        "    func() { defer mu.Unlock(); work() }()\n"  # own scope: fine
        "  }\n"
        "  for i := 0; i < 3; i++ {\n"
        "    for j := 0; j < 3; j++ { defer log(i, j) }\n"  # nested: once
        "  }\n"
        "  defer done()\n"
        "}\n"
    )
    found = go(src, "GO-COR-004")
    assert [f.location.line for f in found] == [5, 9]
    assert found[0].severity == "warning" and found[0].confidence == "high"


# ---- C++ headers ---------------------------------------------------------------

def test_cpp_using_namespace_in_header_only_at_file_scope():
    src = (
        "#pragma once\n"
        "using namespace std;\n"
        "namespace app {\n"
        "using namespace detail;\n"  # scoped to the namespace: not reported
        "inline void f() { using namespace std; }\n"
        "}\n"
    )
    found = cpp(src, "C-COR-004", name="a.hpp")
    assert [f.location.line for f in found] == [2]
    assert cpp(src, "C-COR-004", name="a.cpp") == []
    assert cpp("using namespace std;\n", "C-COR-004", name="a.h") != []


# ---- calibration-driven precision fixes ------------------------------------

def test_csharp_result_property_on_plain_object_is_not_a_task_wait():
    # Found on StackExchange.Redis: ``received.Result`` is a struct property.
    src = (
        "class A {\n"
        "  async Task F() {\n"
        "    if (received.IsOutOfBand && received.Result is not null) { pair(received.Result); }\n"
        "    var a = GetAsync().Result;\n"
        "    var b = pendingTask.Result;\n"
        "    var c = someTask.Result;\n"
        "  }\n"
        "}\n"
    )
    found = csharp(src, "CS-COR-004")
    assert [f.location.line for f in found] == [4, 5, 6]


def test_is_test_path_conventions():
    from cqa_analyzer.languages._parity import is_test_path

    for path in (
        "pkg/cache_test.go", "src/a.spec.ts", "src/a.test.tsx", "src/__tests__/x.ts",
        "src/test/kotlin/FooTest.kt", "Tests/FooTests.cs", "tests/test_x.py", "e2e/flow.ts",
    ):
        assert is_test_path(path), path
    for path in ("pkg/cache.go", "src/attest.ts", "src/contest/x.kt", "testimony/a.cs"):
        assert not is_test_path(path), path


def test_idiom_in_tests_rules_are_notes_in_test_files():
    go_src = "package p\nfunc f(x any) { s := x.(string); use(s) }\n"
    assert go(go_src, "GO-COR-003")[0].severity == "warning"
    assert go(go_src, "GO-COR-003", name="p_test.go")[0].severity == "note"

    many = "".join(f"const v{i} = maybe{i}!.value;\n" for i in range(NON_NULL_LIMIT + 1))
    assert ts(many, "TS-COR-005")[0].severity == "warning"
    assert ts(many, "TS-COR-005", name="a.spec.ts")[0].severity == "note"

    kt_many = "".join(f"val v{i} = maybe{i}!!.value\n" for i in range(NON_NULL_LIMIT + 1))
    assert kotlin(kt_many, "KT-COR-005", name="src/test/kotlin/ATest.kt")[0].severity == "note"
