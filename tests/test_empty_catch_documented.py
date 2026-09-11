"""Staff review C3: a commented empty catch is documented intent, not a warning."""

from __future__ import annotations

from pathlib import Path

import pytest

from cqa_analyzer.languages.c_family import CLanguageAdapter, CRulePack
from cqa_analyzer.languages.csharp import CSharpLanguageAdapter, CSharpRulePack
from cqa_analyzer.languages.java import JavaLanguageAdapter, JavaRulePack
from cqa_analyzer.languages.kotlin import KotlinLanguageAdapter, KotlinRulePack
from cqa_analyzer.languages.typescript import TypeScriptLanguageAdapter, TypeScriptRulePack
from cqa_analyzer.protocols import SourceFile

CASES = [
    (
        "a.ts",
        TypeScriptLanguageAdapter,
        TypeScriptRulePack,
        "TS-COR-001",
        "try { f(); } catch (e) {BODY}\n",
    ),
    (
        "A.java",
        JavaLanguageAdapter,
        JavaRulePack,
        "JAVA-COR-001",
        "class A { void f() { try { g(); } catch (Exception e) {BODY} } }\n",
    ),
    (
        "A.kt",
        KotlinLanguageAdapter,
        KotlinRulePack,
        "KT-COR-001",
        "fun f() { try { g() } catch (e: Exception) {BODY} }\n",
    ),
    (
        "A.cs",
        CSharpLanguageAdapter,
        CSharpRulePack,
        "CS-COR-001",
        "class A { void F() { try { G(); } catch (Exception e) {BODY} } }\n",
    ),
    (
        "a.cpp",
        CLanguageAdapter,
        CRulePack,
        "C-COR-001",
        "void f() { try { g(); } catch (...) {BODY} }\n",
    ),
]


@pytest.mark.parametrize("name, adapter, pack, rule_id, template", CASES)
def test_documented_empty_catch_is_a_note_and_bare_one_is_a_warning(
    name, adapter, pack, rule_id, template
):
    def findings(body):
        source = template.replace("BODY", body)
        parsed = adapter().parse(SourceFile(Path(name), name, name, source))
        # The fixtures catch ``Exception`` / ``...``, which the 2.41.0
        # broad-catch rules also report (as Python does); this test is about
        # the empty-catch grading only.
        return [f for f in pack().evaluate(parsed) if f.rule_id == rule_id]

    bare = findings(" ")
    assert [f.rule_id for f in bare] == [rule_id]
    assert bare[0].severity == "warning"

    documented = findings(" /* best effort: cache warm-up may fail */ ")
    assert [f.rule_id for f in documented] == [rule_id]
    assert documented[0].severity == "note"
    assert "documented" in documented[0].message

    line_comment = findings(" // intentionally ignored\n    ")
    assert line_comment[0].severity == "note"

    handled = findings(" log(e); ")
    assert handled == []
