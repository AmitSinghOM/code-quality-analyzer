"""Dynamic-SQL rules: one classifier, seven languages, identical semantics.

Stack Overflow's most-voted PHP question is "How can I prevent SQL injection"
and the ``sql`` tag is the 7th largest on the site; the defect class is
building a statement out of runtime values. These tests pin, per language,
that each construction style fires exactly once per statement and that the
safe alternatives (driver parameters, literal-only concatenation, prose that
merely contains SQL words) stay silent.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cqa_analyzer.languages._sql import (
    C_SQL,
    CSHARP_SQL,
    GO_SQL,
    JAVA_SQL,
    KOTLIN_SQL,
    TYPESCRIPT_SQL,
    literal_spans,
)
from cqa_analyzer.languages.c_family import CLanguageAdapter, CRulePack
from cqa_analyzer.languages.csharp import CSharpLanguageAdapter, CSharpRulePack
from cqa_analyzer.languages.go import GoLanguageAdapter, GoRulePack
from cqa_analyzer.languages.java import JavaLanguageAdapter, JavaRulePack
from cqa_analyzer.languages.kotlin import KotlinLanguageAdapter, KotlinRulePack
from cqa_analyzer.languages.typescript import TypeScriptLanguageAdapter, TypeScriptRulePack
from cqa_analyzer.protocols import SourceFile
from cqa_analyzer.python_sql import DynamicSqlRule
from cqa_analyzer.sql_text import is_sql_statement

ADAPTERS = {
    "java": (JavaLanguageAdapter, JavaRulePack, "A.java", "JAVA-COR-002", JAVA_SQL),
    "kotlin": (KotlinLanguageAdapter, KotlinRulePack, "a.kt", "KT-COR-002", KOTLIN_SQL),
    "csharp": (CSharpLanguageAdapter, CSharpRulePack, "a.cs", "CS-COR-002", CSHARP_SQL),
    "typescript": (
        TypeScriptLanguageAdapter, TypeScriptRulePack, "a.ts", "TS-COR-002", TYPESCRIPT_SQL
    ),
    "go": (GoLanguageAdapter, GoRulePack, "a.go", "GO-COR-002", GO_SQL),
    "c_cpp": (CLanguageAdapter, CRulePack, "a.cpp", "C-COR-002", C_SQL),
}


def findings_for(language: str, source: str):
    adapter_cls, pack_cls, name, rule_id, _ = ADAPTERS[language]
    parsed = adapter_cls().parse(SourceFile(Path(name), name, name, source))
    assert parsed.complete, "fixture must lex cleanly"
    return [f for f in pack_cls().evaluate(parsed) if f.rule_id == rule_id]


def py_findings(source: str):
    return list(DynamicSqlRule().evaluate(ast.parse(source), "m.py"))


# ---- classifier -------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "SELECT * FROM users WHERE id = ",
        "select name from t where x = 1",
        "INSERT INTO t (a) VALUES (",
        "UPDATE t SET a = 1 WHERE",
        "DELETE FROM t WHERE id = ",
        "WITH recent AS (SELECT * FROM t) SELECT * FROM recent",
        "  \n  SELECT *\n  FROM t",
    ],
)
def test_classifier_accepts_statement_heads(text):
    assert is_sql_statement(text)


@pytest.mark.parametrize(
    "text",
    [
        "Select an item from the list",  # prose: mixed case
        "Update the config set by the user",  # prose: mixed case
        "With love from Paris",
        "SELECT",  # no clause
        "users FROM SELECT",  # wrong order
        "Delete from cart?",  # UI text, mixed case
        "",
    ],
)
def test_classifier_rejects_prose_and_fragments(text):
    assert not is_sql_statement(text)


# ---- shared span finder -----------------------------------------------------

def test_literal_spans_skip_comments_and_join_multiline_literals():
    source = 'x = "a" // "not a string"\ny = `SELECT *\n  FROM t` + z\n'
    parsed = TypeScriptLanguageAdapter().parse(SourceFile(Path("a.ts"), "a.ts", "a.ts", source))
    spans = list(literal_spans(source, parsed.facts.code_text))
    texts = [source[s:e] for s, e in spans]
    assert texts == ['"a"', "`SELECT *\n  FROM t`"]


# ---- Python (AST) -----------------------------------------------------------

def test_python_fires_for_each_construction_style():
    src = (
        'a = f"SELECT * FROM t WHERE id = {uid}"\n'
        'b = "SELECT * FROM t WHERE id = %s" % uid\n'
        'c = "SELECT * FROM t WHERE id = {}".format(uid)\n'
        'd = "SELECT * FROM t WHERE id = " + str(uid) + " AND x = 1"\n'
        'e = "SELECT * FROM t WHERE name = {name}".format(name=n)\n'
    )
    found = py_findings(src)
    assert [f.location.line for f in found] == [1, 2, 3, 4, 5]
    assert {f.message for f in found} == {
        "SQL statement is assembled with an f-string.",
        "SQL statement is assembled with %-formatting.",
        "SQL statement is assembled with str.format.",
        "SQL statement is assembled with string concatenation.",
    }
    assert all(f.severity == "warning" and f.confidence == "medium" for f in found)


def test_python_stays_silent_for_parameters_literals_and_prose():
    src = (
        'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n'  # driver param
        'cur.execute("SELECT * FROM t WHERE id = ?", [uid])\n'
        'q = "SELECT * FROM t " + "WHERE id = 1"\n'  # literal-only concat
        'msg = f"Select an item from {menu}"\n'  # prose
        'n = "SELECT count FROM cache"\n'  # plain literal
        'lim = "SELECT * FROM t LIMIT " + "10"\n'
    )
    assert py_findings(src) == []


def test_python_reports_a_chain_once():
    src = 'q = ("SELECT * FROM t WHERE a = " + a\n     + " AND b = " + b)\n'
    assert len(py_findings(src)) == 1


# ---- regex languages: one positive, one negative each -----------------------

POSITIVE = {
    "java": (
        'class A {\n'
        '  String a = "SELECT * FROM t WHERE id = " + id;\n'
        '  String b = String.format("SELECT * FROM t WHERE id = %s", id);\n'
        '  String c = "SELECT * FROM t WHERE id = %d".formatted(id);\n'
        '  String d = """\n      SELECT * FROM t\n      WHERE id = """ + id;\n'
        '}\n'
    ),
    "kotlin": (
        'val a = "SELECT * FROM t WHERE id = $id"\n'
        'val b = "SELECT * FROM t WHERE id = ${user.id}"\n'
        'val c = "SELECT * FROM t WHERE id = " + id\n'
        'val d = "SELECT * FROM t WHERE id = %s".format(id)\n'
    ),
    "csharp": (
        'class A {\n'
        '  string a = $"SELECT * FROM t WHERE id = {id}";\n'
        '  string b = "SELECT * FROM t WHERE id = " + id;\n'
        '  string c = string.Format("SELECT * FROM t WHERE id = {0}", id);\n'
        '  string d = $@"SELECT * FROM t\n      WHERE id = {id}";\n'
        '}\n'
    ),
    "typescript": (
        'const a = `SELECT * FROM t WHERE id = ${id}`;\n'
        'const b = "SELECT * FROM t WHERE id = " + id;\n'
        "const c = 'SELECT * FROM t WHERE id = ' + req.params.id;\n"
    ),
    "go": (
        'package p\n'
        'func f() {\n'
        '  a := "SELECT * FROM t WHERE id = " + id\n'
        '  b := fmt.Sprintf("SELECT * FROM t WHERE id = %s", id)\n'
        '  c := `SELECT *\n    FROM t WHERE id = ` + id\n'
        '}\n'
    ),
    "c_cpp": (
        'void f() {\n'
        '  auto a = std::string("SELECT * FROM t WHERE id = ") + id;\n'
        '  snprintf(buf, sizeof buf, "SELECT * FROM t WHERE id = %d", id);\n'
        '  auto c = std::format("SELECT * FROM t WHERE id = {}", id);\n'
        '}\n'
    ),
}
EXPECTED_LINES = {
    "java": [2, 3, 4, 5],
    "kotlin": [1, 2, 3, 4],
    "csharp": [2, 3, 4, 5],
    "typescript": [1, 2, 3],
    "go": [3, 4, 5],
    "c_cpp": [2, 3, 4],
}

NEGATIVE = {
    "java": (
        'class A {\n'
        '  String a = "SELECT * FROM t WHERE id = ?";\n'  # driver parameter
        '  String b = "SELECT * FROM t " + "WHERE id = 1";\n'  # literal-only
        '  String c = "Select an item from the list: " + name;\n'  # prose
        '  String d = "SELECT * FROM t LIMIT " + 10;\n'  # numeric constant
        '  String e = String.format("Select %s from %s", a, b);\n'
        '  // String f = "SELECT * FROM t WHERE id = " + id;\n'  # comment
        '}\n'
    ),
    "kotlin": (
        'val a = "SELECT * FROM t WHERE id = :id"\n'
        'val b = "SELECT * FROM t WHERE cost = \\$5"\n'  # escaped dollar
        'val c = "Select $count items from the cart"\n'
    ),
    "csharp": (
        'class A {\n'
        '  string a = @"SELECT * FROM t WHERE id = @id";\n'  # verbatim, param
        '  string b = $"Select {n} items from cart";\n'
        '  string c = $"SELECT * FROM t WHERE x = {{literal}}";\n'  # escaped brace
        '}\n'
    ),
    "typescript": (
        'const a = "SELECT * FROM t WHERE id = $1";\n'
        'const b = `SELECT * FROM t WHERE id = $1`;\n'  # template, no hole
        'const c = "SELECT * FROM t " + "WHERE id = 1";\n'
    ),
    "go": (
        'package p\n'
        'func f() {\n'
        '  a := "SELECT * FROM t WHERE id = $1"\n'
        '  db.Query("SELECT * FROM t WHERE id = ?", id)\n'
        '  b := fmt.Sprintf("Select %d rows from %s", n, name)\n'
        '}\n'
    ),
    "c_cpp": (
        'void f() {\n'
        '  const char* a = "SELECT * FROM t WHERE id = ?";\n'
        '  const char* b = "SELECT * FROM t " "WHERE id = 1";\n'  # adjacent literals
        '  printf("Select %d from menu", n);\n'
        '}\n'
    ),
}


@pytest.mark.parametrize("language", sorted(ADAPTERS))
def test_regex_language_fires_once_per_statement(language):
    found = findings_for(language, POSITIVE[language])
    assert [f.location.line for f in found] == EXPECTED_LINES[language]
    assert all(f.category == "correctness" for f in found)
    assert all(f.severity == "warning" and f.confidence == "medium" for f in found)
    assert all("driver parameters" in f.remediation for f in found)


@pytest.mark.parametrize("language", sorted(ADAPTERS))
def test_regex_language_stays_silent_for_safe_forms(language):
    assert findings_for(language, NEGATIVE[language]) == []


def test_reasons_are_language_appropriate():
    kt = findings_for("kotlin", POSITIVE["kotlin"])
    assert kt[0].message == "SQL statement is assembled with string interpolation."
    assert kt[2].message == "SQL statement is assembled with string concatenation."
    assert kt[3].message == "SQL statement is assembled with string formatting."
    go = findings_for("go", POSITIVE["go"])
    assert go[1].message == "SQL statement is assembled with string formatting."


def test_multiline_literal_reports_its_first_line():
    found = findings_for("go", POSITIVE["go"])
    assert found[2].location.line == 5 and found[2].location.column == 8
