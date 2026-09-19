# ruff: noqa: E501 -- source fixtures read better on one line
"""Security rule family (``*-SEC-*``), 3.2.0.

Every rule is pinned three ways: the positive shape fires, the idiomatic
safe alternative is silent, and the escape hatches behave (test-path
downgrade to ``note``, same-line ``cqa: ignore=... reason="..."``). Two
regressions found on the calibration corpus are locked: ioredis declares an
interface method literally named ``eval(script: string, ...)`` and jq
concatenates adjacent C literals around an ``#ifdef`` inside ``fprintf``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cqa_analyzer.languages._security import (
    SECRET_NAME,
    Argument,
    classify_argument,
    split_arguments,
)
from cqa_analyzer.languages._suppressions import comment_suppression_lines
from cqa_analyzer.languages.c_family import CLanguageAdapter, CRulePack
from cqa_analyzer.languages.csharp import CSharpLanguageAdapter, CSharpRulePack
from cqa_analyzer.languages.go import GoLanguageAdapter, GoRulePack
from cqa_analyzer.languages.java import JavaLanguageAdapter, JavaRulePack
from cqa_analyzer.languages.kotlin import KotlinLanguageAdapter, KotlinRulePack
from cqa_analyzer.languages.rust import RustLanguageAdapter, RustRulePack
from cqa_analyzer.languages.typescript import TypeScriptLanguageAdapter, TypeScriptRulePack
from cqa_analyzer.protocols import SourceFile
from cqa_analyzer.python_security import SECURITY_RULES
from cqa_analyzer.reporters import _rule_descriptor
from cqa_analyzer.rule_metadata import builtin_rule_ids, rule_metadata

ADAPTERS = {
    "go": (GoLanguageAdapter, GoRulePack, "a.go"),
    "java": (JavaLanguageAdapter, JavaRulePack, "A.java"),
    "kotlin": (KotlinLanguageAdapter, KotlinRulePack, "a.kt"),
    "csharp": (CSharpLanguageAdapter, CSharpRulePack, "a.cs"),
    "typescript": (TypeScriptLanguageAdapter, TypeScriptRulePack, "a.ts"),
    "c_cpp": (CLanguageAdapter, CRulePack, "a.c"),
    "rust": (RustLanguageAdapter, RustRulePack, "a.rs"),
}


def parse(language: str, source: str, name: str | None = None):
    adapter_cls, _pack, default = ADAPTERS[language]
    name = name or default
    parsed = adapter_cls().parse(SourceFile(Path(name), name, name, source))
    assert parsed.complete, "fixture must lex cleanly"
    return parsed


def findings(language: str, source: str, rule_id: str, name: str | None = None):
    parsed = parse(language, source, name)
    return [f for f in ADAPTERS[language][1]().evaluate(parsed) if f.rule_id == rule_id]


def py(source: str, rule_id: str, path: str = "m.py"):
    rule = next(r for r in SECURITY_RULES if r.rule_id == rule_id)()
    return list(rule.evaluate(ast.parse(source), path))


# ---- positive / negative per rule -------------------------------------------

CASES = [
    # (rule, language, positive source, negative source)
    (
        "PY-SEC-001",
        "python",
        "import pickle\nx = pickle.loads(blob)\n",
        "import yaml\nx = yaml.load(f, Loader=yaml.SafeLoader)\ny = yaml.safe_load(f)\n",
    ),
    (
        "PY-SEC-002",
        "python",
        "import subprocess\nsubprocess.run(f'ls {p}', shell=True)\n",
        "import subprocess, os\nsubprocess.run(['ls', p])\nsubprocess.run(f'ls {p}')\nos.system('ls')\n",
    ),
    (
        "PY-SEC-003",
        "python",
        "eval(user)\n",
        "eval('1+1')\nast.literal_eval(user)\ndf.eval(expr)\n",
    ),
    (
        "PY-SEC-004",
        "python",
        "requests.get(u, verify=False)\n",
        "requests.get(u, verify='/etc/ca.pem')\nctx.check_hostname = True\n",
    ),
    (
        "PY-SEC-005",
        "python",
        "import random\ntoken = random.randint(0, 10**9)\n",
        "import random, secrets\nretries = random.randint(0, 3)\ntoken = secrets.token_hex()\n"
        "salt = random.SystemRandom().random()\n",
    ),
    (
        "GO-SEC-001",
        "go",
        'package p\nimport "crypto/tls"\nvar c = &tls.Config{InsecureSkipVerify: true}\n',
        'package p\nimport "crypto/tls"\nvar c = &tls.Config{InsecureSkipVerify: false}\n',
    ),
    (
        "GO-SEC-002",
        "go",
        'package p\nimport "os/exec"\nfunc f(c string) { exec.Command("sh", "-c", c) }\n',
        'package p\nimport "os/exec"\nfunc f(c string) { exec.Command("sh", "-c", "ls")\n'
        'exec.Command(c)\nexec.Command("ls", c) }\n',
    ),
    (
        "GO-SEC-003",
        "go",
        'package p\nimport "math/rand"\nfunc f() { sessionToken := rand.Int63(); _ = sessionToken }\n',
        'package p\nimport "crypto/rand"\nfunc f() { token := rand.Read(b); n := rand.Intn(3); _, _ = token, n }\n',
    ),
    (
        "JAVA-SEC-001",
        "java",
        "class A { Object f(InputStream in) { return new ObjectInputStream(in).readObject(); } }\n",
        "class A { Object f(String s) { return mapper.readValue(s, A.class); } }\n",
    ),
    (
        "JAVA-SEC-002",
        "java",
        "class A { void f(String c) throws Exception { Runtime.getRuntime().exec(c); } }\n",
        'class A { void f(String c) throws Exception { Runtime.getRuntime().exec("ls");\n'
        'new ProcessBuilder("ls", "-la", c); } }\n',
    ),
    (
        "JAVA-SEC-003",
        "java",
        "class T { public void checkServerTrusted(X509Certificate[] c, String a) {} }\n",
        "class T { public void checkServerTrusted(X509Certificate[] c, String a) { "
        "validator.check(c); } }\n",
    ),
    (
        "KT-SEC-001",
        "kotlin",
        "fun f(i: InputStream): Any = ObjectInputStream(i).readObject()\n",
        "fun f(s: String): A = Json.decodeFromString(s)\n",
    ),
    (
        "KT-SEC-002",
        "kotlin",
        'fun f(c: String) { ProcessBuilder("sh", "-c", c).start() }\n',
        'fun f(c: String) { ProcessBuilder("ls", c).start() }\n',
    ),
    (
        "KT-SEC-003",
        "kotlin",
        "class V : HostnameVerifier { override fun verify(h: String, s: SSLSession): Boolean = true }\n",
        "class V : HostnameVerifier { override fun verify(h: String, s: SSLSession): Boolean = "
        "h == expected }\n",
    ),
    (
        "CS-SEC-001",
        "csharp",
        "class A { object F(Stream s) { return new BinaryFormatter().Deserialize(s); } }\n",
        "class A { object F(string s) { return JsonSerializer.Deserialize<A>(s); }\n"
        "  var o = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None }; }\n",
    ),
    (
        "CS-SEC-002",
        "csharp",
        'class A { void F(string c) { Process.Start("cmd.exe", $"/c {c}"); } }\n',
        'class A { void F(string c) { Process.Start("cmd.exe", "/c dir"); Process.Start(c); } }\n',
    ),
    (
        "CS-SEC-003",
        "csharp",
        "class A { void F() { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true; } }\n",
        "class A { void F() { h.ServerCertificateCustomValidationCallback = Validate; } }\n",
    ),
    ("TS-SEC-001", "typescript", "eval(code);\n", "eval('1+1');\nJSON.parse(code);\n"),
    (
        "TS-SEC-002",
        "typescript",
        'import { exec } from "child_process";\nexec(`ls ${dir}`);\n',
        'import { execFile } from "child_process";\nexecFile("ls", [dir]);\nre.exec(dir);\n',
    ),
    (
        "TS-SEC-003",
        "typescript",
        "el.innerHTML = userHtml;\n",
        "el.innerHTML = '<b>x</b>';\nel.textContent = userHtml;\n"
        "el.innerHTML = DOMPurify.sanitize(userHtml);\n",
    ),
    (
        "TS-SEC-004",
        "typescript",
        "const a = new https.Agent({ rejectUnauthorized: false });\n",
        "const a = new https.Agent({ rejectUnauthorized: true, ca });\n"
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n",
    ),
    (
        "C-SEC-001",
        "c_cpp",
        "void f(char *b, const char *s) { strcpy(b, s); }\n",
        "extern char *strcpy(char *, const char *);\nint my_strcpy(char *a, const char *b);\n"
        "void f(char *b, const char *s) { strncpy(b, s, 8); obj.strcpy(b); }\n",
    ),
    (
        "C-SEC-002",
        "c_cpp",
        "void f(const char *c) { system(c); }\n",
        'int system(const char *);\nvoid f(const char *c) { system("ls -la"); }\n',
    ),
    (
        "C-SEC-003",
        "c_cpp",
        "void f(const char *m) { printf(m); }\n",
        '#define BANNER "hi"\nvoid f(const char *m) { printf("%s", m); printf(BANNER); '
        "fprintf(stderr, m, 1); }\n",
    ),
    (
        "RS-SEC-001",
        "rust",
        "fn f(p: *const u8) -> u8 { unsafe { *p } }\n",
        "fn f(p: *const u8) -> u8 {\n    // SAFETY: p is valid for the call.\n    unsafe { *p }\n}\n",
    ),
    (
        "RS-SEC-002",
        "rust",
        'fn f(c: &str) { Command::new("sh").arg("-c").arg(c).status(); }\n',
        'fn f(c: &str) { Command::new("sh").arg("-c").arg("ls").status();\n'
        'Command::new("ls").arg(c).status(); }\n',
    ),
    (
        "RS-SEC-003",
        "rust",
        "fn f() { let c = Client::builder().danger_accept_invalid_certs(true).build(); }\n",
        "fn f() { let c = Client::builder().add_root_certificate(ca).build(); }\n",
    ),
]


def _run(rule_id: str, language: str, source: str):
    if language == "python":
        return py(source, rule_id)
    return findings(language, source, rule_id)


@pytest.mark.parametrize("rule_id,language,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_positive_fires_and_negative_is_silent(rule_id, language, positive, negative):
    hits = _run(rule_id, language, positive)
    assert hits, f"{rule_id} should fire on the positive fixture"
    assert all(f.category == "security" and f.severity == "warning" for f in hits)
    assert not _run(rule_id, language, negative), f"{rule_id} fired on the safe form"


def test_every_sec_rule_has_a_case_and_metadata():
    sec_rules = [r for r in builtin_rule_ids() if "-SEC-" in r]
    assert len(sec_rules) == 27
    assert {c[0] for c in CASES} == set(sec_rules)
    for rule_id in sec_rules:
        meta = rule_metadata(rule_id)
        assert meta.category == "security"
        assert meta.cwe and all(c.startswith("CWE-") for c in meta.cwe)
        assert meta.security_severity is not None
        assert meta.not_when, rule_id


# ---- escape hatches ---------------------------------------------------------


@pytest.mark.parametrize(
    "rule_id,language,source,test_name",
    [
        (
            "GO-SEC-001",
            "go",
            'package p\nimport "crypto/tls"\nvar c = &tls.Config{InsecureSkipVerify: true}\n',
            "a_test.go",
        ),
        (
            "JAVA-SEC-003",
            "java",
            "class T { public void checkServerTrusted(X509Certificate[] c, String a) {} }\n",
            "src/test/java/T.java",
        ),
        (
            "TS-SEC-004",
            "typescript",
            "const a = new https.Agent({ rejectUnauthorized: false });\n",
            "tls.spec.ts",
        ),
        (
            "RS-SEC-003",
            "rust",
            "fn f() { Client::builder().danger_accept_invalid_certs(true); }\n",
            "tests/tls.rs",
        ),
    ],
)
def test_fixtures_in_test_paths_are_notes_not_warnings(rule_id, language, source, test_name):
    (hit,) = findings(language, source, rule_id, name=test_name)
    assert hit.severity == "note"


def test_python_test_path_downgrade():
    (hit,) = py("import pickle\nx = pickle.loads(b)\n", "PY-SEC-001", path="tests/test_x.py")
    assert hit.severity == "note"
    (hit,) = py("import pickle\nx = pickle.loads(b)\n", "PY-SEC-001", path="app/x.py")
    assert hit.severity == "warning"


def test_shell_rules_are_not_downgraded_in_tests():
    (hit,) = findings(
        "go",
        'package p\nimport "os/exec"\nfunc f(c string) { exec.Command("sh", "-c", c) }\n',
        "GO-SEC-002",
        name="a_test.go",
    )
    assert hit.severity == "warning"


@pytest.mark.parametrize(
    "language,source",
    [
        (
            "go",
            'package p\nimport "crypto/tls"\n'
            'var c = &tls.Config{InsecureSkipVerify: true} // cqa: ignore=GO-SEC-001 reason="local proxy"\n',
        ),
        (
            "c_cpp",
            'void f(const char *c) { system(c); /* cqa: ignore=C-SEC-002 reason="trusted" */ }\n',
        ),
        ("typescript", "eval(code); // cqa: ignore=TS-SEC-001 reason='plugin sandbox'\n"),
    ],
)
def test_same_line_directive_with_reason_suppresses(language, source):
    parsed = parse(language, source)
    assert not [f for f in ADAPTERS[language][1]().evaluate(parsed) if "-SEC-" in f.rule_id]


def test_directive_without_reason_or_for_other_rule_does_not_suppress():
    assert findings("typescript", 'eval(code); // cqa: ignore=TS-SEC-001 reason=""\n', "TS-SEC-001")
    assert findings("typescript", "eval(code); // cqa: ignore=TS-SEC-001\n", "TS-SEC-001")
    assert findings(
        "typescript", 'eval(code); // cqa: ignore=TS-SEC-002 reason="other"\n', "TS-SEC-001"
    )


def test_comment_suppression_lines_parse_multiple_rules():
    lines = comment_suppression_lines('x\ny // cqa: ignore=A-SEC-001, B-SEC-002 reason="why"\n')
    assert lines == frozenset({(2, "A-SEC-001"), (2, "B-SEC-002")})


# ---- corpus regressions -----------------------------------------------------


def test_interface_method_named_eval_is_a_declaration_not_a_call():
    # ioredis lib/utils/RedisCommander.ts: 9 false positives before the fix.
    source = (
        "interface Commander {\n"
        "  eval(script: string | Buffer, numkeys: number, callback?: Callback<unknown>): Result<unknown>;\n"
        "  eval(...args: [script: string | Buffer, numkeys: number]): Result<unknown>;\n"
        "}\n"
        "class C { exec(cmd: string) { return cmd; } }\n"
    )
    assert not findings("typescript", source, "TS-SEC-001")


def test_adjacent_c_literals_with_preprocessor_lines_are_one_literal():
    # jq src/main.c: a usage string built from adjacent literals around #ifdef WIN32.
    source = (
        "void usage(FILE *f) {\n"
        "  (void) fprintf(f,\n"
        '    "Command options:\\n"\n'
        '    "  -n   null input\\n"\n'
        "#ifdef WIN32\n"
        '    "  --windows\\n"\n'
        "#endif\n"
        '    "  -s   slurp\\n");\n'
        "}\n"
    )
    assert not findings("c_cpp", source, "C-SEC-003")


# ---- shared classifier ------------------------------------------------------


def test_split_arguments_respects_nesting_and_blanked_strings():
    parsed = parse("typescript", 'f(a, g(b, c), "x, y", [1, 2]);\n')
    spans, close = split_arguments(parsed.facts.code_text, 1)
    assert [parsed.source.content[s:e].strip() for s, e in spans] == [
        "a",
        "g(b, c)",
        '"x, y"',
        "[1, 2]",
    ]
    assert parsed.source.content[close] == ")"


@pytest.mark.parametrize(
    "language,call,expected",
    [
        ("typescript", 'f("plain")', Argument("literal", "plain")),
        ("typescript", "f(`tpl ${x}`)", Argument("dynamic")),
        ("typescript", 'f("a" + b)', Argument("dynamic")),
        ("typescript", "f()", Argument("empty")),
        ("csharp", 'F($"{x}")', Argument("dynamic")),
        ("csharp", 'F(@"verbatim")', Argument("literal", "verbatim")),
        ("kotlin", 'f("$x")', Argument("dynamic")),
        ("rust", 'f(r#"raw"#)', Argument("literal", "raw")),
    ],
)
def test_classify_argument(language, call, expected):
    from cqa_analyzer.languages import _sql

    interpolates = {
        "typescript": _sql.TYPESCRIPT_SQL.interpolates,
        "csharp": _sql.CSHARP_SQL.interpolates,
        "kotlin": _sql.KOTLIN_SQL.interpolates,
        "rust": None,
    }[language]
    parsed = parse(language, call + ";\n" if language != "rust" else f"fn g() {{ {call}; }}\n")
    code_text = parsed.facts.code_text
    spans, _ = split_arguments(code_text, code_text.rindex("("))
    assert classify_argument(parsed, spans[0], interpolates) == expected


@pytest.mark.parametrize(
    "name", ["token", "apiKey", "SESSION_ID", "csrf_token", "reset_code", "password"]
)
def test_secret_names_match(name):
    assert SECRET_NAME.search(name)


@pytest.mark.parametrize("name", ["counter", "retries", "index", "delay_ms", "shuffle_seed"])
def test_ordinary_names_do_not_match(name):
    assert not SECRET_NAME.search(name)


# ---- SARIF --------------------------------------------------------------------


def test_sarif_descriptor_carries_security_severity_and_cwe_tags():
    descriptor = _rule_descriptor(rule_metadata("PY-SEC-002"))
    assert descriptor["properties"]["security-severity"] == "8.8"
    assert descriptor["properties"]["tags"] == ["security", "external/cwe/cwe-78"]
    multi = _rule_descriptor(rule_metadata("C-SEC-001"))
    assert multi["properties"]["tags"] == [
        "security",
        "external/cwe/cwe-120",
        "external/cwe/cwe-676",
    ]


@pytest.mark.parametrize(
    "rule_id",
    [
        "PY-COR-007",
        "GO-COR-002",
        "JAVA-COR-002",
        "KT-COR-002",
        "CS-COR-002",
        "TS-COR-002",
        "C-COR-002",
        "RS-COR-002",
    ],
)
def test_dynamic_sql_rules_are_tagged_as_security(rule_id):
    descriptor = _rule_descriptor(rule_metadata(rule_id))
    assert descriptor["properties"]["security-severity"] == "8.8"
    assert "external/cwe/cwe-89" in descriptor["properties"]["tags"]
    assert descriptor["properties"]["category"] == "correctness"  # ID and category unchanged


def test_quality_rules_carry_no_security_properties():
    descriptor = _rule_descriptor(rule_metadata("PY-MAINT-001"))
    assert "security-severity" not in descriptor["properties"]
    assert "tags" not in descriptor["properties"]
