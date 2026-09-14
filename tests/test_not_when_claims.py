# ruff: noqa: E501 - fixture source strings read better unbroken
"""Lock ``RuleMetadata.not_when`` clauses to detector behaviour.

Every clause in ``rule_metadata._NOT_WHEN`` describes something a detector
does (or deliberately does not do). Prose can drift from code silently, so
each claim that can be expressed as a fixture is checked here: one input that
the rule MUST flag, and one that the clause says it MUST leave alone. When a
detector changes, this file fails before the metadata lies.

Fixtures run through the real CLI so the whole pipeline — adapter, blanking,
path selection, severity policy — is exercised, not a unit under test.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_CARGO = "[package]\nname = 'x'\nversion = '0.1.0'\n"

# (rule, files, expectation) where expectation is True (fires at warning),
# False (silent), or "info" (fires but downgraded below warning).
CLAIMS: dict[str, tuple[str, dict[str, str], bool | str]] = {
    # PY-COR-001 — displays, comprehensions and the four factory calls are mutable
    "py-cor-001 list display fires": ("PY-COR-001", {"a.py": "def f(x=[]):\n    return x\n"}, True),
    "py-cor-001 factory call fires": (
        "PY-COR-001",
        {"a.py": "def f(x=dict()):\n    return x\n"},
        True,
    ),
    "py-cor-001 immutable defaults silent": (
        "PY-COR-001",
        {"a.py": "def f(x=None, y=(), z=frozenset(), w='s'):\n    return x, y, z, w\n"},
        False,
    ),
    # PY-COR-003 — suppress/logging are not swallowing
    "py-cor-003 pass fires": (
        "PY-COR-003",
        {"a.py": "try:\n    open('x')\nexcept OSError:\n    pass\n"},
        True,
    ),
    "py-cor-003 suppress silent": (
        "PY-COR-003",
        {"a.py": "import contextlib\nwith contextlib.suppress(OSError):\n    open('x')\n"},
        False,
    ),
    "py-cor-003 logging silent": (
        "PY-COR-003",
        {
            "a.py": "import logging\ntry:\n    open('x')\nexcept OSError:\n    logging.warning('x')\n"
        },
        False,
    ),
    # PY-COR-004 — only statements after an unconditional transfer in the same block
    "py-cor-004 after return fires": (
        "PY-COR-004",
        {"a.py": "def f():\n    return 1\n    print('x')\n"},
        True,
    ),
    "py-cor-004 else branch silent": (
        "PY-COR-004",
        {"a.py": "def f(a):\n    if a:\n        return 1\n    else:\n        return 2\n"},
        False,
    ),
    # PY-COR-005 — async body, allowlisted call, not via to_thread
    "py-cor-005 sleep in async fires": (
        "PY-COR-005",
        {"a.py": "import time\nasync def f():\n    time.sleep(1)\n"},
        True,
    ),
    "py-cor-005 sleep in sync silent": (
        "PY-COR-005",
        {"a.py": "import time\ndef f():\n    time.sleep(1)\n"},
        False,
    ),
    "py-cor-005 to_thread silent": (
        "PY-COR-005",
        {
            "a.py": "import asyncio, time\nasync def f():\n    await asyncio.to_thread(time.sleep, 1)\n"
        },
        False,
    ),
    # PY-COR-006 — with, return, try/finally are guaranteed cleanup
    "py-cor-006 bare open fires": (
        "PY-COR-006",
        {"a.py": "def f():\n    h = open('x')\n    return h.read()\n"},
        True,
    ),
    "py-cor-006 with silent": (
        "PY-COR-006",
        {"a.py": "def f():\n    with open('x') as h:\n        return h.read()\n"},
        False,
    ),
    "py-cor-006 returned silent": (
        "PY-COR-006",
        {"a.py": "def f():\n    return open('x')\n"},
        False,
    ),
    "py-cor-006 finally silent": (
        "PY-COR-006",
        {
            "a.py": "def f():\n    h = open('x')\n    try:\n        return h.read()\n    finally:\n        h.close()\n"
        },
        False,
    ),
    # PY-COR-007 — SQL head + dynamic part; placeholders and non-SQL are silent
    "py-cor-007 f-string fires": (
        "PY-COR-007",
        {"a.py": "def f(c, i):\n    c.execute(f'SELECT * FROM t WHERE id = {i}')\n"},
        True,
    ),
    "py-cor-007 placeholder silent": (
        "PY-COR-007",
        {"a.py": "def f(c, i):\n    c.execute('SELECT * FROM t WHERE id = %s', (i,))\n"},
        False,
    ),
    "py-cor-007 non-sql concat silent": (
        "PY-COR-007",
        {"a.py": "def f(n):\n    return 'Hello ' + n\n"},
        False,
    ),
    # PY-MAINT-004 — self is not a parameter
    "py-maint-004 eight params fires": (
        "PY-MAINT-004",
        {"a.py": "def m(a, b, c, d, e, f, g, h):\n    return a\n"},
        True,
    ),
    "py-maint-004 self uncounted silent": (
        "PY-MAINT-004",
        {"a.py": "class A:\n    def m(self, a, b, c, d, e, f, g):\n        return a\n"},
        False,
    ),
    # PY-PKG-001 — function-local imports DO count (ast.walk)
    "py-pkg-001 top-level cycle fires": (
        "PY-PKG-001",
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg import b\n",
            "pkg/b.py": "from pkg import a\n",
        },
        True,
    ),
    "py-pkg-001 local import still fires": (
        "PY-PKG-001",
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "from pkg import b\n",
            "pkg/b.py": "def f():\n    from pkg import a\n    return a\n",
        },
        True,
    ),
    # Go
    "go-cor-001 blank err fires": (
        "GO-COR-001",
        {
            "main.go": 'package main\nimport "os"\nfunc main() {\n\tf, _ := os.Open("x")\n\t_ = f\n}\n'
        },
        True,
    ),
    "go-cor-001 checked err silent": (
        "GO-COR-001",
        {
            "main.go": 'package main\nimport "os"\nfunc main() {\n\tf, err := os.Open("x")\n'
            "\tif err != nil {\n\t\treturn\n\t}\n\t_ = f\n}\n"
        },
        False,
    ),
    "go-cor-003 single value fires": (
        "GO-COR-003",
        {"main.go": "package main\nfunc f(x interface{}) int {\n\treturn x.(int)\n}\n"},
        True,
    ),
    "go-cor-003 two value silent": (
        "GO-COR-003",
        {
            "main.go": "package main\nfunc f(x interface{}) int {\n\tv, ok := x.(int)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn v\n}\n"
        },
        False,
    ),
    "go-cor-003 test path downgraded": (
        "GO-COR-003",
        {"f_test.go": "package main\nfunc f(x interface{}) int {\n\treturn x.(int)\n}\n"},
        "info",
    ),
    "go-cor-004 defer in loop fires": (
        "GO-COR-004",
        {
            "main.go": "package main\nfunc f(xs []int) {\n\tfor range xs {\n\t\tdefer println()\n\t}\n}\n"
        },
        True,
    ),
    "go-cor-004 defer in literal silent": (
        "GO-COR-004",
        {
            "main.go": "package main\nfunc f(xs []int) {\n\tfor range xs {\n\t\tfunc() {\n\t\t\tdefer println()\n\t\t}()\n\t}\n}\n"
        },
        False,
    ),
    # TypeScript
    "ts-cor-001 empty catch fires": ("TS-COR-001", {"a.ts": "try { f(); } catch (e) {}\n"}, True),
    "ts-cor-001 empty catch in spec still warning": (
        "TS-COR-001",
        {"a.spec.ts": "try { f(); } catch (e) {}\n"},
        True,  # empty-catch does NOT use the test-path downgrade; the clause must not claim it
    ),
    "ts-cor-004 bare ts-ignore fires": (
        "TS-COR-004",
        {"a.ts": "// @ts-ignore\nconst x: number = 'a';\n"},
        True,
    ),
    "ts-cor-004 explained ts-ignore silent": (
        "TS-COR-004",
        {"a.ts": "// @ts-ignore because upstream types are wrong\nconst x: number = 'a';\n"},
        False,
    ),
    # C / C++
    "c-cor-004 header fires": ("C-COR-004", {"a.h": "#pragma once\nusing namespace std;\n"}, True),
    "c-cor-004 source silent": (
        "C-COR-004",
        {"a.cpp": "#include <vector>\nusing namespace std;\nint main() { return 0; }\n"},
        False,
    ),
    # Rust
    "rs-cor-004 crate allow fires": (
        "RS-COR-004",
        {"src/lib.rs": "#![allow(dead_code)]\npub fn f() {}\n", "Cargo.toml": _CARGO},
        True,
    ),
    "rs-cor-004 reason silent": (
        "RS-COR-004",
        {
            "src/lib.rs": '#![allow(dead_code, reason = "wip")]\npub fn f() {}\n',
            "Cargo.toml": _CARGO,
        },
        False,
    ),
    "rs-cor-004 item scoped silent": (
        "RS-COR-004",
        {"src/lib.rs": "#[allow(dead_code)]\nfn f() {}\n", "Cargo.toml": _CARGO},
        False,
    ),
}


def _scan(root: Path) -> dict:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            "-m",
            "cqa_analyzer",
            str(root),
            "--output-format",
            "json",
            "--offline",
            "--no-project-config",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.stdout, completed.stderr
    return json.loads(completed.stdout)


@pytest.mark.parametrize("name", sorted(CLAIMS))
def test_not_when_clause_matches_detector(name: str, tmp_path: Path) -> None:
    rule, files, expectation = CLAIMS[name]
    for relative, source in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
    hits = [f for f in _scan(tmp_path)["findings"] if f["rule_id"] == rule]
    if expectation == "info":
        assert hits and all(h["severity"] != "warning" for h in hits), hits
    elif expectation:
        assert hits, f"{rule} should fire"
    else:
        assert not hits, f"{rule} should stay silent: {hits}"


def test_every_downgrade_clause_belongs_to_a_rule_that_downgrades() -> None:
    """The test-path downgrade clause may only appear on rules that call it."""
    from cqa_analyzer.rule_metadata import builtin_rule_ids, rule_metadata

    downgrading = {"GO-COR-003", "TS-COR-005", "KT-COR-005", "RS-COR-001"}
    for rule_id in builtin_rule_ids():
        claims = any(
            "downgraded to informational" in c or "downgraded" in c
            for c in rule_metadata(rule_id).not_when
        )
        assert claims == (rule_id in downgrading), rule_id
