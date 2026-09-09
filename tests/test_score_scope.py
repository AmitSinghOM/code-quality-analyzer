"""Architecture signal score scope and not-applicable reporting."""

from __future__ import annotations

import json

from click.testing import CliRunner

from cqa_analyzer.__main__ import (
    EXIT_BELOW_THRESHOLD,
    EXIT_OK,
    EXIT_SCORE_NOT_APPLICABLE,
    main,
)
from cqa_analyzer.languages.go import (
    GoLanguageAdapter,
    GoRulePack,
)
from cqa_analyzer.registry import PluginRegistry
from cqa_analyzer.scanner import CodeScanner

_GO_SOURCE = (
    "package main\n"
    "\n"
    'import "fmt"\n'
    "\n"
    "func main() {\n"
    '\tfmt.Println("hello")\n'
    "}\n"
)

_PY_SOURCE = "VALUE = 1\n"


def run(args):
    return CliRunner().invoke(main, args)


def test_go_only_project_score_is_now_applicable(project):
    root = project({"main.go": _GO_SOURCE})

    result = run([str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["architecture_signal_scope"] == {
        "languages": ["csharp", "go", "java", "kotlin", "python", "typescript"],
        "applicable": True,
    }


def test_scope_is_not_applicable_without_signal_providers(project):
    root = project({"main.go": _GO_SOURCE})
    registry = PluginRegistry()
    registry.register_language(GoLanguageAdapter())
    registry.register_rule_pack(GoRulePack())
    scanner = CodeScanner(root, registry=registry)

    scanner.scan()
    scope = scanner.architecture_signal_scope()

    assert scope == {"languages": [], "applicable": False}


def test_fail_under_on_not_applicable_score_exits_distinctly(project):
    from cqa_analyzer.__main__ import _exit_code

    root = project({"main.go": _GO_SOURCE})
    registry = PluginRegistry()
    registry.register_language(GoLanguageAdapter())
    registry.register_rule_pack(GoRulePack())
    scanner = CodeScanner(root, registry=registry)
    scanner.scan()

    exit_code = _exit_code(
        scanner,
        1.0,
        scanner.architecture_signal_scope(),
        fail_under=5.0,
        strict=False,
    )

    assert exit_code == EXIT_SCORE_NOT_APPLICABLE


def test_python_project_score_remains_applicable(project):
    root = project({"module.py": _PY_SOURCE})

    result = run([str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["architecture_signal_scope"] == {
        "languages": ["csharp", "go", "java", "kotlin", "python", "typescript"],
        "applicable": True,
    }


def test_python_fail_under_still_gates_normally(project):
    root = project({"module.py": _PY_SOURCE})

    result = run([str(root), "--fail-under", "9.5"])

    assert result.exit_code == EXIT_BELOW_THRESHOLD


def test_mixed_project_score_is_applicable(project):
    root = project({"module.py": _PY_SOURCE, "main.go": _GO_SOURCE})

    result = run([str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["architecture_signal_scope"]["applicable"] is True
