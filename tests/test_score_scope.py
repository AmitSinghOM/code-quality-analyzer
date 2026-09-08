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


def test_go_only_project_reports_score_not_applicable(project):
    root = project({"main.go": _GO_SOURCE})

    result = run([str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["architecture_signal_score"] is None
    assert payload["rating"] is None
    assert payload["architecture_signal_label"] == "Not applicable"
    assert payload["architecture_signal_scope"] == {
        "languages": ["python"],
        "applicable": False,
    }


def test_go_only_text_report_shows_not_applicable(project):
    root = project({"main.go": _GO_SOURCE})

    result = run([str(root)])

    assert result.exit_code == EXIT_OK
    assert "Not applicable" in result.output
    assert "/10" not in result.output


def test_go_only_fail_under_exits_distinctly(project):
    root = project({"main.go": _GO_SOURCE})

    result = run([str(root), "--fail-under", "5"])

    assert result.exit_code == EXIT_SCORE_NOT_APPLICABLE


def test_python_project_score_remains_applicable(project):
    root = project({"module.py": _PY_SOURCE})

    result = run([str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["architecture_signal_scope"] == {
        "languages": ["python"],
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
