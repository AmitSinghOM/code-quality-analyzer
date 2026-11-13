"""``--anonymize`` must tokenize paths inside every provider's health block.

Provider health (``scan_health.project_analysis[...]`` and
``project_analyses[...].health``) is a verbatim copy of each project-level
provider's discovery summary, whose ``skipped_examples`` hold real display
paths. The top-level examples were tokenized; the per-provider copies were
not, so a shareable report named the files the complexity provider skipped.
"""

from __future__ import annotations

import json

from clirunner import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.anonymize import ReportAnonymizer
from cqa_analyzer.complexity import ProjectComplexityAnalyzer

PRIVATE_DIR = "secret_customer_acme"
PRIVATE_FILE = "confidential_module_xyz"


def _strings(value):
    """Yield every string anywhere in a JSON-like value, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def _leaks(payload) -> list[str]:
    return [
        text
        for text in _strings(payload)
        if PRIVATE_DIR in text or PRIVATE_FILE in text
    ]


def _run(root, output_format: str):
    return CliRunner().invoke(
        main,
        [
            str(root),
            "--complexity",
            "--anonymize",
            "--offline",
            "--output-format",
            output_format,
        ],
    )


def _leaky_project(project):
    # Through the CLI the complexity provider only sees already-parsed trees,
    # so the one reachable skip is ``too_many_functions``: a file holding more
    # than ``ProjectComplexityAnalyzer.MAX_FUNCTIONS_PER_FILE`` defs is skipped and its
    # display path is recorded under ``skipped_examples``.
    too_many = "".join(
        f"def f{index}():\n    return {index}\n"
        for index in range(ProjectComplexityAnalyzer.MAX_FUNCTIONS_PER_FILE + 1)
    )
    return project(
        {
            f"{PRIVATE_DIR}/{PRIVATE_FILE}.py": too_many,
            f"{PRIVATE_DIR}/ok.py": "def fine():\n    return 1\n",
        }
    )


def test_anonymized_json_carries_no_provider_health_path(project):
    root = _leaky_project(project)

    result = _run(root, "json")
    payload = json.loads(result.output)

    provider = payload["scan_health"]["project_analysis"]["python:complexity"]
    assert provider["skipped_examples"]["too_many_functions"], "fixture did not trigger a skip"
    assert payload["privacy"]["anonymized"] is True
    assert _leaks(payload) == []
    assert PRIVATE_FILE not in result.output


def test_anonymized_sarif_carries_no_provider_health_path(project):
    root = _leaky_project(project)

    result = _run(root, "sarif")
    payload = json.loads(result.output)

    assert payload["runs"], "no SARIF run emitted"
    assert _leaks(payload) == []
    assert PRIVATE_FILE not in result.output


def test_scan_health_tokenizes_provider_examples_without_adding_keys():
    anonymizer = ReportAnonymizer()
    health = {
        "skipped_examples": {"too_large": ["top/a.py"]},
        "unparsed_examples": ["top/b.py"],
        "excluded_generated_examples": {},
        "project_analysis": {
            "python:complexity": {
                "skipped_examples": {"syntax_error": ["private/c.py"]},
                "unparsed_examples": ["private/d.py"],
                "excluded_generated_examples": {"vendored": ["private/e.py"]},
                "failed_functions": 0,
            },
            "go:package-graph": {"errors": 0, "complete": True, "package_count": 1},
        },
    }

    payload = anonymizer.scan_health(health)

    complexity = payload["project_analysis"]["python:complexity"]
    assert complexity["skipped_examples"] == {"syntax_error": ["file-0003"]}
    assert complexity["unparsed_examples"] == ["file-0004"]
    assert complexity["excluded_generated_examples"] == {"vendored": ["file-0005"]}
    assert complexity["failed_functions"] == 0
    # Provider health without example keys keeps its exact shape.
    assert payload["project_analysis"]["go:package-graph"] == {
        "errors": 0,
        "complete": True,
        "package_count": 1,
    }
    assert "private" not in str(payload)
    # Input is not mutated.
    assert health["project_analysis"]["python:complexity"]["skipped_examples"] == {
        "syntax_error": ["private/c.py"]
    }
