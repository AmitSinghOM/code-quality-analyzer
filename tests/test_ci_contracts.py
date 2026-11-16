"""Source contracts for canary dependency coverage; never execute workflow commands."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _job(workflow, name):
    match = re.search(rf"^  {name}:\n(.*?)(?=^  [\w-]+:|\Z)", workflow, re.M | re.S)
    assert match, name
    return match.group(1)


@pytest.mark.parametrize("name", ["latest-dependencies", "python-prerelease"])
def test_full_suite_canaries_install_schema_validator_without_dev_pins(name):
    workflow = (ROOT / ".github/workflows/canary.yml").read_text()
    job = _job(workflow, name)
    installs = [shlex.split(line.strip()) for line in job.splitlines() if "pip install" in line]
    assert any("pytest" in args and "jsonschema" in args for args in installs)
    assert not any("dev" in arg for args in installs for arg in args)
    assert "run: pytest -p no:cacheprovider -q\n" in job
    assert not any("ruff" in args for args in installs)


def test_grammar_canary_preserves_its_targeted_scope():
    job = _job((ROOT / ".github/workflows/canary.yml").read_text(), "grammar-ceiling")
    assert "pip install --upgrade tree-sitter " in job
    for name in ["deep", "rust", "c_family", "go_signals"]:
        assert f"tests/test_{name}.py" in job


def test_python_prerelease_canary_is_one_minor_above_the_ci_matrix():
    """The canary tests the NEXT Python; once that Python ships it joins CI.

    3.15-dev silently became stable 3.15 in October 2026 and the canary kept
    running it, so it stopped testing a pre-release at all. Lock the invariant:
    the pre-release line is exactly one minor above the newest `test` matrix
    entry, which must also carry a classifier.
    """
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    matrix = re.search(r"^\s+python-version: \[(.*?)\]", _job(ci, "test"), re.M).group(1)
    minors = sorted(int(v) for v in re.findall(r"'3\.(\d+)'", matrix))
    newest = minors[-1]
    assert minors == list(range(minors[0], newest + 1)), minors
    canary = _job((ROOT / ".github/workflows/canary.yml").read_text(), "python-prerelease")
    assert f"python-version: '3.{newest + 1}-dev'" in canary
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert f'"Programming Language :: Python :: 3.{newest}"' in pyproject
    assert f'"Programming Language :: Python :: 3.{newest + 1}"' not in pyproject


def test_workflow_changes_trigger_push_and_pull_request_ci():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    for event in ["push", "pull_request"]:
        assert '".github/workflows/*.yml"' in _job(workflow, event)
