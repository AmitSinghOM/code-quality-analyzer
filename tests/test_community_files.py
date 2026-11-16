"""Community files exist and route feedback where the project says (E15)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
TEMPLATES = ROOT / ".github" / "ISSUE_TEMPLATE"
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")
COMMUNITY_FILES = [
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "GOVERNANCE.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/false_positive.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("relative", COMMUNITY_FILES)
def test_community_file_exists_and_is_not_empty(relative):
    path = ROOT / relative
    assert path.is_file(), relative
    assert path.read_text(encoding="utf-8").strip(), relative


def test_blank_issues_are_disabled_and_vulnerabilities_route_to_security_policy():
    config = _read(".github/ISSUE_TEMPLATE/config.yml")
    assert re.search(r"^blank_issues_enabled:\s*false\s*$", config, re.MULTILINE), config
    assert "SECURITY.md" in config


@pytest.mark.parametrize("name", ["bug_report", "false_positive", "feature_request"])
def test_issue_form_has_the_shape_github_requires(name):
    """Issue forms need top-level name, description and a non-empty body."""
    form = _read(f".github/ISSUE_TEMPLATE/{name}.yml")
    for key in ("name:", "description:", "body:"):
        assert re.search(rf"^{key}", form, re.MULTILINE), (name, key)
    ids = re.findall(r"^\s+id:\s*([\w-]+)\s*$", form, re.MULTILINE)
    assert ids, name
    assert len(ids) == len(set(ids)), f"duplicate element ids in {name}: {ids}"


@pytest.mark.parametrize("name", ["bug_report", "false_positive"])
def test_repro_forms_require_a_synthetic_only_confirmation(name):
    """No proprietary code or paths may enter the public tracker; see SECURITY.md."""
    form = _read(f".github/ISSUE_TEMPLATE/{name}.yml")
    assert "type: checkboxes" in form, name
    assert "synthetic" in form.lower(), name
    assert "required: true" in form, name


def test_false_positive_form_collects_what_a_fixture_needs():
    form = _read(".github/ISSUE_TEMPLATE/false_positive.yml")
    for element_id in ("rule-id", "snippet", "why-safe", "verbose-evidence", "synthetic-only"):
        assert re.search(rf"^\s+id:\s*{element_id}\s*$", form, re.MULTILINE), element_id
    assert "-v" in form or "--verbose" in form


def test_code_of_conduct_is_covenant_2_1_with_the_project_channel_filled_in():
    text = _read("CODE_OF_CONDUCT.md")
    assert "Contributor Covenant" in text
    assert "version 2.1" in text
    assert "[INSERT CONTACT METHOD]" not in text
    assert "SECURITY.md" in text
    assert "@" not in text, "no personal contact address in the Code of Conduct"


def test_contributing_names_the_gates_ci_runs():
    text = _read("CONTRIBUTING.md")
    for command in ("ruff check .", "pytest", "--fail-under 4.5 --strict", "--new-findings-only"):
        assert command in text, command
    assert "synthetic" in text.lower()
    assert "CHANGELOG" in text


def test_pull_request_template_carries_the_checklist():
    text = _read(".github/PULL_REQUEST_TEMPLATE.md")
    assert "## CHANGELOG" in text
    for word in ("fail", "baseline", "schema", "privacy"):
        assert word in text.lower(), word


@pytest.mark.parametrize(
    "relative",
    ["CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "GOVERNANCE.md", ".github/PULL_REQUEST_TEMPLATE.md"],
)
def test_every_local_link_in_community_files_resolves(relative):
    path = ROOT / relative
    for target in LINK.findall(path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (path.parent / target).exists(), f"{relative} -> {target}"
