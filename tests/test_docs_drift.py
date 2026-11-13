"""Prose that mirrors code must track it: docs index, exit codes, pins, deps."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import cqa_analyzer
from cqa_analyzer import __main__ as cli

ROOT = Path(__file__).parents[1]
DOCS = ROOT / "docs"
LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+)(?:#[^)]*)?\)")


def _local_links(path: Path) -> list[str]:
    return [
        target
        for target in LINK.findall(path.read_text(encoding="utf-8"))
        if not target.startswith(("http://", "https://", "mailto:"))
    ]


def test_docs_index_lists_every_markdown_document_once():
    index = (DOCS / "README.md").read_text(encoding="utf-8")
    documents = sorted(
        path.relative_to(DOCS).as_posix()
        for path in DOCS.rglob("*.md")
        if path != DOCS / "README.md"
    )

    assert documents, "no docs found"
    for document in documents:
        assert index.count(f"]({document})") == 1, document


def test_every_local_link_in_the_docs_resolves():
    for path in [ROOT / "README.md", *DOCS.rglob("*.md")]:
        for target in _local_links(path):
            assert (path.parent / target).exists(), f"{path.relative_to(ROOT)} -> {target}"


def test_readme_exit_code_table_lists_every_exit_code():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Exit Codes", 1)[1].split("\n## ", 1)[0]
    documented = {int(code) for code in re.findall(r"^\| (\d+) \|", section, re.MULTILINE)}
    defined = {
        value
        for name, value in vars(cli).items()
        if name.startswith("EXIT_") and isinstance(value, int)
    }

    assert defined == set(range(7)), sorted(defined)
    assert documented == defined, sorted(documented ^ defined)


def test_stale_action_plan_lives_only_in_history():
    assert not (ROOT / "Action-Plan guide.md").exists()
    archived = DOCS / "history" / "2026-08-action-plan.md"
    assert archived.exists()
    assert archived.read_text(encoding="utf-8").startswith("> **Historical")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "Action-Plan" not in workflow


def test_maintenance_policy_matches_zero_runtime_dependencies():
    with (ROOT / "pyproject.toml").open("rb") as stream:
        assert tomllib.load(stream)["project"]["dependencies"] == []
    maintenance = (DOCS / "MAINTENANCE.md").read_text(encoding="utf-8")
    assert "zero runtime dependencies" in maintenance
    for stale in ("`click`", "`rich`", "two pinned runtime dependencies"):
        assert stale not in maintenance, stale


def test_roadmap_opening_matrix_names_every_registered_language():
    from cqa_analyzer.plugins import create_default_registry

    roadmap = (DOCS / "ROADMAP.md").read_text(encoding="utf-8")
    today = roadmap.split("## Language support today", 1)[1].split("\n## ", 1)[0]
    languages = create_default_registry().capabilities()["languages"]

    assert len(languages) == 8
    for name in ("Python", "Go", "TypeScript", "Java", "Kotlin", "C#", "C/C++", "Rust"):
        assert f"| {name}" in today, name
    assert "## Language support when this roadmap was written" in roadmap


def test_readme_pattern_catalog_totals_add_up():
    from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    dsa, design = len(DSA_PATTERNS), len(SYSTEM_DESIGN_PATTERNS)

    assert f"### DSA Patterns ({dsa} patterns)" in readme
    assert f"### System Design Patterns ({design} patterns)" in readme
    assert f"{dsa + design} patterns: {dsa} DSA + {design} system-design" in readme


def test_pre_commit_examples_pin_the_current_release_tag():
    tag = f"rev: v{cqa_analyzer.__version__}"

    assert tag in (ROOT / "README.md").read_text(encoding="utf-8")
    pre_commit = (DOCS / "PRE_COMMIT.md").read_text(encoding="utf-8")
    assert tag in pre_commit
    assert "Replace after the first signed release" not in pre_commit
