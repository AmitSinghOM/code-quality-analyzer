"""README claims that must track the repository: links, the output sample, counts.

Stdlib only (plus the package under test): the README is the first thing a
newcomer reads, and a dead link, a hand-edited sample or a stale count there
costs more trust than anywhere else.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from clirunner import CliRunner

from cqa_analyzer.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"
SAMPLE_FIXTURE = ROOT / "tests" / "fixtures" / "readme_sample"
SAMPLE_SUFFIX = ".sample"

# ](docs/...) and ](tests/...) targets, with any #fragment dropped.
REPO_LINK = re.compile(r"\]\(((?:docs|tests)/[^)#\s]+)(?:#[^)]*)?\)")
# File and directory names in the ARCHITECTURE.md tree, left of the comment.
TREE_NAME = re.compile(r"[\w.-]+\.py|[\w.-]+/")


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def test_every_docs_and_tests_link_in_the_readme_resolves():
    targets = REPO_LINK.findall(_readme())

    assert targets, "README links no docs/ or tests/ path at all"
    missing = sorted({target for target in targets if not (ROOT / target).exists()})
    assert missing == [], missing


def _readme_sample_block() -> str:
    """The fenced block that starts with the analyzer's first output line."""
    text = _readme()
    start = text.index("```text\nAnalyzing: readme_sample\n") + len("```text\n")
    end = text.index("\n```", start)
    return text[start:end]


def materialize_sample(parent: Path) -> Path:
    """Copy the fixture into ``parent/readme_sample`` with the ``.sample`` suffix removed.

    The sources are stored with a non-source suffix so the repository's own
    analyzer gate and ruff never read them; the analyzer runs on this copy.
    """
    root = parent / "readme_sample"
    for source in sorted(SAMPLE_FIXTURE.rglob(f"*{SAMPLE_SUFFIX}")):
        target = root / source.relative_to(SAMPLE_FIXTURE).with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return root


def test_readme_output_sample_is_the_analyzers_real_output(tmp_path):
    project = materialize_sample(tmp_path)
    assert sorted(p.name for p in project.rglob("*.py")) == ["__init__.py", "cache.py", "sync.py"]

    result = CliRunner().invoke(main, [str(project), "--offline"])

    assert result.exit_code == 0, result.output
    assert result.output.strip("\n") == _readme_sample_block()


def test_readme_output_sample_fits_the_first_screen():
    lines = _readme_sample_block().splitlines()

    assert 25 <= len(lines) <= 40, len(lines)
    assert "Actionable Findings" in lines
    assert any(line.startswith("PY-SEC-") for line in lines), "no security finding shown"


def test_sample_fixture_holds_no_source_the_repository_gate_would_read():
    """A real .py here would be a new finding or a strict coverage gap in CI."""
    stray = sorted(
        path.relative_to(SAMPLE_FIXTURE).as_posix()
        for path in SAMPLE_FIXTURE.rglob("*")
        if path.is_file() and path.suffix not in {SAMPLE_SUFFIX, ".md"}
    )
    assert stray == [], stray


def test_readme_first_screen_counts_match_the_code():
    from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
    from cqa_analyzer.plugins import create_default_registry
    from cqa_analyzer.rule_metadata import builtin_rule_ids

    rules = len(builtin_rule_ids())
    patterns = len(DSA_PATTERNS) + len(SYSTEM_DESIGN_PATTERNS)
    languages = len(create_default_registry().capabilities()["languages"])

    assert languages == 8
    assert re.search(
        rf"{rules} rules and {patterns} architecture patterns across eight\s+languages", _readme()
    ), (rules, patterns)


def test_readme_no_longer_carries_the_project_tree():
    text = _readme()

    assert "## Project Structure" not in text
    assert "](docs/ARCHITECTURE.md)" in text


def _names_in_architecture_map() -> set[str]:
    page = ARCHITECTURE.read_text(encoding="utf-8")
    tree = page.split("```\n", 1)[1].split("\n```", 1)[0]
    # Comments mention things like C/C++ and TypeScript/JavaScript.
    entries = "\n".join(line.split("#", 1)[0] for line in tree.splitlines())
    return set(TREE_NAME.findall(entries)) - {"code-quality-analyzer/"}


def _package_entries() -> set[str]:
    package = ROOT / "cqa_analyzer"
    entries = set()
    for path in package.rglob("*"):
        if "__pycache__" in path.parts:
            continue
        if path.is_dir():
            entries.add(f"{path.name}/")
        elif path.suffix == ".py" and path.name != "__init__.py":
            entries.add(path.name)
    return entries


def _names_on_disk() -> set[str]:
    """Names where the map places them: root, .github/, tests/, docs/, the package tree.

    No whole-repository walk, so a checkout with a populated .venv/ stays fast.
    """
    package = ROOT / "cqa_analyzer"
    bases = [ROOT, ROOT / ".github", ROOT / "tests", ROOT / "docs", package]
    bases += [path for path in package.rglob("*") if path.is_dir()]
    names = set()
    for base in bases:
        for path in base.iterdir():
            names.add(f"{path.name}/" if path.is_dir() else path.name)
    return names


def test_architecture_module_map_matches_the_package():
    """Every module under cqa_analyzer/ is in the map; every name in the map exists."""
    listed = _names_in_architecture_map()

    # deep/ is listed as a directory only; its sole module is __init__.py.
    missing = sorted(_package_entries() - listed)
    assert missing == [], missing

    stale = sorted(listed - _names_on_disk())
    assert stale == [], stale
