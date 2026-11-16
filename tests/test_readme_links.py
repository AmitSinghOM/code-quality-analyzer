"""README claims that must track the repository: links, the output sample, counts.

Stdlib only (plus the package under test): the README is the first thing a
newcomer reads, and a dead link, a hand-edited sample or a stale count there
costs more trust than anywhere else.
"""

from __future__ import annotations

import re
from pathlib import Path

from clirunner import CliRunner

from cqa_analyzer.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"
SAMPLE_FIXTURE = ROOT / "tests" / "fixtures" / "readme_sample"

# ](docs/...) and ](tests/...) targets, with any #fragment dropped.
REPO_LINK = re.compile(r"\]\(((?:docs|tests)/[^)#\s]+)(?:#[^)]*)?\)")


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


def test_readme_output_sample_is_the_analyzers_real_output():
    result = CliRunner().invoke(main, [str(SAMPLE_FIXTURE), "--offline"])

    assert result.exit_code == 0, result.output
    assert result.output.strip("\n") == _readme_sample_block()


def test_readme_output_sample_fits_the_first_screen():
    lines = _readme_sample_block().splitlines()

    assert 25 <= len(lines) <= 40, len(lines)
    assert "Actionable Findings" in lines
    assert any(line.startswith("PY-SEC-") for line in lines), "no security finding shown"


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


def test_architecture_module_map_matches_the_package():
    """Every module under cqa_analyzer/ is in the map; every name in the map exists."""
    page = ARCHITECTURE.read_text(encoding="utf-8")
    tree = page.split("```\n", 1)[1].split("\n```", 1)[0]
    # Names sit left of the "# ..." comment; comments mention things like C/C++.
    entries = [line.split("#", 1)[0] for line in tree.splitlines()]
    listed = set(re.findall(r"[\w.-]+\.py|[\w.-]+/", "\n".join(entries)))

    package = ROOT / "cqa_analyzer"
    actual_modules = {
        path.name for path in package.rglob("*.py") if "__pycache__" not in path.parts
    }
    actual_dirs = {
        f"{path.name}/"
        for path in package.rglob("*")
        if path.is_dir() and path.name != "__pycache__"
    }
    # deep/ is listed as a directory only; its sole module is __init__.py.
    missing = sorted((actual_modules | actual_dirs) - listed - {"__init__.py"})
    assert missing == [], missing

    # Names are resolved where the map places them: the repository root,
    # .github/, tests/, docs/, and the package tree. No whole-repo walk, so a
    # checkout with a populated .venv/ stays fast.
    bases = [ROOT, ROOT / ".github", ROOT / "tests", ROOT / "docs", package]
    bases += [path for path in package.rglob("*") if path.is_dir()]
    names_on_disk: set[str] = set()
    for base in bases:
        for path in base.iterdir():
            names_on_disk.add(f"{path.name}/" if path.is_dir() else path.name)
    stale = sorted(
        name for name in listed - {"code-quality-analyzer/"} if name not in names_on_disk
    )
    assert stale == [], stale
