"""First-class pre-commit hook contract without parser dependencies."""

import re
from pathlib import Path

from click.testing import CliRunner

from analyzer.__main__ import EXIT_OK, main

ROOT = Path(__file__).parents[1]
HOOK = ROOT / ".pre-commit-hooks.yaml"
EXPECTED_HOOK = """- id: code-quality-analyzer
  name: code-quality-analyzer
  description: Run privacy-first Python and Go code-quality analysis locally.
  entry: code-quality-analyzer . --offline
  language: python
  types: [file]
  files: '(^|/)[^/]+\\.(py|go)$|^(pyproject\\.toml|go\\.mod|\\.code-quality\\.toml|\\.gitignore)$'
  pass_filenames: false
  require_serial: true
"""
HOOK_PATTERN = re.compile(
    r"(^|/)[^/]+\.(py|go)$|^"
    r"(pyproject\.toml|go\.mod|\.code-quality\.toml|\.gitignore)$"
)


def test_pre_commit_hook_manifest_is_exact_and_non_gating_by_default():
    rendered = HOOK.read_text(encoding="utf-8")

    assert rendered == EXPECTED_HOOK
    assert "entry: code-quality-analyzer . --offline" in rendered
    assert "pass_filenames: false" in rendered
    assert "require_serial: true" in rendered
    for gated_option in (
        "--baseline",
        "--changed-lines-manifest",
        "--fail-on",
        "--fail-under",
        "--new-findings-only",
        "--strict",
    ):
        assert gated_option not in rendered


def test_hook_trigger_pattern_covers_sources_and_root_policy_files():
    for path in (
        "module.py",
        "pkg/module.py",
        "cmd/main.go",
        "pyproject.toml",
        "go.mod",
        ".code-quality.toml",
        ".gitignore",
    ):
        assert HOOK_PATTERN.search(path), path

    for path in (
        "README.md",
        "docs/guide.txt",
        "pkg/pyproject.toml",
        "pkg/go.mod",
        "module.py.example",
        "generated.go.txt",
    ):
        assert not HOOK_PATTERN.search(path), path


def test_default_hook_entry_is_offline_and_advisory(project, monkeypatch):
    root = project({
        "module.py": "def existing(items=[]):\n    return items\n",
    })
    monkeypatch.chdir(root)

    result = CliRunner().invoke(main, [".", "--offline"])

    assert result.exit_code == EXIT_OK
    assert "PY-COR-001" in result.output
    assert "offline enforced=yes" in result.output


def test_source_distribution_manifest_includes_pre_commit_metadata():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "include .pre-commit-hooks.yaml\n" in manifest
