"""First-class pre-commit hook contract without parser dependencies."""

import re
from pathlib import Path

from clirunner import CliRunner

from cqa_analyzer.__main__ import EXIT_OK, main
from cqa_analyzer.plugins import create_default_registry

ROOT = Path(__file__).parents[1]
HOOK = ROOT / ".pre-commit-hooks.yaml"
DESCRIPTION = (
    "Run privacy-first code-quality analysis locally for Python, Go, "
    "TypeScript/JavaScript, Java, Kotlin, C#, C/C++ and Rust."
)
FILES_REGEX = (
    r"(^|/)[^/]+\.(py|go|ts|tsx|js|jsx|mjs|cjs|java|kt|kts|cs|c|cc|cpp|cxx|h|hh|hpp|hxx|rs|csproj)$"
    r"|(^|/)(pyproject\.toml|go\.mod|package\.json|pom\.xml|build\.gradle|build\.gradle\.kts"
    r"|Cargo\.toml|CMakeLists\.txt)$"
    r"|^(\.code-quality\.toml|\.gitignore)$"
)
EXPECTED_HOOK = f"""- id: code-quality-analyzer
  name: code-quality-analyzer
  description: {DESCRIPTION}
  entry: code-quality-analyzer . --offline
  language: python
  types: [file]
  files: '{FILES_REGEX}'
  pass_filenames: false
  require_serial: true
"""
# Manifests every adapter reads, at any depth (workspaces nest them).
MANIFESTS = (
    "pyproject.toml",
    "go.mod",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "app.csproj",
    "Cargo.toml",
    "CMakeLists.txt",
)


def hook_pattern() -> re.Pattern:
    """Extract the ``files:`` regex from the hook manifest by text, no YAML parser."""
    for line in HOOK.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("files: '") and stripped.endswith("'"):
            return re.compile(stripped[len("files: '") : -1])
    raise AssertionError("hook manifest has no quoted files: entry")


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


def test_hook_trigger_pattern_covers_every_registered_source_extension():
    pattern = hook_pattern()
    extensions = create_default_registry().source_extensions()

    assert len(extensions) >= 21, extensions
    for extension in extensions:
        assert pattern.search(f"module{extension}"), extension
        assert pattern.search(f"src/nested/module{extension}"), extension


def test_hook_trigger_pattern_covers_manifests_and_root_policy_files():
    pattern = hook_pattern()

    for manifest in MANIFESTS:
        assert pattern.search(manifest), manifest
        assert pattern.search(f"services/api/{manifest}"), manifest
    for path in (".code-quality.toml", ".gitignore"):
        assert pattern.search(path), path

    for path in (
        "README.md",
        "docs/guide.txt",
        "pkg/.code-quality.toml",
        "pkg/.gitignore",
        "module.py.example",
        "generated.go.txt",
        "notes.rst",
        "Makefile",
    ):
        assert not pattern.search(path), path


def test_hook_description_names_every_registered_language():
    rendered = HOOK.read_text(encoding="utf-8")
    description = next(
        line for line in rendered.splitlines() if line.strip().startswith("description:")
    )
    languages = create_default_registry().capabilities()["languages"]

    assert len(languages) == 8, sorted(languages)
    for name in ("Python", "Go", "TypeScript", "Java", "Kotlin", "C#", "C/C++", "Rust"):
        assert name in description, name


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
