"""Shared test helpers."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

# Allow `import analyzer` when running pytest from the package root without
# an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def project(tmp_path):
    """Builds a throwaway project tree from ``{relative_path: source}``."""

    def _build(files: dict[str, str]) -> Path:
        root = tmp_path / "proj"
        root.mkdir(exist_ok=True)
        for rel, source in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        return root

    return _build


def function_node(source: str, name: str):
    """Return the AST node for the named function in ``source``."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found")
