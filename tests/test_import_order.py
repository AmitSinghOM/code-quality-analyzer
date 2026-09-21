"""Every module must be importable first, in a fresh interpreter.

Circular imports in this package are order-dependent: ``python_rules ->
python_security -> languages.* -> languages/__init__ -> languages.python ->
python_rules`` raised ``ImportError`` only when ``python_rules`` was the first
module imported. The full test run never noticed for two releases because an
earlier test module initialised ``languages`` first. Importing each module in
its own subprocess removes that shelter, so any such cycle fails here
regardless of which test runs first.
"""

import pkgutil
import subprocess
import sys
from pathlib import Path

import pytest

import cqa_analyzer

PACKAGE_ROOT = Path(cqa_analyzer.__file__).parent


def _all_modules() -> list[str]:
    names = []
    for info in pkgutil.walk_packages([str(PACKAGE_ROOT)], prefix="cqa_analyzer."):
        if info.name.endswith("__main__"):
            continue
        names.append(info.name)
    return sorted(names)


MODULES = _all_modules()


def test_module_inventory_is_non_trivial():
    assert "cqa_analyzer.python_rules" in MODULES
    assert "cqa_analyzer.languages.python" in MODULES
    assert len(MODULES) > 20


@pytest.mark.parametrize("module", MODULES)
def test_module_imports_cleanly_as_first_import(module):
    # Module names come from pkgutil over this package, not from any input.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-P", "-c", f"import {module}"],
        capture_output=True,
        text=True,
        cwd=str(PACKAGE_ROOT.parent),
        timeout=60,
    )
    assert proc.returncode == 0, f"{module} failed as first import:\n{proc.stderr[-1500:]}"
