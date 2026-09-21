"""Refused file reads must say why (review 6, finding B2).

Before 3.4.0 a symlinked baseline reported "not readable valid JSON" and a
symlinked configuration "could not be read safely", sending the user to
debug syntax when the real cause was the safety boundary.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cqa_analyzer.baseline import BaselineError, load_baseline
from cqa_analyzer.changed_lines import ChangedLinesError, load_changed_lines
from cqa_analyzer.config import ConfigError, load_config
from cqa_analyzer.safe_io import SafeReadError, read_failure_message

symlinks = pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")


def _link(tmp_path: Path, name: str, target: Path) -> Path:
    link = tmp_path / name
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:  # Windows without privilege
        pytest.skip(f"cannot create symlink: {error}")
    return link


@symlinks
def test_symlinked_baseline_is_named_as_a_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(
        json.dumps(
            {
                "schema_version": "2.0.0",
                "fingerprint_algorithm": "sha256",
                "fingerprints": [],
            }
        ),
        encoding="utf-8",
    )
    link = _link(tmp_path, "baseline.json", real)

    with pytest.raises(BaselineError, match="symbolic link; pass the real file"):
        load_baseline(link)


@symlinks
def test_symlinked_manifest_is_named_as_a_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"schema_version": "1.0.0", "files": []}))
    link = _link(tmp_path, "manifest.json", real)

    with pytest.raises(ChangedLinesError, match="symbolic link; pass the real file"):
        load_changed_lines(link)


@symlinks
def test_configuration_outside_the_root_is_named(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.toml"
    outside.write_text("[analyzer]\n", encoding="utf-8")
    _link(root, ".code-quality.toml", outside)

    with pytest.raises(ConfigError, match="outside the project root|symbolic link"):
        load_config(root)


def test_oversized_baseline_keeps_its_limit_message(tmp_path):
    path = tmp_path / "baseline.json"
    with path.open("wb") as stream:
        stream.truncate(5 * 1024 * 1024 + 1)

    with pytest.raises(BaselineError, match="exceeds the 5 MB safety limit"):
        load_baseline(path)


@pytest.mark.parametrize(
    ("reason", "fragment"),
    [
        ("symbolic_link", "is a symbolic link"),
        ("not_regular_file", "must be a regular file"),
        ("outside_project_root", "outside the project root"),
        ("too_large", "exceeds the 7 KiB safety limit"),
        ("undecodable", "not valid UTF-8"),
        ("file_changed", "changed while it was being read"),
        ("never_seen_reason", "could not be read safely"),
    ],
)
def test_every_reason_has_a_distinct_message(reason, fragment):
    message = read_failure_message(SafeReadError(reason), "Thing", "7 KiB")

    assert message.startswith("Thing ")
    assert fragment in message
    assert message.endswith(".")
