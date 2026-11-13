"""Source contracts for the PyPI publish workflow; never execute workflow commands."""

from __future__ import annotations

import re
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github/workflows/publish.yml"
RELEASE_REQUIREMENTS = ROOT / "requirements-release.txt"


def _job(workflow: str, name: str) -> str:
    match = re.search(rf"^  {name}:\n(.*?)(?=^  [\w-]+:|\Z)", workflow, re.M | re.S)
    assert match, name
    return match.group(1)


def _dispatch_input(workflow: str, name: str) -> str:
    # The inputs block sits under on.workflow_dispatch.inputs at six spaces.
    match = re.search(rf"^      {name}:\n(.*?)(?=^      [\w-]+:|^\S|^  \w)", workflow, re.M | re.S)
    assert match, name
    return match.group(1)


def _pinned_requirements(text: str) -> dict[str, list[str]]:
    """Map each `name==version` line to the `--hash=` lines that follow it."""
    pins: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            assert current, line
            pins[current].append(line.rstrip(" \\"))
            continue
        requirement = line.rstrip(" \\")
        assert "==" in requirement, requirement
        current = requirement
        pins.setdefault(current, [])
    return pins


def test_dispatch_declares_dry_run_defaulting_to_true():
    dry_run = _dispatch_input(PUBLISH.read_text(), "dry_run")
    assert "type: boolean" in dry_run
    assert "default: true" in dry_run


def test_publish_job_runs_only_for_release_events_or_explicit_non_dry_run():
    workflow = PUBLISH.read_text()
    publish = _job(workflow, "publish")
    condition = re.search(r"^    if: (.+)$", publish, re.M)
    assert condition, "publish job has no if: gate"
    assert "github.event_name == 'release'" in condition.group(1)
    assert "inputs.dry_run == false" in condition.group(1)
    # The build job stays unconditional so a dry run still proves the
    # tag/version guard, the build and twine check.
    assert not re.search(r"^    if:", _job(workflow, "build"), re.M)


def test_build_job_installs_release_tooling_with_required_hashes():
    build = _job(PUBLISH.read_text(), "build")
    assert "pip install --require-hashes -r requirements-release.txt" in build
    assert not re.search(r"pip install (build|twine)==", build)


def test_every_release_requirement_is_hash_pinned():
    pins = _pinned_requirements(RELEASE_REQUIREMENTS.read_text())
    assert {"build", "twine"} <= {name.split("==")[0] for name in pins}
    for requirement, hashes in pins.items():
        assert hashes, f"{requirement} has no --hash lines"
        assert all(h.startswith("--hash=sha256:") for h in hashes), requirement


def test_release_build_pin_matches_the_dev_extra_pin():
    with (ROOT / "pyproject.toml").open("rb") as stream:
        dev = tomllib.load(stream)["project"]["optional-dependencies"]["dev"]
    (dev_build,) = [spec for spec in dev if spec.startswith("build==")]
    pins = _pinned_requirements(RELEASE_REQUIREMENTS.read_text())
    (release_build,) = [spec for spec in pins if spec.startswith("build==")]
    assert release_build == dev_build
