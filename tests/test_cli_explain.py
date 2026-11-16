"""E5: ``--explain RULE_ID`` and ``--list-rules [--language XX]`` on the CLI.

Both flags answer from rule metadata without a project, exit 0, and never
touch the filesystem. ``PROJECT_PATH`` becomes optional in argparse but stays
required for an analysis (exit 2 with argparse's own wording).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from clirunner import CliRunner

from cqa_analyzer import __version__
from cqa_analyzer.__main__ import main
from cqa_analyzer.plugins import create_default_registry
from cqa_analyzer.rule_catalog import github_anchor, help_url, language_codes
from cqa_analyzer.rule_metadata import builtin_rule_ids, rule_metadata

ROOT = Path(__file__).resolve().parents[1]
RULES_URL = f"https://github.com/AmitSinghOM/code-quality-analyzer/blob/v{__version__}/docs/RULES.md"
LIST_LINE = re.compile(
    r"^(?P<id>[A-Z]+-[A-Z]+-\d{3}) +(?P<severity>warning|error) +(?P<title>\S.*)$"
)


def _invoke(*args: str):
    return CliRunner().invoke(main, list(args))


# --- --explain ---------------------------------------------------------------------


def test_explain_prints_every_metadata_field_and_exits_0():
    result = _invoke("--explain", "PY-COR-001")
    meta = rule_metadata("PY-COR-001")
    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    out = result.stdout
    assert out.startswith(f"PY-COR-001: {meta.title}\n")
    for label, value in (
        ("language", meta.language),
        ("family", meta.category),
        ("severity", meta.default_severity),
        ("confidence", meta.confidence),
    ):
        assert re.search(rf"^  {label}: +{re.escape(value)}$", out, re.M), label
    assert meta.description in out
    assert meta.remediation in out
    assert meta.not_when, "fixture rule must carry not_when to prove it is printed"
    for condition in meta.not_when:
        assert f"    - {condition}" in out
    assert f"  Docs: {RULES_URL}#py-cor-001-mutable-default-argument" in out


def test_explain_shows_cwe_for_security_rules_and_omits_it_otherwise():
    secure = _invoke("--explain", "PY-SEC-001")
    assert secure.exit_code == 0
    assert rule_metadata("PY-SEC-001").cwe
    assert re.search(r"^  cwe: +CWE-\d+", secure.stdout, re.M)
    plain = _invoke("--explain", "PY-COR-001")
    assert not rule_metadata("PY-COR-001").cwe
    assert "cwe:" not in plain.stdout


def test_explain_accepts_lowercase_ids():
    result = _invoke("--explain", "py-cor-001")
    assert result.exit_code == 0
    assert result.stdout.startswith("PY-COR-001: ")


def test_explain_keeps_bracketed_text_literal():
    """``[deep]`` in metadata must not be eaten as a style tag by the renderer."""
    meta = rule_metadata("GO-MAINT-001")
    assert "[deep]" in meta.description
    result = _invoke("--explain", "GO-MAINT-001")
    assert result.exit_code == 0
    assert "[deep]" in result.stdout


def test_explain_unknown_id_exits_2_with_close_matches():
    result = _invoke("--explain", "PY-COR-99")
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "unknown rule id 'PY-COR-99'" in result.stderr
    assert "PY-COR-007" in result.stderr  # difflib's nearest neighbour


def test_explain_unknown_id_without_a_near_match_points_at_list_rules():
    result = _invoke("--explain", "FOO")
    assert result.exit_code == 2
    assert "unknown rule id 'FOO'" in result.stderr
    assert "--list-rules" in result.stderr


# --- --list-rules ------------------------------------------------------------------


def test_list_rules_prints_one_line_per_catalog_rule_in_lexical_order():
    result = _invoke("--list-rules")
    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert len(lines) == len(builtin_rule_ids()) == 95
    ids = []
    for line in lines:
        match = LIST_LINE.match(line)
        assert match, line
        meta = rule_metadata(match["id"])
        assert match["severity"] == meta.default_severity
        assert match["title"] == meta.title
        ids.append(match["id"])
    assert ids == list(builtin_rule_ids())


def test_list_rules_language_filter_keeps_only_that_language():
    result = _invoke("--list-rules", "--language", "rust")
    assert result.exit_code == 0, result.output
    listed = [LIST_LINE.match(line)["id"] for line in result.stdout.splitlines()]
    expected = [rid for rid in builtin_rule_ids() if rule_metadata(rid).language == "rust"]
    assert listed == expected
    assert listed and all(rid.startswith("RS-") for rid in listed)


def test_language_codes_come_from_the_adapter_registry():
    registry_ids = tuple(create_default_registry().capabilities()["languages"])
    assert language_codes() == registry_ids
    assert set(registry_ids) >= {rule_metadata(rid).language for rid in builtin_rule_ids()}


def test_list_rules_unknown_language_exits_2_and_names_the_codes():
    result = _invoke("--list-rules", "--language", "ruby")
    assert result.exit_code == 2
    assert "unknown language 'ruby'" in result.stderr
    for code in language_codes():
        assert code in result.stderr


def test_every_listed_rule_is_explainable():
    listed = _invoke("--list-rules").stdout.splitlines()
    assert listed
    for line in listed:
        rule_id = LIST_LINE.match(line)["id"]
        result = _invoke("--explain", rule_id)
        assert result.exit_code == 0, (rule_id, result.output)
        assert result.stdout.startswith(f"{rule_id}: ")
        assert f"{RULES_URL}#" in result.stdout


# --- PROJECT_PATH stays required for an analysis ----------------------------------


def test_project_path_is_still_required_without_a_catalog_flag():
    result = _invoke()
    assert result.exit_code == 2
    assert "the following arguments are required: PROJECT_PATH" in result.stderr


def test_catalog_flags_reject_a_project_path(tmp_path: Path):
    for flags in (("--explain", "PY-COR-001"), ("--list-rules",)):
        result = _invoke(str(tmp_path), *flags)
        assert result.exit_code == 2, flags
        assert "PROJECT_PATH is not used with --explain or --list-rules" in result.stderr


def test_explain_and_list_rules_are_mutually_exclusive():
    result = _invoke("--explain", "PY-COR-001", "--list-rules")
    assert result.exit_code == 2
    assert "mutually exclusive" in result.stderr


def test_language_without_list_rules_is_a_usage_error(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = _invoke(str(tmp_path), "--language", "python")
    assert result.exit_code == 2
    assert "--language requires --list-rules" in result.stderr


# --- documentation link -----------------------------------------------------------


@pytest.mark.parametrize(
    ("heading", "anchor"),
    [
        ("PY-COR-001: Mutable default argument", "py-cor-001-mutable-default-argument"),
        ("C-COR-004: `using namespace` in a header", "c-cor-004-using-namespace-in-a-header"),
        (
            "RS-COR-001: `unwrap()` density outside test code",
            "rs-cor-001-unwrap-density-outside-test-code",
        ),
    ],
)
def test_github_anchor_matches_githubs_heading_slug(heading: str, anchor: str):
    assert github_anchor(heading) == anchor


def test_help_url_is_pinned_to_this_version_and_lands_on_a_real_heading():
    url = help_url("PY-COR-001")
    assert url == f"{RULES_URL}#py-cor-001-mutable-default-argument"
    headings = re.findall(r"^#+ (.+)$", (ROOT / "docs" / "RULES.md").read_text(), re.M)
    assert "py-cor-001-mutable-default-argument" in {github_anchor(h) for h in headings}
