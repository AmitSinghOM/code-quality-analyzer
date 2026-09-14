# ruff: noqa: E501 - fixture dicts read better unbroken
"""Network-free tests for scripts/aacr_bench_slice.py (the pure parts)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "aacr_bench_slice", ROOT / "scripts" / "aacr_bench_slice.py"
)
slice_mod = importlib.util.module_from_spec(_SPEC)
sys.modules["aacr_bench_slice"] = slice_mod
_SPEC.loader.exec_module(slice_mod)


def _pr(comments: list[dict], language: str = "Python") -> dict:
    return {
        "githubPrUrl": "https://github.com/o/r/pull/1",
        "project_main_language": language,
        "target_commit": "a" * 40,
        "change_line_count": 10,
        "comments": comments,
    }


def _finding(rule_id: str, path: str, line: int, end_line: int | None = None) -> dict:
    return {"rule_id": rule_id, "location": {"path": path, "line": line, "end_line": end_line}}


def test_every_family_regex_maps_to_at_least_one_builtin_rule():
    from cqa_analyzer.rule_metadata import builtin_rule_ids

    for family in slice_mod.FAMILIES:
        assert any(slice_mod.family_for_rule(r) == family for r in builtin_rule_ids()), family


def test_rule_ids_map_to_exactly_one_family_and_collisions_resolve_correctly():
    from cqa_analyzer.rule_metadata import builtin_rule_ids, rule_metadata

    for rule_id in builtin_rule_ids():
        hits = [f for f, rx in slice_mod._FAMILY_RULE.items() if rx.search(rule_id)]
        assert len(hits) <= 1, (rule_id, hits)
    # Same numeric suffix, different defect across languages: must not collide.
    assert slice_mod.family_for_rule("PY-COR-002") == "empty-or-broad-catch"  # broad handler
    assert slice_mod.family_for_rule("GO-COR-002") == "sql-assembled"
    assert slice_mod.family_for_rule("GO-COR-003") == "unchecked-or-density"  # type assertion
    assert slice_mod.family_for_rule("RS-COR-003") == "blocking-in-async"
    assert slice_mod.family_for_rule("TS-COR-003") == "blocking-in-async"
    assert slice_mod.family_for_rule("C-COR-004") is None  # using-namespace has no AACR family
    # Every mapped rule's title agrees with its family's defect class.
    titles = {rule_id: rule_metadata(rule_id).title.lower() for rule_id in builtin_rule_ids()}
    for rule_id, title in titles.items():
        family = slice_mod.family_for_rule(rule_id)
        if family == "sql-assembled":
            assert "sql" in title, rule_id
        if family == "blocking-in-async":
            assert "blocking" in title or "synchronous" in title, rule_id


def test_families_for_note_is_conservative():
    assert slice_mod.families_for_note("Possible SQL injection via string concat") == [
        "sql-assembled"
    ]
    assert slice_mod.families_for_note("This exception is silently swallowed") == [
        "empty-or-broad-catch"
    ]
    assert slice_mod.families_for_note("Please rename this variable for clarity") == []


def test_select_prs_skips_unsupported_languages_and_orders_small_first():
    dataset = [
        _pr([{"note": "duplicated logic", "path": "a.py", "from_line": 1, "to_line": 1}], "PHP"),
        {
            **_pr([{"note": "duplicated logic", "path": "a.py", "from_line": 1, "to_line": 1}]),
            "change_line_count": 500,
            "githubPrUrl": "https://github.com/o/big/pull/2",
        },
        {
            **_pr([{"note": "duplicated logic", "path": "a.py", "from_line": 1, "to_line": 1}]),
            "change_line_count": 5,
            "githubPrUrl": "https://github.com/o/small/pull/3",
        },
        _pr(
            [{"note": "nice naming", "path": "a.py", "from_line": 1, "to_line": 1}]
        ),  # not in slice
    ]
    chosen = slice_mod.select_prs(dataset, None, None)
    assert [pr["githubPrUrl"] for pr in chosen] == [
        "https://github.com/o/small/pull/3",
        "https://github.com/o/big/pull/2",
    ]
    assert slice_mod.select_prs(dataset, "Python", 1)[0]["githubPrUrl"].endswith("/3")


def test_evaluate_pr_matches_by_path_family_and_slack():
    pr = _pr(
        [
            {
                "note": "sql built with f-string",
                "path": "db.py",
                "from_line": 40,
                "to_line": 42,
                "side": "right",
            },
            {
                "note": "exception swallowed",
                "path": "svc.py",
                "from_line": 10,
                "to_line": 10,
                "side": "right",
            },
            {
                "note": "exception swallowed (old code)",
                "path": "svc.py",
                "from_line": 99,
                "to_line": 99,
                "side": "left",
            },
        ]
    )
    findings = [
        _finding("PY-COR-007", "db.py", 44),  # within slack 2 of 40-42
        _finding("PY-COR-003", "svc.py", 30),  # same file, no annotation nearby -> unannotated
        _finding(
            "PY-COR-002", "svc.py", 10
        ),  # wrong family for the note? no: broad handler IS in the catch family
        _finding("PY-MAINT-003", "other.py", 1),  # file without annotations: ignored entirely
        _finding("PY-COR-007", "db.py", 90),  # far away -> unannotated
    ]
    result = slice_mod.evaluate_pr(pr, findings, slack=2)
    assert result["slice_annotations"] == 2  # left-side comment excluded
    assert result["matched_annotations"] == 2
    assert dict(result["matched_families"]) == {"sql-assembled": 1, "empty-or-broad-catch": 1}
    assert [f["rule_id"] for f in result["credited_findings"]] == ["PY-COR-007", "PY-COR-002"]
    assert [f["line"] for f in result["unannotated_findings"]] == [30, 90]

    strict = slice_mod.evaluate_pr(pr, findings, slack=0)
    assert strict["matched_annotations"] == 1  # line 44 no longer overlaps 40-42


def test_summarise_and_render_report_recall_and_precision_floor():
    result = {
        "annotation_families": {"sql-assembled": 2},
        "matched_families": {"sql-assembled": 1},
        "credited_findings": [{"family": "sql-assembled"}],
        "unannotated_findings": [{"family": "sql-assembled"}, {"family": "sql-assembled"}],
    }
    summary = slice_mod.summarise([result])
    row = summary["families"]["sql-assembled"]
    assert row["slice_recall"] == 0.5
    assert row["precision_vs_annotated"] == 1 / 3
    text = slice_mod.render_markdown(summary, [result], [{"pr": "x", "reason": "too big"}])
    assert "| sql-assembled | 2 | 1 | 50% | 1 | 2 | 33% |" in text
    assert "lower bound" in text and "too big" in text
