"""Bounded changed-line manifest and CI selection contracts."""

import json

import pytest
from click.testing import CliRunner

from analyzer.__main__ import EXIT_FINDINGS, EXIT_OK, main
from analyzer.changed_lines import (
    ChangedLinesError,
    LineRange,
    load_changed_lines,
)
from analyzer.findings import Finding, Location


def _write_manifest(path, files):
    path.write_text(
        json.dumps({"schema_version": "1.0.0", "files": files}),
        encoding="utf-8",
    )
    return path


def _file(path, *ranges):
    return {
        "path": path,
        "ranges": [
            {"start_line": start, "end_line": end}
            for start, end in ranges
        ],
    }


def _finding(
    path,
    line,
    *,
    end_line=None,
    display_path=None,
):
    return Finding(
        rule_id="PY-COR-001",
        category="correctness",
        severity="warning",
        confidence="high",
        message="Finding message.",
        location=Location(
            path=display_path or path,
            line=line,
            column=1,
            end_line=end_line,
            identity_path=path,
        ),
        remediation="Fix it.",
    )


def test_manifest_canonicalizes_paths_and_merges_adjacent_ranges(tmp_path):
    manifest = _write_manifest(tmp_path / "changed.json", [
        _file("z.py", (9, 10), (2, 4), (4, 8)),
        _file("a.py", (7, 7)),
    ])

    selection = load_changed_lines(manifest)

    assert list(selection.files) == ["a.py", "z.py"]
    assert selection.files["z.py"] == (LineRange(2, 10),)
    assert selection.file_count == 2
    assert selection.range_count == 2
    assert selection.summary(5, 1) == {
        "schema_version": "1.0.0",
        "file_count": 2,
        "range_count": 2,
        "input_findings": 5,
        "selected_findings": 1,
    }


def test_empty_manifest_selects_no_findings(tmp_path):
    selection = load_changed_lines(
        _write_manifest(tmp_path / "changed.json", [])
    )

    assert selection.select([_finding("module.py", 1)]) == ()
    assert selection.file_count == 0
    assert selection.range_count == 0


def test_selection_uses_inclusive_spans_and_hidden_identity_paths(tmp_path):
    selection = load_changed_lines(
        _write_manifest(tmp_path / "changed.json", [
            _file("a/service.py", (5, 5)),
        ])
    )
    findings = [
        _finding("a/service.py", 3, end_line=5, display_path="service.py"),
        _finding("a/service.py", 5, display_path="service.py"),
        _finding("a/service.py", 6, display_path="service.py"),
        _finding("b/service.py", 5, display_path="service.py"),
    ]

    assert selection.select(findings) == tuple(findings[:2])


def test_selection_rejects_invalid_internal_finding_span(tmp_path):
    selection = load_changed_lines(
        _write_manifest(tmp_path / "changed.json", [_file("a.py", (1, 2))])
    )

    with pytest.raises(ChangedLinesError, match="invalid source span"):
        selection.select([_finding("a.py", 2, end_line=1)])


@pytest.mark.parametrize(
    "source_path",
    [
        "",
        "/absolute.py",
        "../escape.py",
        "pkg/../escape.py",
        "pkg/./module.py",
        "pkg//module.py",
        "pkg\\module.py",
        "file:///module.py",
        "C:/module.py",
        "module.py\x00suffix",
    ],
)
def test_manifest_rejects_unsafe_paths_without_echoing_them(
    tmp_path,
    source_path,
):
    manifest = _write_manifest(
        tmp_path / "changed.json",
        [_file(source_path, (1, 1))],
    )

    with pytest.raises(ChangedLinesError) as captured:
        load_changed_lines(manifest)

    if source_path:
        assert source_path not in str(captured.value)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"schema_version": "2.0.0", "files": []},
        {"schema_version": "1.0.0", "files": {}, "extra": True},
        {"schema_version": "1.0.0", "files": [{}]},
        {
            "schema_version": "1.0.0",
            "files": [{"path": "a.py", "ranges": []}],
        },
        {
            "schema_version": "1.0.0",
            "files": [_file("a.py", (0, 1))],
        },
        {
            "schema_version": "1.0.0",
            "files": [_file("a.py", (2, 1))],
        },
        {
            "schema_version": "1.0.0",
            "files": [_file("a.py", (2_147_483_648, 2_147_483_648))],
        },
        {
            "schema_version": "1.0.0",
            "files": [{
                "path": "a.py",
                "ranges": [{"start_line": True, "end_line": 1}],
            }],
        },
    ],
)
def test_manifest_rejects_invalid_shapes_and_ranges(tmp_path, payload):
    manifest = tmp_path / "changed.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ChangedLinesError):
        load_changed_lines(manifest)


def test_manifest_rejects_duplicate_paths(tmp_path):
    manifest = _write_manifest(tmp_path / "changed.json", [
        _file("a.py", (1, 1)),
        _file("a.py", (2, 2)),
    ])

    with pytest.raises(ChangedLinesError, match="duplicate path"):
        load_changed_lines(manifest)


def test_manifest_rejects_malformed_utf8_and_nonregular_inputs(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("not-json", encoding="utf-8")
    invalid_utf8 = tmp_path / "invalid.json"
    invalid_utf8.write_bytes(b"\xff")

    for path in (malformed, invalid_utf8, tmp_path):
        with pytest.raises(ChangedLinesError):
            load_changed_lines(path)


def test_manifest_enforces_bounded_counts(tmp_path, monkeypatch):
    import analyzer.changed_lines as changed_lines

    monkeypatch.setattr(changed_lines, "MAX_FILES", 1)
    too_many_files = _write_manifest(tmp_path / "files.json", [
        _file("a.py", (1, 1)),
        _file("b.py", (1, 1)),
    ])
    with pytest.raises(ChangedLinesError, match="too many files"):
        load_changed_lines(too_many_files)

    monkeypatch.setattr(changed_lines, "MAX_FILES", 20_000)
    monkeypatch.setattr(changed_lines, "MAX_RANGES", 1)
    too_many_ranges = _write_manifest(
        tmp_path / "ranges.json",
        [_file("a.py", (1, 1), (3, 3))],
    )
    with pytest.raises(ChangedLinesError, match="too many ranges"):
        load_changed_lines(too_many_ranges)


def test_cli_filters_json_and_gate_to_changed_lines(project, tmp_path):
    root = project({
        "a.py": "def existing(items=[]):\n    return items\n",
        "b.py": "def changed(cache={}):\n    return cache\n",
    })
    manifest = _write_manifest(
        tmp_path / "private-selection.json",
        [_file("b.py", (1, 1))],
    )

    result = CliRunner().invoke(main, [
        str(root), "-f", "json", "--changed-lines-manifest", str(manifest),
        "--fail-on", "warning",
    ])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_FINDINGS
    assert [item["location"]["path"] for item in payload["findings"]] == [
        "b.py"
    ]
    assert payload["changed_lines"] == {
        "schema_version": "1.0.0",
        "file_count": 1,
        "range_count": 1,
        "input_findings": 2,
        "selected_findings": 1,
    }
    assert "private-selection.json" not in result.output


def test_empty_changed_selection_does_not_weaken_analysis_authority(
    project,
    tmp_path,
):
    root = project({
        "a.py": "def existing(items=[]):\n    return items\n",
    })
    manifest = _write_manifest(tmp_path / "changed.json", [])

    result = CliRunner().invoke(main, [
        str(root), "-f", "json", "--changed-lines-manifest", str(manifest),
        "--fail-on", "warning", "--strict",
    ])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["findings"] == []
    assert payload["analysis_health"]["authoritative"] is True
    assert payload["analysis_health"]["source_candidates"] == 1
    assert payload["changed_lines"]["input_findings"] == 1
    assert payload["changed_lines"]["selected_findings"] == 0


def test_changed_lines_intersect_new_findings_without_partial_baseline(
    project,
    tmp_path,
):
    root = project({
        "existing.py": "def existing(items=[]):\n    return items\n",
    })
    baseline = tmp_path / "baseline.json"
    initial = CliRunner().invoke(main, [
        str(root), "--write-baseline", str(baseline),
    ])
    assert initial.exit_code == EXIT_OK

    (root / "selected.py").write_text(
        "def selected(cache={}):\n    return cache\n",
        encoding="utf-8",
    )
    (root / "other.py").write_text(
        "def other(values=[]):\n    return values\n",
        encoding="utf-8",
    )
    manifest = _write_manifest(
        tmp_path / "changed.json",
        [_file("selected.py", (1, 1))],
    )
    filtered_baseline = tmp_path / "filtered-baseline.json"
    result = CliRunner().invoke(main, [
        str(root), "-f", "json", "--baseline", str(baseline),
        "--new-findings-only", "--changed-lines-manifest", str(manifest),
        "--write-baseline", str(filtered_baseline),
    ])
    payload = json.loads(result.output)

    assert result.exit_code == EXIT_OK
    assert payload["baseline"]["current_findings"] == 3
    assert payload["baseline"]["new_findings"] == 2
    assert payload["changed_lines"]["input_findings"] == 2
    assert payload["changed_lines"]["selected_findings"] == 1
    assert len(json.loads(filtered_baseline.read_text())["fingerprints"]) == 3


def test_cli_sarif_changed_selection_is_aggregate_and_deterministic(
    project,
    tmp_path,
):
    root = project({
        "private/a.py": (
            "def proprietary(secret_items=[]):\n"
            "    return secret_items\n"
        ),
        "private/b.py": "def internal(cache={}):\n    return cache\n",
    })
    first = _write_manifest(tmp_path / "first-private.json", [
        _file("private/b.py", (3, 3), (1, 1), (2, 2)),
        _file("private/a.py", (1, 1)),
    ])
    second = _write_manifest(tmp_path / "second-private.json", [
        _file("private/a.py", (1, 1)),
        _file("private/b.py", (1, 3)),
    ])

    outputs = []
    for manifest in (first, second):
        result = CliRunner().invoke(main, [
            str(root), "-f", "sarif", "--anonymize", "--offline",
            "--changed-lines-manifest", str(manifest),
        ])
        assert result.exit_code == EXIT_OK
        outputs.append(result.output)

    assert outputs[0] == outputs[1]
    payload = json.loads(outputs[0])
    properties = payload["runs"][0]["properties"]
    assert properties["changedLineSelection"] == {
        "schema_version": "1.0.0",
        "file_count": 2,
        "range_count": 2,
        "input_findings": 2,
        "selected_findings": 2,
    }
    for sensitive in (
        "private/a.py",
        "private/b.py",
        "first-private.json",
        "second-private.json",
        "proprietary",
        "secret_items",
    ):
        assert sensitive not in outputs[0]


def test_cli_changed_manifest_error_is_clean_and_generic(project, tmp_path):
    root = project({"module.py": "VALUE = 1\n"})
    manifest = tmp_path / "private-manifest-name.json"
    manifest.write_text("secret invalid content", encoding="utf-8")

    result = CliRunner().invoke(main, [
        str(root), "--changed-lines-manifest", str(manifest),
    ])

    assert result.exit_code != EXIT_OK
    assert "not readable valid UTF-8 JSON" in result.output
    assert "private-manifest-name" not in result.output
    assert "secret invalid content" not in result.output
    assert "Traceback" not in result.output


def test_text_report_shows_aggregate_changed_line_summary(project, tmp_path):
    root = project({"module.py": "def add(items=[]):\n    return items\n"})
    manifest = _write_manifest(
        tmp_path / "changed.json",
        [_file("module.py", (1, 1))],
    )

    result = CliRunner().invoke(main, [
        str(root), "--changed-lines-manifest", str(manifest),
    ])

    assert result.exit_code == EXIT_OK
    assert "Changed-Line Selection" in result.output
    assert "Canonical ranges:" in result.output
    assert "Selected findings:" in result.output
    assert "module.py" in result.output
    assert "changed.json" not in result.output


def test_changed_selection_does_not_change_written_baseline(project, tmp_path):
    root = project({
        "a.py": "def first(items=[]):\n    return items\n",
        "b.py": "def second(cache={}):\n    return cache\n",
    })
    manifest = _write_manifest(
        tmp_path / "changed.json",
        [_file("a.py", (1, 1))],
    )
    full = tmp_path / "full.json"
    selected = tmp_path / "selected.json"

    first = CliRunner().invoke(main, [
        str(root), "--write-baseline", str(full),
    ])
    second = CliRunner().invoke(main, [
        str(root), "--changed-lines-manifest", str(manifest),
        "--write-baseline", str(selected),
    ])

    assert first.exit_code == EXIT_OK
    assert second.exit_code == EXIT_OK
    assert full.read_bytes() == selected.read_bytes()


def test_manifest_enforces_file_size_limit(tmp_path, monkeypatch):
    import analyzer.changed_lines as changed_lines

    manifest = tmp_path / "changed.json"
    manifest.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(changed_lines, "MAX_MANIFEST_SIZE", 1)

    with pytest.raises(ChangedLinesError, match="5 MB safety limit"):
        load_changed_lines(manifest)


def test_manifest_rejects_duplicate_json_keys(tmp_path):
    manifest = tmp_path / "changed.json"
    manifest.write_text(
        '{"schema_version":"1.0.0","schema_version":"1.0.0","files":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ChangedLinesError, match="duplicate JSON key"):
        load_changed_lines(manifest)
