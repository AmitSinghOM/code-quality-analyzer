"""Scanner side of ADR 005: path-scoped rule policy, the policy ledger and
``policy_source`` (decisions 1-4).

Every finding a disabled rule removes is recorded with the full ``Finding``
and the source that removed it; every emitted finding can name the policy
that set its severity. Matching always uses the hidden project-relative
identity path, never the redacted display path.
"""

import json

import pytest
from clirunner import CliRunner

from cqa_analyzer.__main__ import EXIT_FINDINGS, EXIT_OK, main
from cqa_analyzer.baseline import fingerprints_for
from cqa_analyzer.config import load_config
from cqa_analyzer.delegate import rules_for_files
from cqa_analyzer.reporters import _rule_descriptor
from cqa_analyzer.rule_metadata import builtin_rule_ids, rule_metadata
from cqa_analyzer.scanner import CodeScanner

MUTABLE_DEFAULT = "def f(cache={}):\n    return cache\n"  # PY-COR-001
UNSAFE_PICKLE = "import pickle\nx = pickle.loads(blob)\n"  # PY-SEC-001, CWE-502
GO_TLS_OFF = (  # GO-SEC-001, CWE-295
    'package p\nimport "crypto/tls"\nvar c = &tls.Config{InsecureSkipVerify: true}\n'
)
EMPTY_HEALTH = {"count": 0, "by_rule": {}, "by_source": {}, "security": 0}


def _scan(project, files: dict[str, str], toml: str | None = None, **kwargs) -> CodeScanner:
    if toml is not None:
        files = {**files, ".code-quality.toml": toml}
    root = project(files)
    scanner = CodeScanner(root, configuration=load_config(root), **kwargs)
    scanner.scan()
    return scanner


def _hits(scanner: CodeScanner, rule_id: str) -> list[tuple[str, str, str]]:
    """(identity path, severity, policy_source) for each emitted ``rule_id`` finding."""
    return sorted(
        (
            finding.location.identity_path or finding.location.path,
            finding.severity,
            scanner.policy_ledger.source_for(finding),
        )
        for finding in scanner.findings
        if finding.rule_id == rule_id
    )


def _dropped(scanner: CodeScanner) -> list[tuple[str, str, str]]:
    """(rule, identity path, source) for each ledger entry."""
    return sorted(
        (
            entry.finding.rule_id,
            entry.finding.location.identity_path or entry.finding.location.path,
            entry.source,
        )
        for entry in scanner.policy_ledger.entries
    )


# --- Recording drops (decision 4) ---------------------------------------------


def test_project_wide_disable_is_recorded_not_silently_dropped(project):
    scanner = _scan(
        project,
        {"service.py": MUTABLE_DEFAULT},
        '[rules."PY-COR-001"]\nenabled = false\n',
    )

    assert _hits(scanner, "PY-COR-001") == []
    assert _dropped(scanner) == [("PY-COR-001", "service.py", "project")]
    assert scanner.policy_ledger.health() == {
        "count": 1,
        "by_rule": {"PY-COR-001": 1},
        "by_source": {"project": 1},
        "security": 0,
    }
    # The entry keeps the whole finding, not a summary of it.
    (entry,) = scanner.policy_ledger.entries
    assert entry.finding.message and entry.finding.location.line == 1


def test_path_disable_is_counted_and_other_paths_still_report(project):
    scanner = _scan(
        project,
        {"gen/a.py": MUTABLE_DEFAULT, "src/b.py": MUTABLE_DEFAULT},
        '[overrides."gen/**"]\ndisabled = ["PY-COR-001"]\n',
    )

    assert _hits(scanner, "PY-COR-001") == [("src/b.py", "warning", "project")]
    assert _dropped(scanner) == [("PY-COR-001", "gen/a.py", "override:gen/**")]
    assert scanner.policy_ledger.health() == {
        "count": 1,
        "by_rule": {"PY-COR-001": 1},
        "by_source": {"override:gen/**": 1},
        "security": 0,
    }


def test_security_rule_disabled_by_path_is_counted_as_security(project):
    scanner = _scan(
        project,
        # Not "thirdparty/": discovery skips that name before any rule runs.
        {"vendored/x.py": UNSAFE_PICKLE, "app/x.py": UNSAFE_PICKLE},
        '[overrides."vendored/**"]\ndisabled = ["PY-SEC-001"]\n',
    )

    # Still fires outside the glob.
    assert _hits(scanner, "PY-SEC-001") == [("app/x.py", "warning", "project")]
    assert _dropped(scanner) == [("PY-SEC-001", "vendored/x.py", "override:vendored/**")]
    health = scanner.policy_ledger.health()
    assert health["by_rule"] == {"PY-SEC-001": 1}
    assert health["security"] == 1


def test_security_count_uses_the_sarif_cwe_predicate():
    """``security`` counts exactly the rules SARIF tags ``security``."""
    from cqa_analyzer.scanner import PolicyLedger

    ledger = PolicyLedger()
    for rule_id in builtin_rule_ids():
        tagged = "security" in _rule_descriptor(rule_metadata(rule_id))["properties"].get(
            "tags", []
        )
        assert ledger.is_security_rule(rule_id) is tagged, rule_id
    # A plugin rule outside the catalog has no CWE to show; it is not counted.
    assert ledger.is_security_rule("ZZ-SEC-999") is False


# --- Severity (decision 2) ----------------------------------------------------


def test_override_severity_note_stays_visible_and_error_promotes(project):
    scanner = _scan(
        project,
        {
            "legacy/a.py": MUTABLE_DEFAULT,
            "core/b.py": MUTABLE_DEFAULT,
            "other/c.py": MUTABLE_DEFAULT,
        },
        '[overrides."legacy/**"]\nseverity = { "PY-COR-001" = "note" }\n\n'
        '[overrides."core/**"]\nseverity = { "PY-COR-001" = "error" }\n',
    )

    assert _hits(scanner, "PY-COR-001") == [
        ("core/b.py", "error", "override:core/**"),
        ("legacy/a.py", "note", "override:legacy/**"),
        ("other/c.py", "warning", "project"),
    ]
    assert scanner.policy_ledger.health() == EMPTY_HEALTH


def test_cli_note_does_not_gate_error_gates_and_disabled_never_counts(project):
    root = project({"legacy/a.py": MUTABLE_DEFAULT, "gen/b.py": MUTABLE_DEFAULT})
    config = root / ".code-quality.toml"
    args = [str(root), "--offline", "--output-format", "json", "--fail-on", "warning"]

    config.write_text(
        '[overrides."legacy/**"]\nseverity = { "PY-COR-001" = "note" }\n\n'
        '[overrides."gen/**"]\ndisabled = ["PY-COR-001"]\n',
        encoding="utf-8",
    )
    demoted = CliRunner().invoke(main, args)
    payload = json.loads(demoted.output)
    assert demoted.exit_code == EXIT_OK
    assert [(f["location"]["path"], f["severity"]) for f in payload["findings"]] == [
        ("legacy/a.py", "note")
    ]
    assert payload["finding_summary"]["by_severity"] == {"note": 1}

    config.write_text(
        '[overrides."legacy/**"]\nseverity = { "PY-COR-001" = "error" }\n\n'
        '[overrides."gen/**"]\ndisabled = ["PY-COR-001"]\n',
        encoding="utf-8",
    )
    promoted = CliRunner().invoke(main, [*args[:-1], "error"])
    assert promoted.exit_code == EXIT_FINDINGS
    assert json.loads(promoted.output)["finding_summary"]["by_severity"] == {"error": 1}


# --- Precedence (decision 1) --------------------------------------------------


def test_broader_disable_cannot_be_undone_by_a_more_specific_table(project):
    scanner = _scan(
        project,
        {"src/keep/a.py": MUTABLE_DEFAULT},
        '[overrides."src/**"]\ndisabled = ["PY-COR-001"]\n\n'
        '[overrides."src/keep/**"]\nseverity = { "PY-COR-001" = "error" }\n',
    )

    assert _hits(scanner, "PY-COR-001") == []
    assert _dropped(scanner) == [("PY-COR-001", "src/keep/a.py", "override:src/**")]


def test_overlapping_tables_name_the_winning_source(project):
    scanner = _scan(
        project,
        {
            "src/gen/a.py": MUTABLE_DEFAULT,
            "src/b.py": MUTABLE_DEFAULT,
            "lib/db/x.py": MUTABLE_DEFAULT,
            "lib/y.py": MUTABLE_DEFAULT,
            "pkg/z.py": MUTABLE_DEFAULT,
        },
        # Disablers: the most specific one is the source.
        '[overrides."src/gen/**"]\ndisabled = ["PY-COR-001"]\n\n'
        '[overrides."src/**"]\ndisabled = ["PY-COR-001"]\n\n'
        # Severity: longest literal prefix wins regardless of order.
        '[overrides."lib/db/**"]\nseverity = { "PY-COR-001" = "error" }\n\n'
        '[overrides."lib/**"]\nseverity = { "PY-COR-001" = "note" }\n\n'
        # Equal prefix ("pkg/"): the later table wins.
        '[overrides."pkg/**"]\nseverity = { "PY-COR-001" = "note" }\n\n'
        '[overrides."pkg/*.py"]\nseverity = { "PY-COR-001" = "error" }\n',
    )

    assert _dropped(scanner) == [
        ("PY-COR-001", "src/b.py", "override:src/**"),
        ("PY-COR-001", "src/gen/a.py", "override:src/gen/**"),
    ]
    assert _hits(scanner, "PY-COR-001") == [
        ("lib/db/x.py", "error", "override:lib/db/**"),
        ("lib/y.py", "note", "override:lib/**"),
        ("pkg/z.py", "error", "override:pkg/*.py"),
    ]
    assert scanner.policy_ledger.health()["by_source"] == {
        "override:src/**": 1,
        "override:src/gen/**": 1,
    }


# --- Identity path, not display path ------------------------------------------


def test_redacted_display_path_is_never_matched(project):
    """``*/service.py`` matches the identity ``pkg/service.py`` but not the
    redacted display path ``service.py``; the drop proves which one was used."""
    scanner = _scan(
        project,
        {"pkg/service.py": MUTABLE_DEFAULT, "other/keep.py": MUTABLE_DEFAULT},
        '[overrides."*/service.py"]\ndisabled = ["PY-COR-001"]\n',
        redact_paths=True,
    )

    (entry,) = scanner.policy_ledger.entries
    assert entry.finding.location.path == "service.py"
    assert entry.finding.location.identity_path == "pkg/service.py"
    # Lossless: the raw glob stays internal; sinks transform it.
    assert entry.source == "override:*/service.py"
    assert [f.location.path for f in scanner.findings if f.rule_id == "PY-COR-001"] == ["keep.py"]


def test_redaction_never_changes_what_policy_decides(project):
    files = {
        "pkg/gen/a.py": MUTABLE_DEFAULT,
        "pkg/src/a.py": MUTABLE_DEFAULT,
        "pkg/db/a.py": MUTABLE_DEFAULT,
    }
    toml = (
        '[overrides."pkg/gen/**"]\ndisabled = ["PY-COR-001"]\n\n'
        '[overrides."pkg/db/**"]\nseverity = { "PY-COR-001" = "error" }\n'
    )
    plain = _scan(project, files, toml)
    redacted = _scan(project, files, toml, redact_paths=True)

    # All three display as "a.py" when redacted; policy still tells them apart.
    assert {f.location.path for f in redacted.findings if f.rule_id == "PY-COR-001"} == {"a.py"}
    assert (
        _dropped(redacted)
        == _dropped(plain)
        == [("PY-COR-001", "pkg/gen/a.py", "override:pkg/gen/**")]
    )
    assert (
        _hits(redacted, "PY-COR-001")
        == _hits(plain, "PY-COR-001")
        == [
            ("pkg/db/a.py", "error", "override:pkg/db/**"),
            ("pkg/src/a.py", "warning", "project"),
        ]
    )


# --- Compatibility and isolation ----------------------------------------------


def test_without_overrides_behaviour_and_scan_health_are_unchanged(project):
    files = {"a.py": MUTABLE_DEFAULT, "b.py": UNSAFE_PICKLE}
    plain = _scan(project, files)
    ruled = _scan(project, files, '[rules."PY-COR-001"]\nseverity = "error"\n')

    assert plain.policy_ledger.health() == EMPTY_HEALTH
    assert {plain.policy_ledger.source_for(f) for f in plain.findings} == {"project"}
    assert {ruled.policy_ledger.source_for(f) for f in ruled.findings} == {"project"}
    assert _hits(ruled, "PY-COR-001") == [("a.py", "error", "project")]
    # The report shape is integration's to change (schema 1.15.0), not the scanner's.
    assert "policy_dropped" not in plain.scan_health()
    assert "policy_dropped" not in ruled.scan_health()


def test_independent_scans_keep_independent_ledgers(project, tmp_path):
    first = _scan(
        project,
        {"gen/a.py": MUTABLE_DEFAULT},
        '[overrides."gen/**"]\ndisabled = ["PY-COR-001"]\n',
    )
    second_root = tmp_path / "second"
    second_root.mkdir()
    (second_root / "a.py").write_text(MUTABLE_DEFAULT, encoding="utf-8")
    second = CodeScanner(second_root)
    second.scan()

    assert first.policy_ledger is not second.policy_ledger
    assert first.policy_ledger.health()["count"] == 1
    assert second.policy_ledger.health() == EMPTY_HEALTH
    # A finding from one scan has no source in another scan's side table.
    (other,) = [f for f in second.findings if f.rule_id == "PY-COR-001"]
    assert first.policy_ledger.source_for(other) is None
    assert second.policy_ledger.source_for(other) == "project"


def test_ledger_unit_counts_are_deterministic():
    from cqa_analyzer.findings import Finding, Location
    from cqa_analyzer.scanner import PolicyLedger

    def finding(rule_id: str, path: str, line: int) -> Finding:
        return Finding(rule_id, "c", "warning", "high", "m", Location(path, line, 1), "r")

    ledger = PolicyLedger()
    ledger.drop(finding("PY-SEC-001", "b.py", 2), "override:b/**")
    ledger.drop(finding("PY-COR-001", "a.py", 9), "project")
    ledger.drop(finding("ZZ-FUTURE-001", "a.py", 1), "override:b/**")

    health = ledger.health()
    assert json.dumps(health) == json.dumps(
        {
            "count": 3,
            "by_rule": {"PY-COR-001": 1, "PY-SEC-001": 1, "ZZ-FUTURE-001": 1},
            "by_source": {"override:b/**": 2, "project": 1},
            "security": 1,
        }
    )
    # Report order (path, line, column, rule), as baseline ordinals expect.
    assert [(f.location.path, f.location.line) for f in ledger.dropped_findings()] == [
        ("a.py", 1),
        ("a.py", 9),
        ("b.py", 2),
    ]


def test_dropped_findings_keep_the_fingerprint_they_had_when_active(project):
    """E6 matches drops against the baseline, so the line-text identity the
    scanner stamps on active findings must be stamped on drops too."""
    # Two identical lines: baseline ordinals 0 and 1 must survive the drop.
    files = {"gen/a.py": MUTABLE_DEFAULT * 2, "src/b.py": MUTABLE_DEFAULT}
    active = _scan(project, files)
    accepted = set(fingerprints_for(active.findings))
    root = active.project_path
    (root / ".code-quality.toml").write_text(
        '[overrides."gen/**"]\ndisabled = ["PY-COR-001"]\n', encoding="utf-8"
    )
    policed = CodeScanner(root, configuration=load_config(root))
    policed.scan()

    dropped = policed.policy_ledger.dropped_findings()
    assert [f.rule_id for f in dropped] == ["PY-COR-001", "PY-COR-001"]
    assert all(f.location.context for f in dropped)
    assert set(fingerprints_for(list(dropped))) <= accepted
    assert set(fingerprints_for(policed.findings)) <= accepted


# --- Nearby selection and mixed languages -------------------------------------


def test_excluded_files_are_not_policy_drops_and_include_still_scopes(project):
    scanner = _scan(
        project,
        {
            "gen/a.py": MUTABLE_DEFAULT,
            "src/legacy/b.py": MUTABLE_DEFAULT,
            "src/c.py": MUTABLE_DEFAULT,
            "outside/d.py": MUTABLE_DEFAULT,
        },
        '[analysis]\ninclude = ["src/**", "gen/**"]\nexclude = ["gen/**"]\n\n'
        '[overrides."gen/**"]\ndisabled = ["PY-COR-001"]\n\n'
        '[overrides."src/legacy/**"]\ndisabled = ["PY-COR-001"]\n\n'
        '[overrides."outside/**"]\ndisabled = ["PY-COR-001"]\n',
    )

    # Excluded / not-included files never reach the policy: nothing to count.
    assert _dropped(scanner) == [("PY-COR-001", "src/legacy/b.py", "override:src/legacy/**")]
    assert _hits(scanner, "PY-COR-001") == [("src/c.py", "warning", "project")]


def test_mixed_language_tree_resolves_each_rule_on_its_own_path(project):
    scanner = _scan(
        project,
        {
            "svc/a.py": MUTABLE_DEFAULT,
            "svc/tls.go": GO_TLS_OFF,
            "other/tls.go": GO_TLS_OFF,
            "other/a.py": MUTABLE_DEFAULT,
        },
        '[overrides."svc/**"]\ndisabled = ["PY-COR-001", "GO-SEC-001"]\n\n'
        '[overrides."*.go"]\nseverity = { "GO-SEC-001" = "error", "PY-COR-001" = "note" }\n',
    )

    assert _dropped(scanner) == [
        ("GO-SEC-001", "svc/tls.go", "override:svc/**"),
        ("PY-COR-001", "svc/a.py", "override:svc/**"),
    ]
    assert scanner.policy_ledger.health()["security"] == 1
    assert _hits(scanner, "GO-SEC-001") == [("other/tls.go", "error", "override:*.go")]
    # A Python rule named under a Go-only glob changes nothing for .py files.
    assert _hits(scanner, "PY-COR-001") == [("other/a.py", "warning", "project")]


# --- Delegate grouping (ADR compatibility: groups split per path) -------------


def _groups(payload: dict) -> list[tuple[str, tuple[str, ...], dict[str, str]]]:
    return [
        (
            group["language"],
            tuple(group["files"]),
            {rule["rule_id"]: rule["severity"] for rule in group["rules"]},
        )
        for group in payload["groups"]
    ]


def test_delegate_groups_split_by_exact_per_path_rules(project):
    root = project(
        {
            ".code-quality.toml": (
                '[overrides."tests/**"]\ndisabled = ["PY-MAINT-003"]\n\n'
                '[overrides."db/**"]\nseverity = { "PY-COR-007" = "error" }\n'
            ),
            "tests/a.py": "x = 1\n",
            "src/b.py": "x = 1\n",
            "src/c.py": "x = 1\n",
            "db/q.py": "x = 1\n",
            "tests/main.go": "package main\n",
        }
    )
    groups = _groups(
        rules_for_files(root, ["tests/a.py", "src/b.py", "src/c.py", "db/q.py", "tests/main.go"])
    )

    by_files = {files: rules for _language, files, rules in groups}
    assert set(by_files) == {
        ("db/q.py",),
        ("src/b.py", "src/c.py"),
        ("tests/a.py",),
        ("tests/main.go",),
    }
    assert "PY-MAINT-003" not in by_files[("tests/a.py",)]
    assert by_files[("src/b.py", "src/c.py")]["PY-MAINT-003"] == "warning"
    assert by_files[("db/q.py",)]["PY-COR-007"] == "error"
    assert by_files[("src/b.py", "src/c.py")]["PY-COR-007"] != "error"
    # The Go file is grouped by its own language and untouched by Python rules.
    go = next(rules for language, _files, rules in groups if language == "go")
    assert all(rule_id.startswith("GO-") for rule_id in go)


@pytest.mark.parametrize("toml", [None, '[rules."PY-MAINT-003"]\nenabled = false\n'])
def test_delegate_without_overrides_keeps_one_group_per_language(project, toml):
    files = {"tests/a.py": "x = 1\n", "src/b.py": "x = 1\n", "main.go": "package main\n"}
    if toml is not None:
        files[".code-quality.toml"] = toml
    payload = rules_for_files(project(files), ["tests/a.py", "src/b.py", "main.go"])

    assert [(g["language"], g["files"]) for g in payload["groups"]] == [
        ("go", ["main.go"]),
        ("python", ["src/b.py", "tests/a.py"]),
    ]
    python_rules = {rule["rule_id"] for rule in payload["groups"][1]["rules"]}
    assert ("PY-MAINT-003" in python_rules) is (toml is None)
