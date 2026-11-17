"""Privacy-safe baseline fingerprints and comparison behavior."""

import json
from dataclasses import replace

import pytest

from cqa_analyzer.baseline import (
    BASELINE_SCHEMA_VERSION,
    LEGACY_BASELINE_SCHEMA_VERSION,
    Baseline,
    BaselineComparison,
    BaselineError,
    compare_findings,
    finding_fingerprint,
    finding_fingerprint_v1,
    fingerprints_for,
    load_baseline,
    write_baseline,
)
from cqa_analyzer.findings import Finding, Location


def make_finding(
    path: str = "pkg/service.py",
    *,
    identity_path: str | None = None,
) -> Finding:
    return Finding(
        rule_id="PY-COR-001",
        category="correctness",
        severity="warning",
        confidence="high",
        message="Argument 'items' uses a mutable list default.",
        location=Location(
            path=path,
            line=4,
            column=20,
            identity_path=identity_path,
        ),
        remediation="Use None and create a new list inside the function.",
    )


def test_baseline_contains_only_hashed_fingerprints(tmp_path):
    path = tmp_path / "baseline.json"
    finding = make_finding()

    write_baseline(path, [finding])
    content = path.read_text(encoding="utf-8")
    payload = json.loads(content)

    assert payload["schema_version"] == BASELINE_SCHEMA_VERSION
    assert payload["fingerprint_algorithm"] == "sha256"
    assert payload["fingerprints"] == [finding_fingerprint(finding)]
    assert "pkg/service.py" not in content
    assert "mutable list" not in content
    assert load_baseline(path).fingerprints == {finding_fingerprint(finding)}


def test_identity_path_keeps_redacted_fingerprint_stable():
    full = make_finding(identity_path="pkg/service.py")
    redacted = make_finding("service.py", identity_path="pkg/service.py")

    assert finding_fingerprint(full) == finding_fingerprint(redacted)
    assert redacted.as_dict()["location"]["path"] == "service.py"
    assert "identity_path" not in redacted.as_dict()["location"]


def test_comparison_returns_only_unknown_findings():
    known = make_finding()
    new = Finding(
        rule_id="PY-PKG-001",
        category="package-health",
        severity="warning",
        confidence="high",
        message="Circular import group detected: pkg.a, pkg.b.",
        location=Location("pkg/a.py", 1, 1),
        remediation="Invert one dependency.",
    )

    comparison = compare_findings(
        [known, new],
        {finding_fingerprint(known)},
    )

    assert comparison.loaded is True
    assert comparison.known_count == 1
    assert comparison.current_count == 2
    assert comparison.new_findings == (new,)
    assert comparison.as_dict()["new_findings"] == 1


def test_invalid_baseline_is_rejected(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps({"schema_version": "99", "fingerprints": []}),
        encoding="utf-8",
    )

    with pytest.raises(BaselineError, match="Unsupported baseline schema"):
        load_baseline(path)


def test_write_rejects_missing_parent_directory(tmp_path):
    path = tmp_path / "missing" / "baseline.json"

    with pytest.raises(BaselineError, match="parent directory"):
        write_baseline(path, [make_finding()])


# ---- ADR 005, decision 5: unmatched baseline entries and matched sets (E6) ----
# A baseline entry whose finding is now hidden by a directive or a path policy
# must never read as fixed. The comparison fingerprints the active, suppressed
# and policy-dropped findings separately and reports how many baseline entries
# each set matched, plus the prune candidates nothing matched.

_SIX_KEYS = (
    "schema_version",
    "loaded",
    "written",
    "known_fingerprints",
    "current_findings",
    "new_findings",
)


def _ctx_finding(rule_id: str, path: str, line: int, context: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="security",
        severity="warning",
        confidence="high",
        message="msg",
        location=Location(path=path, line=line, column=5, context=context),
        remediation="fix",
    )


def _three() -> tuple[Finding, Finding, Finding]:
    fixed = _ctx_finding("PY-SEC-002", "src/a.py", 4, "run(cmd, shell=True)")
    suppressed = _ctx_finding("PY-COR-003", "src/b.py", 9, "except Exception: pass")
    dropped = _ctx_finding("PY-MAINT-003", "tests/test_x.py", 1, "def test_long(): ...")
    return fixed, suppressed, dropped


def _record(findings, schema_version: str) -> Baseline:
    return Baseline(frozenset(fingerprints_for(list(findings), schema_version)), schema_version)


@pytest.mark.parametrize(
    "schema_version", [BASELINE_SCHEMA_VERSION, LEGACY_BASELINE_SCHEMA_VERSION]
)
def test_unmatched_count_tells_fixed_from_hidden(schema_version):
    """ADR 005 test plan 5: fix one, suppress one, policy-drop one."""
    fixed, suppressed, dropped = _three()
    baseline = _record((fixed, suppressed, dropped), schema_version)

    comparison = compare_findings(
        [],
        baseline,
        suppressed=[suppressed],
        policy_dropped=[dropped],
    )

    assert comparison.schema_version == schema_version
    assert comparison.known_count == 3
    assert comparison.current_count == 0
    assert comparison.new_findings == ()
    assert comparison.unmatched_count == 1
    assert (
        comparison.matched_active,
        comparison.matched_suppressed,
        comparison.matched_policy_dropped,
    ) == (0, 1, 1)
    payload = comparison.as_dict()
    assert list(payload) == [*_SIX_KEYS, "unmatched_count", "matched"]
    assert payload["unmatched_count"] == 1
    assert payload["matched"] == {"active": 0, "suppressed": 1, "policy_dropped": 1}
    assert list(payload["matched"]) == ["active", "suppressed", "policy_dropped"]


def test_defaults_keep_existing_keys_and_read_unmatched_as_known_minus_active():
    """Every existing caller passes no ledgers: the six keys are unchanged and
    the new keys fall back to the plain set difference."""
    fixed, suppressed, dropped = _three()
    baseline = _record((fixed, suppressed, dropped), BASELINE_SCHEMA_VERSION)

    comparison = compare_findings([suppressed], baseline)

    payload = comparison.as_dict()
    assert {key: payload[key] for key in _SIX_KEYS} == {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "loaded": True,
        "written": False,
        "known_fingerprints": 3,
        "current_findings": 1,
        "new_findings": 0,
    }
    assert payload["unmatched_count"] == 2
    assert payload["matched"] == {"active": 1, "suppressed": 0, "policy_dropped": 0}


def test_comparison_positional_construction_still_works():
    comparison = BaselineComparison(True, 2, 1, ())

    assert comparison.unmatched_count == 0
    assert (
        comparison.matched_active,
        comparison.matched_suppressed,
        comparison.matched_policy_dropped,
    ) == (0, 0, 0)


def test_no_baseline_reports_zero_unmatched_and_zero_matched():
    fixed, suppressed, dropped = _three()

    comparison = compare_findings(
        [fixed],
        None,
        suppressed=[suppressed],
        policy_dropped=[dropped],
    )

    assert comparison.loaded is False
    assert comparison.known_count == 0
    assert comparison.unmatched_count == 0
    assert comparison.as_dict()["matched"] == {"active": 0, "suppressed": 0, "policy_dropped": 0}


def test_policy_dropped_twins_keep_the_ordinals_they_had_when_active():
    """A path policy drops a whole (rule, path), so two identical offending
    lines leave together and must match both baseline entries (ordinals 0 and
    1), not collapse onto ordinal 0 and leave one entry unmatched."""
    twin_a = _ctx_finding("PY-MAINT-003", "tests/test_x.py", 3, "x()")
    twin_b = _ctx_finding("PY-MAINT-003", "tests/test_x.py", 30, "x()")
    baseline = _record((twin_a, twin_b), BASELINE_SCHEMA_VERSION)

    comparison = compare_findings([], baseline, policy_dropped=[twin_a, twin_b])

    assert comparison.unmatched_count == 0
    assert comparison.matched_policy_dropped == 2
    # Negative: dropping only one twin leaves the other entry a prune candidate.
    partial = compare_findings([], baseline, policy_dropped=[twin_a])
    assert partial.unmatched_count == 1
    assert partial.matched_policy_dropped == 1


def test_severity_override_does_not_change_identity():
    """A path override that demotes a finding to ``note`` keeps its fingerprint:
    severity is not hashed, so nothing becomes unmatched."""
    fixed, suppressed, dropped = _three()
    baseline = _record((fixed, suppressed, dropped), BASELINE_SCHEMA_VERSION)
    demoted = [replace(item, severity="note") for item in (fixed, suppressed, dropped)]

    comparison = compare_findings(demoted, baseline)

    assert comparison.new_findings == ()
    assert comparison.unmatched_count == 0
    assert comparison.matched_active == 3


def test_a_finding_in_both_active_and_a_ledger_counts_once_as_active():
    fixed, suppressed, dropped = _three()
    baseline = _record((fixed, suppressed, dropped), BASELINE_SCHEMA_VERSION)

    comparison = compare_findings(
        [fixed, suppressed, dropped],
        baseline,
        suppressed=[suppressed],
        policy_dropped=[dropped, fixed],
    )

    assert comparison.unmatched_count == 0
    assert comparison.as_dict()["matched"] == {"active": 3, "suppressed": 0, "policy_dropped": 0}
    # Negative: a finding named in both ledgers counts once, as suppressed.
    both = compare_findings([], baseline, suppressed=[dropped], policy_dropped=[dropped])
    assert both.as_dict()["matched"] == {"active": 0, "suppressed": 1, "policy_dropped": 0}
    assert both.unmatched_count == 2


def test_ledger_findings_unknown_to_the_baseline_are_not_counted():
    """A suppressed or dropped finding the baseline never held matches nothing
    and is not new: ``new_findings`` stays about active findings only."""
    fixed, suppressed, dropped = _three()
    baseline = _record((fixed,), BASELINE_SCHEMA_VERSION)

    comparison = compare_findings(
        [fixed],
        baseline,
        suppressed=[suppressed],
        policy_dropped=[dropped],
    )

    assert comparison.new_findings == ()
    assert comparison.unmatched_count == 0
    assert comparison.as_dict()["matched"] == {"active": 1, "suppressed": 0, "policy_dropped": 0}


def test_legacy_schema_hashes_ledgers_with_the_file_s_own_algorithm():
    fixed, suppressed, dropped = _three()
    legacy = Baseline(
        frozenset(finding_fingerprint_v1(item) for item in (suppressed, dropped)),
        LEGACY_BASELINE_SCHEMA_VERSION,
    )

    comparison = compare_findings([], legacy, suppressed=[suppressed], policy_dropped=[dropped])

    assert comparison.unmatched_count == 0
    assert comparison.as_dict()["matched"] == {"active": 0, "suppressed": 1, "policy_dropped": 1}
    # Negative: the same ledgers against 2.0.0 hashes of a 1.0.0 file match nothing.
    mismatched = Baseline(legacy.fingerprints, BASELINE_SCHEMA_VERSION)
    assert compare_findings([], mismatched, suppressed=[suppressed]).unmatched_count == 2


def test_written_baseline_keeps_schema_2_and_exactly_three_keys(tmp_path):
    """The file format is unchanged by E6: no configuration fingerprint, no
    ledger counts, nothing but schema, algorithm and hashes."""
    path = tmp_path / "baseline.json"
    fixed, suppressed, dropped = _three()

    write_baseline(path, [fixed, suppressed, dropped])
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "2.0.0"
    assert list(payload) == ["schema_version", "fingerprint_algorithm", "fingerprints"]
    assert len(payload["fingerprints"]) == 3
