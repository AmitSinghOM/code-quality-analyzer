"""Privacy-safe baseline fingerprints and comparison behavior."""

import json

import pytest

from analyzer.baseline import (
    BASELINE_SCHEMA_VERSION,
    BaselineError,
    compare_findings,
    finding_fingerprint,
    load_baseline,
    write_baseline,
)
from analyzer.findings import Finding, Location


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
    assert load_baseline(path) == {finding_fingerprint(finding)}


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
