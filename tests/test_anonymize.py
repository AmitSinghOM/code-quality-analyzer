"""Fully anonymized report projections."""

from analyzer.anonymize import ReportAnonymizer
from analyzer.findings import Finding, Location
from analyzer.package_intelligence import PackageIntelligence


def make_finding() -> Finding:
    return Finding(
        rule_id="PY-COR-001",
        category="correctness",
        severity="warning",
        confidence="high",
        message="Argument 'private_items' uses a mutable default.",
        location=Location(
            "private/service.py",
            4,
            18,
            identity_path="private/service.py",
        ),
        remediation="Use None for private_items.",
    )


def test_finding_projection_is_stable_and_does_not_mutate_source():
    finding = make_finding()
    anonymizer = ReportAnonymizer()

    first = anonymizer.finding(finding)
    second = anonymizer.finding(finding)

    assert first == second
    assert first["location"]["path"] == "file-0001"
    assert "private_items" not in str(first)
    assert finding.message == "Argument 'private_items' uses a mutable default."


def test_package_projection_contains_aggregates_only():
    package = PackageIntelligence(
        pyproject_present=True,
        project_name="private-project",
        dependencies=["private-dependency"],
        scripts={"private-command": "private.module:main"},
        modules=["private", "private.module"],
        import_graph={"private": ["private.module"]},
        circular_imports=[["private", "private.module"]],
    )

    payload = ReportAnonymizer().package(package)
    rendered = str(payload)

    assert payload["dependency_count"] == 1
    assert payload["module_count"] == 2
    assert payload["import_edge_count"] == 1
    assert payload["circular_import_group_count"] == 1
    for secret in (
        "private-project",
        "private-dependency",
        "private-command",
        "private.module",
    ):
        assert secret not in rendered


def test_complexity_projection_replaces_identities_and_reasoning():
    summary = {
        "total_functions": 1,
        "high_complexity_count": 1,
        "high_complexity_functions": [{
            "name": "private_algorithm",
            "file": "private/algorithm.py",
            "line": 10,
            "time": "O(n²)",
            "space": "O(1)",
            "confidence": 0.7,
            "dominant_op": "private_operation",
            "reasoning": ["Uses private_items in nested loops"],
        }],
    }

    payload = ReportAnonymizer().complexity(summary)
    rendered = str(payload)

    assert payload["high_complexity_functions"][0]["name"] == "function-0001"
    assert payload["high_complexity_functions"][0]["file"] == "file-0001"
    assert "private_algorithm" not in rendered
    assert "private/algorithm.py" not in rendered
    assert "private_items" not in rendered
    assert "private_operation" not in rendered
    assert summary["high_complexity_functions"][0]["name"] == "private_algorithm"


def test_literal_public_export_name_is_removed_from_anonymized_finding():
    finding = Finding(
        rule_id="PY-PKG-004",
        category="package-health",
        severity="error",
        confidence="high",
        message=(
            "Literal __all__ export 'private_export' has no module-level "
            "binding."
        ),
        location=Location(
            "private/api.py",
            2,
            5,
            identity_path="private/api.py",
        ),
        remediation="Define or import private_export.",
    )

    payload = ReportAnonymizer().finding(finding)

    assert payload["message"] == "Finding reported by PY-PKG-004."
    assert "private_export" not in str(payload)


def test_package_data_names_are_removed_from_anonymized_finding():
    finding = Finding(
        rule_id="PY-PKG-006",
        category="package-health",
        severity="warning",
        confidence="high",
        message=(
            "Static package-data declaration for 'private_package' names "
            "missing source file 'private/schema.json'."
        ),
        location=Location("pyproject.toml", 1, 1),
        remediation="Add private/schema.json.",
    )

    payload = ReportAnonymizer().finding(finding)

    assert payload["message"] == "Finding reported by PY-PKG-006."
    assert "private_package" not in str(payload)
    assert "private/schema.json" not in str(payload)
