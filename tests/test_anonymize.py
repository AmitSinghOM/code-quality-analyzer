"""Fully anonymized report projections."""

from cqa_analyzer.anonymize import ReportAnonymizer
from cqa_analyzer.findings import Finding, Location
from cqa_analyzer.package_intelligence import PackageIntelligence


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


# --- Path-scoped rule policy sources (ADR 005, decision 4: privacy) ---------


def test_policy_source_project_constant_is_never_transformed():
    anonymizer = ReportAnonymizer()

    assert anonymizer.policy_source("project") == "project"
    assert anonymizer._files == {}


def test_policy_source_override_glob_is_tokenized_through_the_file_map():
    anonymizer = ReportAnonymizer()

    projected = anonymizer.policy_source("override:tests/**/*_test.py")

    assert projected == "override:file-0001"
    assert anonymizer.policy_source("override:tests/**/*_test.py") == projected
    assert anonymizer.policy_source("override:vendor/**") == "override:file-0002"
    assert "tests/**" not in projected


def test_policy_source_glob_equal_to_a_real_path_shares_its_token():
    anonymizer = ReportAnonymizer()

    path_token = anonymizer.file("pkg/generated.py")

    assert anonymizer.policy_source("override:pkg/generated.py") == f"override:{path_token}"
    assert anonymizer.file("other.py") == "file-0002"


def test_policy_source_odd_shape_fails_closed_and_never_returns_raw_text():
    anonymizer = ReportAnonymizer()

    for raw in ("vendor/**", "override:", "Project", "rules:tests/**"):
        projected = anonymizer.policy_source(raw)
        assert projected != raw
        assert projected.startswith("file-"), raw
        assert "vendor" not in projected and "tests" not in projected


def test_scan_health_tokenizes_policy_dropped_sources_and_keeps_counts():
    anonymizer = ReportAnonymizer()
    health = {
        "skipped_examples": {},
        "unparsed_examples": [],
        "excluded_generated_examples": {},
        "suppressed": {"count": 1, "by_rule": {"PY-SEC-002": 1}},
        "policy_dropped": {
            "count": 7,
            "by_rule": {"PY-MAINT-003": 5, "PY-SEC-002": 2},
            "by_source": {
                "override:tests/**/*_test.py": 5,
                "override:vendor/**": 1,
                "project": 1,
            },
            "security": 2,
        },
    }

    payload = anonymizer.scan_health(health)
    dropped = payload["policy_dropped"]

    assert dropped["count"] == 7
    assert dropped["by_rule"] == {"PY-MAINT-003": 5, "PY-SEC-002": 2}
    assert dropped["security"] == 2
    assert dropped["by_source"] == {
        "override:file-0001": 5,
        "override:file-0002": 1,
        "project": 1,
    }
    assert payload["suppressed"] == {"count": 1, "by_rule": {"PY-SEC-002": 1}}
    assert "tests/**" not in str(payload) and "vendor" not in str(payload)
    # Input is not mutated.
    assert "override:vendor/**" in health["policy_dropped"]["by_source"]


def test_scan_health_source_tokens_share_the_report_file_map():
    anonymizer = ReportAnonymizer()
    # A finding already tokenized ``pkg/generated.py``; a glob equal to that
    # path must land on the same token, not mint a second one.
    anonymizer.file("pkg/generated.py")
    health = {"policy_dropped": {"count": 3, "by_rule": {}, "by_source": {
        "override:pkg/generated.py": 2,
        "project": 1,
    }, "security": 0}}

    dropped = anonymizer.scan_health(health)["policy_dropped"]

    assert dropped["by_source"] == {"override:file-0001": 2, "project": 1}
    assert sum(dropped["by_source"].values()) == dropped["count"]
    assert anonymizer.file("pkg/generated.py") == "file-0001"


def test_scan_health_without_policy_dropped_is_unchanged():
    anonymizer = ReportAnonymizer()
    health = {
        "skipped_examples": {"too_large": ["top/a.py"]},
        "unparsed_examples": [],
        "excluded_generated_examples": {},
        "suppressed": {"count": 0, "by_rule": {}},
    }

    payload = anonymizer.scan_health(health)

    assert "policy_dropped" not in payload
    assert payload["skipped_examples"] == {"too_large": ["file-0001"]}
    assert payload["suppressed"] == {"count": 0, "by_rule": {}}


def test_scan_health_leaves_a_malformed_policy_dropped_block_alone():
    anonymizer = ReportAnonymizer()
    health = {"policy_dropped": {"count": 0, "by_rule": {}, "security": 0}}

    payload = anonymizer.scan_health(health)

    assert payload["policy_dropped"] == {"count": 0, "by_rule": {}, "security": 0}
