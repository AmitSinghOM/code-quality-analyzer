"""Language-neutral plugin contracts and built-in Python registration."""

from pathlib import Path

import pytest

from analyzer.findings import Finding, Location
from analyzer.plugins import create_default_registry
from analyzer.protocols import ParsedFile, SourceFile
from analyzer.registry import PluginRegistrationError, PluginRegistry
from analyzer.scanner import CodeScanner


class StubAdapter:
    language_id = "stub"
    adapter_version = "1.0.0"
    extensions = ("stub",)

    def parse(self, source: SourceFile) -> ParsedFile:
        return ParsedFile(source, object(), {"length": 1}, 1, True)


class StubRulePack:
    rule_pack_id = "stub-rules"
    language_id = "stub"
    ruleset_version = "1.0.0"

    def evaluate(self, parsed: ParsedFile):
        yield Finding(
            rule_id="STUB-001",
            category="test",
            severity="warning",
            confidence="high",
            message="Stub finding.",
            location=Location(parsed.source.display_path, 1, 1),
            remediation="Use the fixture remediation.",
        )


class StubMetricProvider:
    provider_id = "stub-metrics"
    language_id = "stub"

    def measure(self, parsed: ParsedFile):
        return {"lines": parsed.line_count}


class StubReporter:
    format_name = "stub"

    def render(self, report: object) -> bytes:
        return str(report).encode()


def source_file(suffix: str = ".stub") -> SourceFile:
    return SourceFile(
        path=Path(f"sample{suffix}"),
        display_path=f"sample{suffix}",
        identity_path=f"sample{suffix}",
        content="value\n",
    )


def test_minimal_plugins_register_and_share_normalized_models():
    registry = PluginRegistry()
    adapter = StubAdapter()
    rule_pack = StubRulePack()
    metric = StubMetricProvider()
    reporter = StubReporter()

    registry.register_language(adapter)
    registry.register_rule_pack(rule_pack)
    registry.register_metric_provider(metric)
    registry.register_reporter(reporter)

    resolved = registry.adapter_for_path("example.STUB")
    parsed = resolved.parse(source_file())
    findings = list(registry.rule_packs_for("stub")[0].evaluate(parsed))
    measurements = registry.metric_providers_for("stub")[0].measure(parsed)

    assert resolved is adapter
    assert findings[0].rule_id == "STUB-001"
    assert measurements == {"lines": 1}
    assert registry.reporter("stub").render(findings) == str(findings).encode()
    assert registry.capabilities() == {
        "languages": {"stub": "1.0.0"},
        "rule_packs": [{
            "language_id": "stub",
            "rule_pack_id": "stub-rules",
            "ruleset_version": "1.0.0",
        }],
        "metric_providers": [{
            "language_id": "stub",
            "provider_id": "stub-metrics",
        }],
        "project_providers": [],
        "reporters": ["stub"],
    }


def test_registry_rejects_language_and_extension_conflicts():
    registry = PluginRegistry()
    registry.register_language(StubAdapter())

    with pytest.raises(PluginRegistrationError, match="already registered"):
        registry.register_language(StubAdapter())

    class ConflictingAdapter(StubAdapter):
        language_id = "other"

    with pytest.raises(PluginRegistrationError, match="already belongs"):
        registry.register_language(ConflictingAdapter())


def test_builtin_python_adapter_preserves_findings_and_parse_health():
    registry = create_default_registry()
    adapter = registry.adapter_for_path("service.py")
    source = SourceFile(
        path=Path("service.py"),
        display_path="service.py",
        identity_path="pkg/service.py",
        content="def add(items=[]):\n    return items\n",
    )

    parsed = adapter.parse(source)
    findings = [
        finding
        for rule_pack in registry.rule_packs_for("python")
        for finding in rule_pack.evaluate(parsed)
    ]

    assert adapter.language_id == "python"
    assert adapter.adapter_version == "1.0.0"
    assert parsed.complete is True
    assert parsed.line_count == 2
    assert findings[0].rule_id == "PY-COR-001"
    assert findings[0].location.path == "service.py"
    assert findings[0].location.identity_path == "pkg/service.py"


def test_builtin_python_adapter_marks_malformed_source_incomplete():
    registry = create_default_registry()
    parsed = registry.language("python").parse(
        SourceFile(
            path=Path("broken.py"),
            display_path="broken.py",
            identity_path="broken.py",
            content="def broken(:\n",
        )
    )

    assert parsed.complete is False
    assert list(registry.rule_packs_for("python")[0].evaluate(parsed)) == []


def test_scanner_discovers_registered_extension_without_branching(
    project,
):
    root = project({"src/example.stub": "value\n", "ignored.txt": "value\n"})
    registry = PluginRegistry()
    registry.register_language(StubAdapter())
    registry.register_rule_pack(StubRulePack())

    scanner = CodeScanner(root, registry=registry)
    dsa, design = scanner.scan()

    assert scanner.files_scanned == 1
    assert scanner.language_counts == {"stub": 1}
    assert [finding.rule_id for finding in scanner.findings] == ["STUB-001"]
    assert dsa == {}
    assert design == {}


def test_python_project_providers_are_registered_and_cached(project):
    root = project({
        "pyproject.toml": "[project]\nname = 'demo'\n",
        "demo/__init__.py": "",
        "demo/core.py": (
            "def pairs(items):\n"
            "    for left in items:\n"
            "        for right in items:\n"
            "            yield left, right\n"
        ),
    })
    scanner = CodeScanner(root)

    scanner.scan()
    package = scanner.project_results[("python", "package")]
    first = scanner.run_project_provider("python", "complexity")
    second = scanner.run_project_provider("python", "complexity")

    assert package.payload is scanner.package_intelligence
    assert package.health == {"errors": 0, "complete": True}
    assert first is second
    assert first.payload["total_functions"] == 1
    assert scanner.registry.capabilities()["project_providers"] == [
        {
            "language_id": "python",
            "capability": "complexity",
            "provider_id": "python-complexity",
            "enabled_by_default": False,
        },
        {
            "language_id": "python",
            "capability": "package",
            "provider_id": "python-package",
            "enabled_by_default": True,
        },
    ]
