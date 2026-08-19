"""Passive package metadata, layout, and import-graph analysis."""

from analyzer.package_intelligence import _strongly_connected_cycles
from analyzer.scanner import CodeScanner


def test_src_layout_metadata_and_import_graph(project):
    root = project({
        "pyproject.toml": (
            "[build-system]\n"
            "build-backend = 'setuptools.build_meta'\n\n"
            "[project]\n"
            "name = 'acme-tools'\n"
            "requires-python = '>=3.10'\n"
            "dependencies = ['click==8.3.3']\n\n"
            "[project.optional-dependencies]\n"
            "dev = ['pytest==8.3.4']\n\n"
            "[project.scripts]\n"
            "acme = 'acme.cli:main'\n"
        ),
        "src/acme/__init__.py": "",
        "src/acme/cli.py": "from . import service\n\ndef main():\n    return 0\n",
        "src/acme/service.py": "VALUE = 1\n",
        "tests/test_cli.py": "from acme import cli\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()
    package = scanner.package_intelligence

    assert package.pyproject_present is True
    assert package.metadata_valid is True
    assert package.project_name == "acme-tools"
    assert package.requires_python == ">=3.10"
    assert package.build_backend == "setuptools.build_meta"
    assert package.dependencies == ["click==8.3.3"]
    assert package.optional_dependencies == {"dev": ["pytest==8.3.4"]}
    assert package.scripts == {"acme": "acme.cli:main"}
    assert package.layout == "src"
    assert package.source_roots == ["src"]
    assert package.modules == ["acme", "acme.cli", "acme.service"]
    assert package.import_graph["acme.cli"] == ["acme.service"]
    assert "tests.test_cli" not in package.modules


def test_circular_import_emits_actionable_finding(project):
    root = project({
        "pkg/__init__.py": "",
        "pkg/a.py": "from . import b\n",
        "pkg/b.py": "from . import a\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert scanner.package_intelligence.circular_imports == [["pkg.a", "pkg.b"]]
    findings = [item for item in scanner.findings if item.rule_id == "PY-PKG-001"]
    assert len(findings) == 1
    assert findings[0].category == "package-health"
    assert findings[0].location.path == "pkg/a.py"
    assert findings[0].location.line == 1
    assert "pkg.a, pkg.b" in findings[0].message


def test_missing_console_script_module_is_an_error(project):
    root = project({
        "pyproject.toml": (
            "[project]\n"
            "name = 'demo'\n\n"
            "[project.scripts]\n"
            "demo = 'demo.missing:main'\n"
        ),
        "demo/__init__.py": "",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    findings = [item for item in scanner.findings if item.rule_id == "PY-PKG-002"]
    assert len(findings) == 1
    assert findings[0].severity == "error"
    assert findings[0].location.path == "pyproject.toml"


def test_invalid_pyproject_marks_analysis_incomplete(project):
    root = project({
        "pyproject.toml": "[project\nname = 'broken'\n",
        "module.py": "VALUE = 1\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert scanner.package_intelligence.metadata_valid is False
    assert scanner.package_health == {"errors": 1, "complete": False}
    assert scanner.has_coverage_gaps is True
    assert any(item.rule_id == "PY-PKG-003" for item in scanner.findings)


def test_directory_without_package_has_empty_package_report(project):
    root = project({"tests/test_only.py": "def test_value():\n    assert True\n"})

    scanner = CodeScanner(root)
    scanner.scan()

    package = scanner.package_intelligence
    assert package.pyproject_present is False
    assert package.layout == "none"
    assert package.source_roots == []
    assert package.modules == []
    assert package.import_graph == {}


def test_import_graph_handles_deep_acyclic_chains_without_recursion():
    graph = {
        f"module_{index}": ({f"module_{index + 1}"} if index < 1499 else set())
        for index in range(1500)
    }

    assert _strongly_connected_cycles(graph) == []


def test_redaction_applies_to_package_findings(project):
    root = project({
        "pkg/__init__.py": "",
        "pkg/a.py": "from . import b\n",
        "pkg/b.py": "from . import a\n",
    })

    scanner = CodeScanner(root, redact_paths=True)
    scanner.scan()

    finding = next(item for item in scanner.findings if item.rule_id == "PY-PKG-001")
    assert finding.location.path == "a.py"
