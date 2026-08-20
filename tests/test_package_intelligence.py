"""Passive package metadata, layout, and import-graph analysis."""

import pytest

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


def test_literal_all_reports_missing_and_repeated_exports(project):
    root = project({
        "pkg/__init__.py": (
            "__all__ = [\n"
            "    'ready',\n"
            "    'missing',\n"
            "    'ready',\n"
            "    'missing',\n"
            "    'missing',\n"
            "]\n"
            "ready = True\n"
        ),
    })

    scanner = CodeScanner(root)
    scanner.scan()
    findings = [
        item for item in scanner.findings
        if item.rule_id in {"PY-PKG-004", "PY-PKG-005"}
    ]

    assert [item.rule_id for item in findings] == [
        "PY-PKG-004",
        "PY-PKG-005",
        "PY-PKG-005",
        "PY-PKG-005",
    ]
    assert [item.location.line for item in findings] == [3, 4, 5, 6]
    assert all(item.location.column == 5 for item in findings)
    assert findings[0].severity == "error"
    assert findings[0].confidence == "high"
    assert findings[1].severity == "warning"
    assert "missing" in findings[0].message


def test_literal_all_recognizes_supported_module_bindings(project):
    root = project({
        "pkg/__init__.py": (
            "__all__: tuple[str, ...] = (\n"
            "    'sync_fn', 'async_fn', 'Type', 'assigned', 'left',\n"
            "    'typed', 'imported', 'imported_from', 'controlled',\n"
            "    'loop_value', 'managed', 'caught',\n"
            ")\n"
            "def sync_fn():\n    pass\n"
            "async def async_fn():\n    pass\n"
            "class Type:\n    pass\n"
            "assigned = 1\n"
            "left, right = (1, 2)\n"
            "typed: int\n"
            "import os as imported\n"
            "from os import path as imported_from\n"
            "if True:\n    controlled = 1\n"
            "for loop_value in ():\n    pass\n"
            "with manager() as managed:\n    pass\n"
            "try:\n    pass\n"
            "except RuntimeError as caught:\n    pass\n"
        ),
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert not [
        item for item in scanner.findings
        if item.rule_id in {"PY-PKG-004", "PY-PKG-005"}
    ]


def test_literal_all_is_case_sensitive_and_ignores_nested_bindings(project):
    root = project({
        "pkg/__init__.py": (
            "__all__ = ('Public', 'nested', 'method_name')\n"
            "public = 1\n"
            "def outer():\n"
            "    nested = 1\n"
            "class Container:\n"
            "    method_name = 1\n"
        ),
        "pkg/empty.py": "__all__ = []\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()
    findings = [
        item for item in scanner.findings if item.rule_id == "PY-PKG-004"
    ]

    assert [item.message.split("'")[1] for item in findings] == [
        "Public",
        "nested",
        "method_name",
    ]


def test_dynamic_or_ambiguous_all_declarations_are_skipped(project):
    sources = (
        "__all__ = ['missing', 'missing']\n__all__ = ['other']\n",
        "__all__ = ['missing'] + ['missing']\n",
        "__all__ = ['missing', *EXTRA]\n",
        "__all__ = [name for name in NAMES]\n",
        "__all__ = make_exports()\n",
        "__all__ = ['missing', 1]\n",
        "__all__ = ['missing', 'missing']\n__all__ += ['other']\n",
        "__all__ = ['missing', 'missing']\n__all__.append('other')\n",
        "__all__ = ['missing', 'missing']\ndel __all__\n",
        "__all__ = ['missing', 'missing']\nescaped = __all__\n",
        "from extension import *\n__all__ = ['missing', 'missing']\n",
        (
            "__all__ = ['missing', 'missing']\n"
            "def __getattr__(name):\n    return 1\n"
        ),
        "__all__ = ['missing', 'missing']\nexec('dynamic = 1')\n",
    )
    files = {
        f"pkg/case_{index}.py": source
        for index, source in enumerate(sources)
    }
    files["pkg/__init__.py"] = ""
    root = project(files)

    scanner = CodeScanner(root)
    scanner.scan()

    assert not [
        item for item in scanner.findings
        if item.rule_id in {"PY-PKG-004", "PY-PKG-005"}
    ]


def test_literal_all_suppressions_require_reason_and_reported_line(project):
    root = project({
        "pkg/__init__.py": (
            "__all__ = [\n"
            "    'hidden',  # cqa: ignore=PY-PKG-004 reason='generated'\n"
            "    'repeat',\n"
            "    'repeat',  # cqa: ignore=PY-PKG-005 reason='compatibility'\n"
            "    'bad_reason',  # cqa: ignore=PY-PKG-004\n"
            "    'wrong_line',\n"
            "]\n"
            "# cqa: ignore=PY-PKG-004 reason='too late'\n"
            "repeat = 1\n"
        ),
    })

    scanner = CodeScanner(root)
    scanner.scan()
    findings = [
        item for item in scanner.findings
        if item.rule_id in {"PY-PKG-004", "PY-PKG-005"}
    ]

    assert [item.location.line for item in findings] == [5, 6]
    assert all(item.rule_id == "PY-PKG-004" for item in findings)


def test_literal_all_findings_preserve_identity_when_redacted(project):
    root = project({
        "pkg/public.py": "__all__ = ['missing']\n",
        "pkg/__init__.py": "",
    })

    scanner = CodeScanner(root, redact_paths=True)
    scanner.scan()
    finding = next(
        item for item in scanner.findings if item.rule_id == "PY-PKG-004"
    )

    assert finding.location.path == "public.py"
    assert finding.location.identity_path == "pkg/public.py"


def test_literal_all_project_findings_honor_rule_policy(project):
    from analyzer.config import load_config

    root = project({
        ".code-quality.toml": (
            "[rules.\"PY-PKG-004\"]\n"
            "enabled = false\n"
            "[rules.\"PY-PKG-005\"]\n"
            "severity = 'error'\n"
        ),
        "pkg/__init__.py": "__all__ = ['missing', 'missing']\n",
    })

    scanner = CodeScanner(root, configuration=load_config(root))
    scanner.scan()
    findings = [
        item for item in scanner.findings
        if item.rule_id in {"PY-PKG-004", "PY-PKG-005"}
    ]

    assert len(findings) == 1
    assert findings[0].rule_id == "PY-PKG-005"
    assert findings[0].severity == "error"


def test_package_public_api_analysis_reuses_shared_ast(project, monkeypatch):
    import ast

    root = project({
        "pkg/__init__.py": "__all__ = ['missing']\n",
    })
    real_parse = ast.parse
    parse_calls = 0

    def counting_parse(*args, **kwargs):
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting_parse)
    scanner = CodeScanner(root)
    scanner.scan()

    assert parse_calls == 1
    assert any(item.rule_id == "PY-PKG-004" for item in scanner.findings)


def test_literal_all_finding_order_is_deterministic(project):
    root = project({
        "pkg/z.py": "__all__ = ['z_missing', 'z_missing']\n",
        "pkg/a.py": "__all__ = ['a_missing', 'a_missing']\n",
        "pkg/__init__.py": "",
    })

    first = CodeScanner(root)
    first.scan()
    second = CodeScanner(root)
    second.scan()

    def package_facts(scanner):
        return [
            (
                item.location.path,
                item.location.line,
                item.rule_id,
                item.message,
            )
            for item in scanner.findings
            if item.rule_id in {"PY-PKG-004", "PY-PKG-005"}
        ]

    assert package_facts(first) == package_facts(second)
    assert [item[0] for item in package_facts(first)] == [
        "pkg/a.py",
        "pkg/a.py",
        "pkg/z.py",
        "pkg/z.py",
    ]


def _namespace_pyproject(find_config: str, backend: str = "setuptools.build_meta"):
    return (
        "[build-system]\n"
        f"build-backend = '{backend}'\n\n"
        "[project]\n"
        "name = 'namespace-demo'\n\n"
        "[project.scripts]\n"
        "demo = 'acme.plugins.cli:main'\n\n"
        f"{find_config}"
    )


def test_configured_flat_namespace_expands_package_analysis(project):
    root = project({
        "pyproject.toml": _namespace_pyproject(
            "[tool.setuptools.packages.find]\n"
            "include = ['acme.*']\n"
        ),
        "acme/plugins/cli.py": (
            "from . import service\n"
            "__all__ = ['main', 'missing']\n\n"
            "def main():\n"
            "    return service.VALUE\n"
        ),
        "acme/plugins/service.py": "VALUE = 1\n",
        "tests/test_cli.py": "from acme.plugins import cli\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()
    package = scanner.package_intelligence

    assert package.layout == "flat"
    assert package.source_roots == ["."]
    assert package.modules == ["acme.plugins.cli", "acme.plugins.service"]
    assert package.import_graph["acme.plugins.cli"] == [
        "acme.plugins.service",
    ]
    assert not any(
        item.rule_id == "PY-PKG-002" for item in scanner.findings
    )
    public_api = [
        item for item in scanner.findings if item.rule_id == "PY-PKG-004"
    ]
    assert len(public_api) == 1
    assert "missing" in public_api[0].message
    assert public_api[0].location.path == "acme/plugins/cli.py"


def test_custom_namespace_root_supports_cycle_detection(project):
    root = project({
        "pyproject.toml": _namespace_pyproject(
            "[tool.setuptools.packages.find]\n"
            "where = ['lib']\n"
            "include = ['acme.plugins']\n"
        ),
        "lib/acme/plugins/cli.py": "from . import service\n\ndef main():\n    pass\n",
        "lib/acme/plugins/service.py": "from . import cli\n",
    })

    first = CodeScanner(root)
    first.scan()
    second = CodeScanner(root)
    second.scan()

    expected_modules = ["acme.plugins.cli", "acme.plugins.service"]
    assert first.package_intelligence.modules == expected_modules
    assert first.package_intelligence.source_roots == ["lib"]
    assert first.package_intelligence.circular_imports == [expected_modules]
    cycle = next(
        item for item in first.findings if item.rule_id == "PY-PKG-001"
    )
    assert cycle.location.path == "lib/acme/plugins/cli.py"
    assert first.package_intelligence.as_dict() == (
        second.package_intelligence.as_dict()
    )
    assert first.findings == second.findings


@pytest.mark.parametrize(
    ("find_config", "backend"),
    [
        ("[tool.setuptools.packages.find]\n", "setuptools.build_meta"),
        (
            "[tool.setuptools.packages.find]\n"
            "include = ['acme.*']\n"
            "namespaces = false\n",
            "setuptools.build_meta",
        ),
        (
            "[tool.setuptools.packages.find]\n"
            "include = ['acme.*']\n",
            "hatchling.build",
        ),
        (
            "[tool.setuptools.packages.find]\n"
            "include = ['acme*']\n",
            "setuptools.build_meta",
        ),
        (
            "[tool.setuptools.packages.find]\n"
            "where = ['../outside']\n"
            "include = ['acme.*']\n",
            "setuptools.build_meta",
        ),
        (
            "[tool.setuptools.packages.find]\n"
            "include = ['acme.*']\n"
            "exclude = ['acme.private']\n",
            "setuptools.build_meta",
        ),
        (
            "[tool.setuptools]\n"
            "package-dir = {'' = '.'}\n"
            "[tool.setuptools.packages.find]\n"
            "include = ['acme.*']\n",
            "setuptools.build_meta",
        ),
        (
            "[tool.setuptools.packages.find]\n"
            "where = ['.', 'lib']\n"
            "include = ['acme.*']\n",
            "setuptools.build_meta",
        ),
    ],
)
def test_ambiguous_namespace_configuration_is_skipped(
    project,
    find_config,
    backend,
):
    root = project({
        "pyproject.toml": _namespace_pyproject(find_config, backend),
        "acme/plugins/cli.py": "def main():\n    pass\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert scanner.package_intelligence.layout == "none"
    assert scanner.package_intelligence.modules == []


def test_namespace_discovery_parses_each_source_once(project, monkeypatch):
    import ast

    root = project({
        "pyproject.toml": _namespace_pyproject(
            "[tool.setuptools.packages.find]\n"
            "include = ['acme.*']\n"
        ),
        "acme/plugins/cli.py": "from . import service\n\ndef main():\n    pass\n",
        "acme/plugins/service.py": "VALUE = 1\n",
    })
    real_parse = ast.parse
    parse_calls = 0

    def counting_parse(*args, **kwargs):
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting_parse)
    scanner = CodeScanner(root)
    scanner.scan()

    assert parse_calls == 2
    assert scanner.package_intelligence.modules == [
        "acme.plugins.cli",
        "acme.plugins.service",
    ]


def _package_data_pyproject(
    declaration: str,
    *,
    backend: str = "setuptools.build_meta",
    requires: str = "['setuptools==80.9.0']",
    build_extra: str = "",
    setuptools_extra: str = "",
) -> str:
    return (
        "[build-system]\n"
        f"requires = {requires}\n"
        f"build-backend = '{backend}'\n"
        f"{build_extra}\n"
        "[project]\n"
        "name = 'package-data-demo'\n\n"
        f"{setuptools_extra}"
        "[tool.setuptools.package-data]\n"
        f"{declaration}\n"
    )


@pytest.mark.parametrize(
    ("module_path", "existing_path"),
    [
        ("pkg/__init__.py", "pkg/data/existing.json"),
        ("src/pkg/__init__.py", "src/pkg/data/existing.json"),
    ],
)
def test_literal_package_data_reports_only_missing_files(
    project,
    module_path,
    existing_path,
):
    root = project({
        "pyproject.toml": _package_data_pyproject(
            "pkg = ['data/existing.json', 'data/missing.json']"
        ),
        module_path: "",
        existing_path: "{}\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()
    findings = [
        item for item in scanner.findings if item.rule_id == "PY-PKG-006"
    ]

    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert findings[0].confidence == "high"
    assert findings[0].location.path == "pyproject.toml"
    assert "pkg" in findings[0].message
    assert "data/missing.json" in findings[0].message
    assert scanner.package_health == {"errors": 0, "complete": True}


def test_literal_package_data_supports_configured_namespaces(project):
    root = project({
        "pyproject.toml": _package_data_pyproject(
            "'acme.plugins' = ['data/missing.json']",
            setuptools_extra=(
                "[tool.setuptools.packages.find]\n"
                "where = ['lib']\n"
                "include = ['acme.*']\n\n"
            ),
        ),
        "lib/acme/plugins/cli.py": "VALUE = 1\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()
    finding = next(
        item for item in scanner.findings if item.rule_id == "PY-PKG-006"
    )

    assert scanner.package_intelligence.source_roots == ["lib"]
    assert "acme.plugins" in finding.message
    assert "data/missing.json" in finding.message


def test_literal_package_data_findings_are_deterministic(project):
    root = project({
        "pyproject.toml": _package_data_pyproject(
            "zeta = ['z.json', 'a.json', 'z.json']\n"
            "alpha = ['b.json', 'a.json']"
        ),
        "alpha/__init__.py": "",
        "zeta/__init__.py": "",
    })

    first = CodeScanner(root)
    first.scan()
    second = CodeScanner(root)
    second.scan()
    first_messages = [
        item.message
        for item in first.findings
        if item.rule_id == "PY-PKG-006"
    ]
    second_messages = [
        item.message
        for item in second.findings
        if item.rule_id == "PY-PKG-006"
    ]

    assert first_messages == second_messages
    assert first_messages == [
        (
            "Static package-data declaration for 'alpha' names missing "
            "source file 'a.json'."
        ),
        (
            "Static package-data declaration for 'alpha' names missing "
            "source file 'b.json'."
        ),
        (
            "Static package-data declaration for 'zeta' names missing "
            "source file 'a.json'."
        ),
        (
            "Static package-data declaration for 'zeta' names missing "
            "source file 'z.json'."
        ),
    ]


@pytest.mark.parametrize(
    "pyproject",
    [
        _package_data_pyproject(
            "pkg = ['missing.json']",
            backend="hatchling.build",
        ),
        _package_data_pyproject(
            "pkg = ['missing.json']",
            build_extra="backend-path = ['build_backend']\n",
        ),
        _package_data_pyproject(
            "pkg = ['missing.json']",
            requires="['setuptools==80.9.0', 'wheel==0.45.1']",
        ),
        _package_data_pyproject(
            "pkg = ['missing.json']",
            setuptools_extra=(
                "[tool.setuptools.cmdclass]\n"
                "build_py = 'build.CustomBuild'\n\n"
            ),
        ),
        _package_data_pyproject(
            "pkg = ['missing.json']",
            setuptools_extra=(
                "[tool.setuptools]\n"
                "package-dir = {'' = 'src'}\n\n"
            ),
        ),
        _package_data_pyproject("'*' = ['missing.json']"),
        _package_data_pyproject("pkg = ['data/*.json']"),
        _package_data_pyproject("'invalid-key' = ['missing.json']"),
        _package_data_pyproject("pkg = [1]"),
        _package_data_pyproject("unknown = ['missing.json']"),
    ],
)
def test_ambiguous_package_data_declarations_are_skipped(project, pyproject):
    root = project({
        "pyproject.toml": pyproject,
        "pkg/__init__.py": "",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert not any(
        item.rule_id == "PY-PKG-006" for item in scanner.findings
    )


@pytest.mark.parametrize(
    "target",
    [
        "/absolute.json",
        "../outside.json",
        "data\\windows.json",
        "data/./local.json",
        "data//local.json",
        "C:/drive.json",
        "data/[ab].json",
    ],
)
def test_unsafe_package_data_paths_are_skipped(project, target):
    root = project({
        "pyproject.toml": _package_data_pyproject(
            f"pkg = [{target!r}]"
        ),
        "pkg/__init__.py": "",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert not any(
        item.rule_id == "PY-PKG-006" for item in scanner.findings
    )


def test_package_data_directories_and_symlinks_are_skipped(project, tmp_path):
    root = project({
        "pyproject.toml": _package_data_pyproject(
            "pkg = ['data', 'linked.json']"
        ),
        "pkg/__init__.py": "",
        "pkg/data/present.json": "{}\n",
    })
    outside = tmp_path / "outside.json"
    outside.write_text("private\n", encoding="utf-8")
    try:
        (root / "pkg" / "linked.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    scanner = CodeScanner(root)
    scanner.scan()

    assert not any(
        item.rule_id == "PY-PKG-006" for item in scanner.findings
    )


def test_package_data_rule_honors_project_policy(project):
    from analyzer.config import load_config

    root = project({
        ".code-quality.toml": (
            "[rules.\"PY-PKG-006\"]\n"
            "enabled = false\n"
        ),
        "pyproject.toml": _package_data_pyproject(
            "pkg = ['missing.json']"
        ),
        "pkg/__init__.py": "",
    })

    disabled = CodeScanner(root, configuration=load_config(root))
    disabled.scan()
    assert not any(
        item.rule_id == "PY-PKG-006" for item in disabled.findings
    )

    (root / ".code-quality.toml").write_text(
        "[rules.\"PY-PKG-006\"]\nseverity = 'error'\n",
        encoding="utf-8",
    )
    overridden = CodeScanner(root, configuration=load_config(root))
    overridden.scan()
    finding = next(
        item for item in overridden.findings
        if item.rule_id == "PY-PKG-006"
    )
    assert finding.severity == "error"


def test_custom_setup_files_disable_package_data_validation(project):
    for filename in ("setup.py", "setup.cfg"):
        root = project({
            "pyproject.toml": _package_data_pyproject(
                "pkg = ['missing.json']"
            ),
            "pkg/__init__.py": "",
            filename: "# custom build\n",
        })

        scanner = CodeScanner(root)
        scanner.scan()

        assert not any(
            item.rule_id == "PY-PKG-006" for item in scanner.findings
        )
        (root / filename).unlink()


def test_package_data_skips_unconfigured_namespace_like_directory(project):
    root = project({
        "pyproject.toml": _package_data_pyproject(
            "'pkg.plugins' = ['missing.json']"
        ),
        "pkg/__init__.py": "",
        "pkg/plugins/tool.py": "VALUE = 1\n",
    })

    scanner = CodeScanner(root)
    scanner.scan()

    assert "pkg.plugins.tool" in scanner.package_intelligence.modules
    assert not any(
        item.rule_id == "PY-PKG-006" for item in scanner.findings
    )
