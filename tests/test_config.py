"""Bounded configuration, source selection, and rule policy."""

import json

import pytest
from click.testing import CliRunner

from analyzer.__main__ import EXIT_FINDINGS, EXIT_OK, main
from analyzer.config import ConfigError, load_config
from analyzer.scanner import CodeScanner


def test_absent_config_has_stable_effective_fingerprint(project):
    root = project({"module.py": "VALUE = 1\n"})

    first = load_config(root)
    second = load_config(root)

    assert first == second
    assert len(first.fingerprint) == 64
    assert first.analysis.respect_gitignore is True


def test_comments_and_toml_key_order_do_not_change_fingerprint(project):
    root = project({
        ".code-quality.toml": (
            "[analysis]\ninclude = ['**/*.py']\nexclude = ['generated/**']\n"
            "[rules.\"PY-COR-001\"]\nenabled = true\nseverity = 'error'\n"
        ),
        "module.py": "VALUE = 1\n",
    })
    first = load_config(root).fingerprint
    (root / ".code-quality.toml").write_text(
        "# reordered\n[rules.\"PY-COR-001\"]\nseverity = 'error'\n"
        "enabled = true\n[analysis]\nexclude = ['generated/**']\n"
        "include = ['**/*.py']\n",
        encoding="utf-8",
    )

    assert load_config(root).fingerprint == first


def test_include_exclude_and_gitignore_filter_before_limit(project):
    root = project({
        ".code-quality.toml": (
            "[analysis]\ninclude = ['src/**/*.py']\n"
            "exclude = ['src/generated/**']\n"
        ),
        ".gitignore": "src/ignored.py\n!src/kept.py\n",
        "a.py": "VALUE = 1\n",
        "src/generated/a.py": "VALUE = 1\n",
        "src/ignored.py": "VALUE = 1\n",
        "src/kept.py": "VALUE = 1\n",
        "src/other.py": "VALUE = 1\n",
    })
    scanner = CodeScanner(
        root,
        max_files=1,
        configuration=load_config(root),
    )
    scanner.scan()

    assert scanner.discovery.source_candidates == 1
    assert scanner.files_scanned == 1
    assert scanner.discovery.truncated is True
    assert set(scanner.parsed_files["python"]) == {"src/kept.py"}


def test_respect_gitignore_can_be_disabled(project):
    root = project({
        ".code-quality.toml": (
            "[analysis]\nrespect_gitignore = false\n"
        ),
        ".gitignore": "ignored.py\n",
        "ignored.py": "VALUE = 1\n",
    })
    scanner = CodeScanner(root, configuration=load_config(root))

    scanner.scan()

    assert scanner.files_scanned == 1


@pytest.mark.parametrize(
    "source, message",
    [
        ("[analysis\n", "not valid TOML"),
        ("[analysis]\ninclude = 'src/**'\n", "array of strings"),
        ("[analysis]\nunknown = true\n", "Unknown analysis key"),
        (
            "[rules.\"PY-COR-001\"]\nseverity = 'critical'\n",
            "must be 'warning' or 'error'",
        ),
        ("[rules.bad]\nenabled = false\n", "Invalid rule ID"),
    ],
)
def test_invalid_configuration_is_rejected(project, source, message):
    root = project({
        ".code-quality.toml": source,
        "module.py": "VALUE = 1\n",
    })

    with pytest.raises(ConfigError, match=message):
        load_config(root)


def test_cli_rule_disable_and_severity_override(project):
    root = project({
        ".code-quality.toml": (
            "[rules.\"PY-COR-001\"]\nenabled = false\n"
        ),
        "service.py": "def f(cache={}):\n    return cache\n",
    })
    disabled = CliRunner().invoke(
        main,
        [str(root), "--output-format", "json", "--fail-on", "warning"],
    )
    disabled_payload = json.loads(disabled.output)

    assert disabled.exit_code == EXIT_OK
    assert disabled_payload["findings"] == []
    assert len(disabled_payload["configuration_fingerprint"]) == 64

    (root / ".code-quality.toml").write_text(
        "[rules.\"PY-COR-001\"]\nseverity = 'error'\n",
        encoding="utf-8",
    )
    overridden = CliRunner().invoke(
        main,
        [str(root), "--output-format", "json", "--fail-on", "error"],
    )
    overridden_payload = json.loads(overridden.output)

    assert overridden.exit_code == EXIT_FINDINGS
    assert overridden_payload["findings"][0]["severity"] == "error"
    assert overridden_payload["finding_summary"]["by_severity"] == {"error": 1}


def test_cli_reports_config_error_without_traceback(project):
    root = project({
        ".code-quality.toml": "[analysis\n",
        "module.py": "VALUE = 1\n",
    })

    result = CliRunner().invoke(main, [str(root)])

    assert result.exit_code != EXIT_OK
    assert "Configuration is not valid TOML" in result.output
    assert "Traceback" not in result.output
