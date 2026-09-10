"""Bounded configuration, source selection, and rule policy."""

import json

import pytest
from click.testing import CliRunner

from cqa_analyzer.__main__ import EXIT_FINDINGS, EXIT_OK, main
from cqa_analyzer.config import ConfigError, load_config
from cqa_analyzer.scanner import CodeScanner


def test_absent_config_has_stable_effective_fingerprint(project):
    root = project({"module.py": "VALUE = 1\n"})

    first = load_config(root)
    second = load_config(root)

    assert first == second
    assert len(first.fingerprint) == 64
    assert first.analysis.respect_gitignore is True


def test_comments_and_toml_key_order_do_not_change_fingerprint(project):
    root = project(
        {
            ".code-quality.toml": (
                "[analysis]\ninclude = ['**/*.py']\nexclude = ['generated/**']\n"
                "[rules.\"PY-COR-001\"]\nenabled = true\nseverity = 'error'\n"
            ),
            "module.py": "VALUE = 1\n",
        }
    )
    first = load_config(root).fingerprint
    (root / ".code-quality.toml").write_text(
        "# reordered\n[rules.\"PY-COR-001\"]\nseverity = 'error'\n"
        "enabled = true\n[analysis]\nexclude = ['generated/**']\n"
        "include = ['**/*.py']\n",
        encoding="utf-8",
    )

    assert load_config(root).fingerprint == first


def test_include_exclude_and_gitignore_filter_before_limit(project):
    root = project(
        {
            ".code-quality.toml": (
                "[analysis]\ninclude = ['src/**/*.py']\n" "exclude = ['src/generated/**']\n"
            ),
            ".gitignore": "src/ignored.py\n!src/kept.py\n",
            "a.py": "VALUE = 1\n",
            "src/generated/a.py": "VALUE = 1\n",
            "src/ignored.py": "VALUE = 1\n",
            "src/kept.py": "VALUE = 1\n",
            "src/other.py": "VALUE = 1\n",
        }
    )
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
    root = project(
        {
            ".code-quality.toml": ("[analysis]\nrespect_gitignore = false\n"),
            ".gitignore": "ignored.py\n",
            "ignored.py": "VALUE = 1\n",
        }
    )
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
    root = project(
        {
            ".code-quality.toml": source,
            "module.py": "VALUE = 1\n",
        }
    )

    with pytest.raises(ConfigError, match=message):
        load_config(root)


def test_cli_rule_disable_and_severity_override(project):
    root = project(
        {
            ".code-quality.toml": ('[rules."PY-COR-001"]\nenabled = false\n'),
            "service.py": "def f(cache={}):\n    return cache\n",
        }
    )
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
    root = project(
        {
            ".code-quality.toml": "[analysis\n",
            "module.py": "VALUE = 1\n",
        }
    )

    result = CliRunner().invoke(main, [str(root)])

    assert result.exit_code != EXIT_OK
    assert "Configuration is not valid TOML" in result.output
    assert "Traceback" not in result.output


def test_byte_budget_truncates_with_an_explicit_reason(project):
    # Round 2, A3: total bytes read are bounded and reported, never silent.
    from cqa_analyzer.config import AnalysisConfig
    from cqa_analyzer.discovery import DiscoveryReport, iter_source_files

    root = project({f"m{i}.py": "x = 1\n" * 100 for i in range(6)})
    report = DiscoveryReport()
    files = list(
        iter_source_files(
            root,
            (".py",),
            report=report,
            analysis=AnalysisConfig(),
            max_total_bytes=2_000,
        )
    )
    assert len(files) == 3  # 600 bytes each; the fourth would exceed 2,000
    assert report.truncated and report.truncated_reasons == ["byte_budget"]
    assert report.bytes_read == 1_800
    assert report.as_dict()["truncated_reasons"] == ["byte_budget"]


def test_pruned_directories_are_counted_and_keep_directories_unprunes(project):
    # Round 2, B4: skipping `vendor/` or `external/` must be visible, and
    # a project whose `external/` is first-party can opt back in.
    files = {
        "src/a.py": "x = 1\n",
        "vendor/lib/v.py": "y = 2\n",
        "external/api/e.py": "z = 3\n",
        "node_modules/m/n.py": "w = 4\n",
    }
    root = project(files)
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    health = payload["scan_health"]
    assert health["files_found"] == 1
    assert health["pruned_directories"] == 3
    assert sorted(health["pruned_examples"]) == ["external", "node_modules", "vendor"]

    root = project({**files, ".code-quality.toml": '[analysis]\nkeep_directories = ["external"]\n'})
    payload = json.loads(CliRunner().invoke(main, [str(root), "-f", "json"]).output)
    assert payload["scan_health"]["files_found"] == 2
    assert payload["scan_health"]["pruned_directories"] == 2

    bad = project({".code-quality.toml": '[analysis]\nkeep_directories = ["a/b"]\n', "a.py": ""})
    result = CliRunner().invoke(main, [str(bad), "-f", "json"])
    assert result.exit_code != 0 and "bare directory names" in result.output


def test_gitignore_character_classes_match_like_git():
    # Round 2, C5.
    from cqa_analyzer.config import _glob_matches

    assert _glob_matches("[abc].py", "a.py")
    assert not _glob_matches("[abc].py", "d.py")
    assert _glob_matches("build[0-9]/", "build3/x.py")
    assert _glob_matches("[!t]est.py", "best.py")
    assert not _glob_matches("[!t]est.py", "test.py")
    assert _glob_matches("[^t]est.py", "best.py")
    assert not _glob_matches("[abc", "a.py")  # unterminated: literal, no crash
