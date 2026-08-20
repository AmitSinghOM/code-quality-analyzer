"""Versioned report-schema and golden authority contract."""

import json
from pathlib import Path

from click.testing import CliRunner

from analyzer.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = Path(__file__).parents[1] / "docs" / "report-schema-1.7.0.json"


def test_json_authority_contract_matches_schema_and_golden(project):
    root = project({"module.py": "VALUE = 1\n"})
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    golden = json.loads(
        (FIXTURES / "analysis-authority.json").read_text(encoding="utf-8")
    )

    assert result.exit_code == 0
    assert set(schema["required"]) <= set(payload)
    assert payload["schema_version"] == schema["properties"][
        "schema_version"
    ]["const"]
    assert {
        "scoring_policy_version": payload["scoring_policy_version"],
        "analysis_health": payload["analysis_health"],
    } == golden


def test_text_authority_contract_matches_golden_lines(project):
    root = project({"module.py": "VALUE = 1\n"})
    result = CliRunner().invoke(main, [str(root)])
    expected = (FIXTURES / "analysis-authority.txt").read_text(
        encoding="utf-8"
    ).splitlines()

    assert result.exit_code == 0
    for line in expected:
        assert line in result.output
