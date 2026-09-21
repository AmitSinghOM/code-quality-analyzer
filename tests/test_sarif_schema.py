"""SARIF output must validate against the OASIS 2.1.0 schema, not just look right.

GitHub code scanning rejects uploads that fail schema validation, so every
result shape the reporter can emit -- plain findings with
``partialFingerprints``, suppressed findings with ``suppressions[]``,
anonymized output (no fingerprints), and an empty run -- is checked here
against the vendored schema (``tests/fixtures/sarif-schema-2.1.0.json``,
``additionalProperties: false`` at the root, so an unknown key fails).

``jsonschema`` is a pinned ``[dev]`` dependency; this module errors rather
than skips when it is missing so the gate can never pass vacuously in CI.
"""

import json
from pathlib import Path

import jsonschema
from clirunner import CliRunner

from cqa_analyzer.__main__ import main

SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
VALIDATOR = jsonschema.Draft7Validator(json.loads(SCHEMA_PATH.read_text()))

SUPPRESSED_AND_PLAIN = {
    "src/app.py": (
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)\n\n"
        "def run2(cmd):\n"
        "    return subprocess.call(cmd, shell=True)"
        '  # cqa: ignore=PY-SEC-002 reason="trusted"\n\n'
        "def f(items=[]):\n"
        "    return items\n"
    ),
}


def _sarif(root, *extra):
    result = CliRunner().invoke(main, [str(root), "-f", "sarif", *extra])
    assert result.output.strip(), result.stderr
    return json.loads(result.output)


def _schema_errors(document):
    return [
        "/".join(str(part) for part in error.absolute_path) + ": " + error.message
        for error in VALIDATOR.iter_errors(document)
    ]


def test_schema_fixture_is_the_oasis_2_1_0_schema():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["$id"].endswith("sarif-schema-2.1.0.json")
    assert schema["additionalProperties"] is False


def test_sarif_with_fingerprints_and_suppressions_validates(project):
    document = _sarif(project(SUPPRESSED_AND_PLAIN))
    results = document["runs"][0]["results"]

    assert sum("partialFingerprints" in r for r in results) >= 1
    assert sum("suppressions" in r for r in results) == 1
    assert _schema_errors(document) == []


def test_anonymized_sarif_validates(project):
    document = _sarif(project(SUPPRESSED_AND_PLAIN), "--anonymize")

    assert document["runs"][0]["results"]
    assert _schema_errors(document) == []


def test_redacted_sarif_validates(project):
    document = _sarif(project(SUPPRESSED_AND_PLAIN), "--redact-paths")

    assert _schema_errors(document) == []


def test_empty_sarif_run_validates(project):
    document = _sarif(project({"ok.py": "X = 1\n"}))

    assert document["runs"][0]["results"] == []
    assert _schema_errors(document) == []


def test_validator_rejects_a_non_spec_key(project):
    """Guard against the guard: the schema really does refuse unknown keys."""
    document = _sarif(project({"ok.py": "X = 1\n"}))
    document["runs"][0]["notASarifKey"] = True

    assert any("notASarifKey" in error for error in _schema_errors(document))
