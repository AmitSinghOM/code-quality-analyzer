"""First-public-release package identity and metadata contracts."""

from pathlib import Path

import tomllib

import cqa_analyzer

ROOT = Path(__file__).parents[1]


def _project_metadata() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)["project"]


def test_distribution_import_and_cli_identities_are_distinct_and_stable():
    metadata = _project_metadata()

    assert metadata["name"] == "cqa-analyzer"
    assert cqa_analyzer.__version__ == "2.30.1"
    assert metadata["scripts"] == {
        "code-quality-analyzer": "cqa_analyzer.__main__:main"
    }


def test_public_package_metadata_is_complete():
    metadata = _project_metadata()

    assert metadata["authors"] == [{"name": "Amit Singh"}]
    assert metadata["urls"]["Repository"].endswith("/code-quality-analyzer")
    assert metadata["urls"]["Issues"].endswith("/issues")
    # PEP 639: the license is declared with an SPDX expression plus license
    # files, not the deprecated "License :: OSI Approved :: MIT License"
    # trove classifier. setuptools>=77 rejects combining that classifier with a
    # license expression, so the classifier must be absent.
    assert metadata["license"] == "MIT"
    assert metadata["license-files"] == ["LICENSE"]
    assert not any(
        classifier.startswith("License ::")
        for classifier in metadata["classifiers"]
    )
    assert "Programming Language :: Python :: 3.11" in metadata["classifiers"]
    assert "Programming Language :: Python :: 3.10" not in metadata["classifiers"]
