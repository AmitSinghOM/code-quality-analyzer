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
    assert cqa_analyzer.__version__ == "2.44.0"
    assert metadata["scripts"] == {"code-quality-analyzer": "cqa_analyzer.__main__:main"}


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
    assert not any(classifier.startswith("License ::") for classifier in metadata["classifiers"])
    assert "Programming Language :: Python :: 3.11" in metadata["classifiers"]
    assert "Programming Language :: Python :: 3.10" not in metadata["classifiers"]


def test_readme_upgrade_example_pins_the_current_version():
    """The README's `cqa-analyzer==X.Y.Z` example must not go stale.

    docs/RELEASING.md step 2 updates it; this makes forgetting a red build
    rather than a stale instruction users copy-paste.
    """
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pinned = set()
    for line in readme.splitlines():
        if "last release" in line:
            continue  # deliberately historical, e.g. the final Python 3.10 release
        pinned.update(re.findall(r"cqa-analyzer==(\d+\.\d+\.\d+)", line))
    assert pinned == {
        cqa_analyzer.__version__
    }, f"README pins {sorted(pinned)}; __version__ is {cqa_analyzer.__version__}"


def test_changelog_top_entry_matches_the_package_version():
    """Round 2, D1: the newest dated CHANGELOG heading must be __version__."""
    import re

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## (\d+\.\d+\.\d+) - (\d{4}-\d{2}-\d{2})$", changelog, re.MULTILINE)
    assert headings, "no dated release heading found"
    newest_version, newest_date = headings[0]
    assert (
        newest_version == cqa_analyzer.__version__
    ), f"CHANGELOG top entry is {newest_version}; __version__ is {cqa_analyzer.__version__}"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", newest_date)
