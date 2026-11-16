"""Every rule links to the heading in ``docs/RULES.md`` that documents it (E3).

``rule_metadata.help_url`` builds the SARIF ``helpUri`` / ``help.markdown``
link from a frozen ``rule id -> GitHub anchor`` map so the runtime never reads
a file. This module is the only place the map is checked against the real
document: it parses the headings of ``docs/RULES.md``, slugs them the way
GitHub does, and asserts the frozen map equals the parsed one for every
built-in rule. Rename or remove a heading and the completeness test fails;
the negative test proves it does.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from clirunner import CliRunner

from cqa_analyzer import __version__
from cqa_analyzer.__main__ import main
from cqa_analyzer.reporters import _rule_descriptor
from cqa_analyzer.rule_metadata import (
    _RULE_ANCHORS,
    builtin_rule_ids,
    help_url,
    rule_metadata,
)

RULES_MD = Path(__file__).parents[1] / "docs" / "RULES.md"
RULE_ID = re.compile(r"\b[A-Z]+-[A-Z]+-\d{3}\b")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
# github-slugger: keep letters, marks, numbers, connector punctuation (``_``),
# hyphen and space; drop everything else; then space -> hyphen.
_SLUG_DROP = re.compile(r"[^\w\- ]", re.UNICODE)
_URL_PREFIX = "https://github.com/AmitSinghOM/code-quality-analyzer/blob/v"

SAMPLE = {
    "src/app.py": (
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)\n\n"
        "def f(items=[]):\n"
        "    return items\n"
    ),
}


def github_slug(text: str, seen: dict[str, int]) -> str:
    """Slug one heading like GitHub, with ``-1``, ``-2`` dedupe suffixes."""
    slug = _SLUG_DROP.sub("", text.lower()).replace(" ", "-")
    count = seen.get(slug, 0)
    seen[slug] = count + 1
    return slug if count == 0 else f"{slug}-{count}"


def heading_anchors(markdown: str) -> dict[str, str]:
    """Map every rule id named in a heading to that heading's GitHub anchor.

    Headings inside fenced code blocks (``# Non-compliant`` comments in the
    examples) are not headings and are skipped, exactly as GitHub skips them.
    """
    anchors: dict[str, str] = {}
    seen: dict[str, int] = {}
    in_fence = False
    for line in markdown.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING.match(line)
        if not match:
            continue
        slug = github_slug(match.group(2), seen)
        for rule_id in RULE_ID.findall(match.group(2)):
            anchors.setdefault(rule_id, slug)
    return anchors


def _sarif(root, *extra):
    result = CliRunner().invoke(main, [str(root), "-f", "sarif", "--offline", *extra])
    assert result.output.strip(), result.stderr
    return json.loads(result.output)


# ---- slugger -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("heading", "slug"),
    [
        ("PY-COR-001: Mutable default argument", "py-cor-001-mutable-default-argument"),
        (
            "GO-DUP-001 / C-DUP-001: Duplicate function implementation (requires `[deep]`)",
            "go-dup-001--c-dup-001-duplicate-function-implementation-requires-deep",
        ),
        (
            "RS-PKG-001: Undeclared crate / RS-PKG-002: Invalid Cargo.toml",
            "rs-pkg-001-undeclared-crate--rs-pkg-002-invalid-cargotoml",
        ),
        ("C-COR-004: `using namespace` in a header", "c-cor-004-using-namespace-in-a-header"),
        ("Security rules (`*-SEC-*`)", "security-rules--sec-"),
    ],
)
def test_github_slug_matches_github_examples(heading, slug):
    assert github_slug(heading, {}) == slug


def test_github_slug_dedupes_repeated_headings_with_numeric_suffixes():
    seen: dict[str, int] = {}
    assert github_slug("Non-compliant", seen) == "non-compliant"
    assert github_slug("Non-compliant", seen) == "non-compliant-1"
    assert github_slug("Compliant", seen) == "compliant"
    assert github_slug("Non-compliant", seen) == "non-compliant-2"


def test_heading_parser_skips_headings_inside_code_fences():
    document = (
        "## PY-COR-001: Mutable default argument\n"
        "```python\n# PY-COR-002 looks like a heading but is a comment\n```\n"
        "### PY-COR-003: Silent\n"
    )
    assert heading_anchors(document) == {
        "PY-COR-001": "py-cor-001-mutable-default-argument",
        "PY-COR-003": "py-cor-003-silent",
    }


# ---- completeness ------------------------------------------------------------


def test_frozen_anchor_map_equals_the_headings_of_rules_md():
    parsed = heading_anchors(RULES_MD.read_text(encoding="utf-8"))
    missing = [rule_id for rule_id in builtin_rule_ids() if rule_id not in parsed]
    assert missing == [], f"rules without a RULES.md heading: {missing}"

    expected = {rule_id: parsed[rule_id] for rule_id in builtin_rule_ids()}
    assert dict(_RULE_ANCHORS) == expected


def test_every_security_rule_has_its_own_heading():
    parsed = heading_anchors(RULES_MD.read_text(encoding="utf-8"))
    security = [rule_id for rule_id in builtin_rule_ids() if "-SEC-" in rule_id]
    assert len(security) == 27
    for rule_id in security:
        title = rule_metadata(rule_id).title
        assert parsed[rule_id] == github_slug(f"{rule_id}: {title}", {}), rule_id


def test_security_subsections_carry_the_metadata_facts():
    """The generated ``###`` sections mirror RuleMetadata, never invent."""
    document = RULES_MD.read_text(encoding="utf-8")
    for rule_id in builtin_rule_ids():
        if "-SEC-" not in rule_id:
            continue
        metadata = rule_metadata(rule_id)
        heading = f"### {rule_id}: {metadata.title}\n"
        assert heading in document, heading
        section = document.split(heading, 1)[1].split("\n### ", 1)[0]
        for cwe in metadata.cwe:
            assert cwe in section, (rule_id, cwe)
        assert metadata.security_severity in section, rule_id
        assert metadata.remediation in section, rule_id
        for condition in metadata.not_when:
            assert condition in section, (rule_id, condition)


def test_removing_one_heading_fails_completeness():
    document = RULES_MD.read_text(encoding="utf-8")
    heading = "## PY-COR-001: Mutable default argument\n"
    assert heading in document
    parsed = heading_anchors(document.replace(heading, "", 1))

    assert "PY-COR-001" not in parsed
    assert dict(_RULE_ANCHORS) != {
        rule_id: parsed.get(rule_id) for rule_id in builtin_rule_ids()
    }


# ---- help_url ----------------------------------------------------------------


def test_help_url_pins_the_release_tag_and_the_heading_anchor():
    assert help_url("PY-COR-001", "3.4.2") == (
        f"{_URL_PREFIX}3.4.2/docs/RULES.md#py-cor-001-mutable-default-argument"
    )
    assert help_url("C-DUP-001", "9.9.9") == (
        f"{_URL_PREFIX}9.9.9/docs/RULES.md#"
        "go-dup-001--c-dup-001-duplicate-function-implementation-requires-deep"
    )


def test_help_url_fails_closed_for_an_unknown_rule():
    with pytest.raises(ValueError, match="PLUGIN-001"):
        help_url("PLUGIN-001", "3.4.2")


# ---- SARIF descriptor --------------------------------------------------------


@pytest.mark.parametrize("rule_id", ["PY-COR-001", "PY-SEC-002", "C-SEC-001"])
def test_descriptor_help_markdown_and_help_uri_are_metadata_derived(rule_id):
    metadata = rule_metadata(rule_id)
    descriptor = _rule_descriptor(metadata, "3.4.2")
    url = help_url(rule_id, "3.4.2")
    markdown = descriptor["help"]["markdown"]

    assert descriptor["helpUri"] == url
    assert descriptor["help"]["text"] == metadata.remediation
    assert markdown.startswith(f"**{metadata.title}** (`{rule_id}`)")
    assert metadata.description in markdown
    assert metadata.remediation in markdown
    for cwe in metadata.cwe:
        assert cwe in markdown
    for condition in metadata.not_when:
        assert f"- {condition}" in markdown
    assert markdown.rstrip().endswith(f"[{rule_id} in the rule reference]({url})")


def test_descriptor_without_cwe_omits_the_cwe_line():
    markdown = _rule_descriptor(rule_metadata("PY-MAINT-001"), "3.4.2")["help"]["markdown"]
    assert "CWE" not in markdown


def test_descriptor_defaults_to_the_package_version():
    descriptor = _rule_descriptor(rule_metadata("PY-COR-001"))
    assert descriptor["helpUri"] == help_url("PY-COR-001", __version__)


def test_every_builtin_rule_renders_a_descriptor_with_both_help_fields():
    for rule_id in builtin_rule_ids():
        descriptor = _rule_descriptor(rule_metadata(rule_id), __version__)
        assert descriptor["helpUri"].startswith(_URL_PREFIX), rule_id
        assert descriptor["help"]["markdown"].rstrip().endswith(")"), rule_id


def test_cli_sarif_links_rules_to_the_running_version(project):
    document = _sarif(project(SAMPLE))
    rules = document["runs"][0]["tool"]["driver"]["rules"]

    assert [rule["id"] for rule in rules] == ["PY-COR-001", "PY-SEC-002"]
    for rule in rules:
        assert rule["helpUri"] == help_url(rule["id"], __version__)
        assert rule["helpUri"] in rule["help"]["markdown"]


@pytest.mark.parametrize("flag", ["--anonymize", "--redact-paths"])
def test_privacy_flags_leave_help_and_help_uri_unchanged(project, flag):
    root = project(SAMPLE)
    plain = _sarif(root)["runs"][0]["tool"]["driver"]["rules"]
    private = _sarif(root, flag)["runs"][0]["tool"]["driver"]["rules"]

    assert [rule["id"] for rule in private] == [rule["id"] for rule in plain]
    assert [rule["help"] for rule in private] == [rule["help"] for rule in plain]
    assert [rule["helpUri"] for rule in private] == [rule["helpUri"] for rule in plain]
    assert str(root) not in json.dumps(private)
