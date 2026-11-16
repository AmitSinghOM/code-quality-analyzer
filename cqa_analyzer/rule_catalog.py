"""Rule-catalog views for ``--explain RULE_ID`` and ``--list-rules`` (stdlib only).

Everything here is derived from :mod:`cqa_analyzer.rule_metadata`; nothing reads
the project under analysis, so no path, identifier or source text can leak.
"""

from __future__ import annotations

import difflib
import re

from . import __version__
from .plugins import create_default_registry
from .rule_metadata import RuleMetadata, builtin_rule_ids, rule_metadata

RULES_DOC_URL = "https://github.com/AmitSinghOM/code-quality-analyzer/blob/v{version}/docs/RULES.md"

_NON_ANCHOR_CHARS = re.compile(r"[^a-z0-9 _-]")


def github_anchor(heading: str) -> str:
    """GitHub's slug of a Markdown heading: lowercase, punctuation dropped, spaces to ``-``."""
    return _NON_ANCHOR_CHARS.sub("", heading.strip().lower()).replace(" ", "-")


def help_url(rule_id: str, version: str = __version__) -> str:
    """Link to the rule's section in ``docs/RULES.md``, pinned to the release tag.

    shortcut: the anchor assumes the rule has its own ``## <ID>: <Title>``
    heading; rules documented under a combined heading open the page top.
    Replace with the resolved-anchor helper once E3 (helpUri) lands.
    """
    meta = rule_metadata(rule_id)
    anchor = github_anchor(f"{meta.rule_id}: {meta.title}")
    return f"{RULES_DOC_URL.format(version=version)}#{anchor}"


def language_codes() -> tuple[str, ...]:
    """Language ids of the registered adapters, in lexical order."""
    return tuple(create_default_registry().capabilities()["languages"])


def resolve_rule(rule_id: str) -> RuleMetadata:
    """Return metadata for ``rule_id`` (case-insensitive) or raise ``LookupError``.

    The error message names the nearest catalog ids so a typo is a one-step fix.
    """
    wanted = rule_id.strip().upper()
    catalog = builtin_rule_ids()
    if wanted in catalog:
        return rule_metadata(wanted)
    close = difflib.get_close_matches(wanted, catalog, n=3, cutoff=0.6)
    hint = f"did you mean {', '.join(close)}?" if close else "run --list-rules for the catalog"
    raise LookupError(f"unknown rule id {rule_id!r}; {hint}")


def explain_lines(meta: RuleMetadata, version: str = __version__) -> list[str]:
    """Plain-text explanation of one rule, one field per line."""
    lines = [
        f"{meta.rule_id}: {meta.title}",
        f"  language:   {meta.language}",
        f"  family:     {meta.category}",
        f"  severity:   {meta.default_severity}",
        f"  confidence: {meta.confidence}",
    ]
    if meta.cwe:
        lines.append(f"  cwe:        {', '.join(meta.cwe)}")
    lines += ["", "  What it detects:", f"    {meta.description}"]
    lines += ["", "  Remediation:", f"    {meta.remediation}"]
    if meta.not_when:
        lines += ["", "  Not reported when:"]
        lines += [f"    - {condition}" for condition in meta.not_when]
    lines += ["", f"  Docs: {help_url(meta.rule_id, version)}"]
    return lines


def list_lines(language: str | None = None) -> list[str]:
    """One ``ID  severity  title`` line per built-in rule, optionally for one language."""
    rules = [rule_metadata(rule_id) for rule_id in builtin_rule_ids()]
    if language is not None:
        rules = [meta for meta in rules if meta.language == language]
    id_width = max((len(meta.rule_id) for meta in rules), default=0)
    severity_width = max((len(meta.default_severity) for meta in rules), default=0)
    return [
        f"{meta.rule_id:<{id_width}}  {meta.default_severity:<{severity_width}}  {meta.title}"
        for meta in rules
    ]
