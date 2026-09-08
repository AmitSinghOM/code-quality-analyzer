"""Reason-required, comment-only suppressions for Python findings."""

from __future__ import annotations

import io
import re
import tokenize

_DIRECTIVE = re.compile(
    r"^#\s*cqa:\s*ignore="
    r"(?P<rules>[A-Z][A-Z0-9-]*(?:\s*,\s*[A-Z][A-Z0-9-]*)*)"
    r"\s+reason=(?:\"(?P<double>[^\"\r\n]+)\"|"
    r"'(?P<single>[^'\r\n]+)')\s*$"
)


def suppression_lines(source: str) -> frozenset[tuple[int, str]]:
    """Return valid ``(line, rule_id)`` suppressions without reason text."""
    suppressions = set()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            match = _DIRECTIVE.fullmatch(token.string.strip())
            if match is None:
                continue
            reason = match.group("double") or match.group("single") or ""
            if not reason.strip():
                continue
            for rule_id in match.group("rules").split(","):
                suppressions.add((token.start[0], rule_id.strip()))
    except (IndentationError, tokenize.TokenError):
        return frozenset()
    return frozenset(suppressions)
