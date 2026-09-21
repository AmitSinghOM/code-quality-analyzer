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


def suppressions(source: str) -> dict[tuple[int, str], str]:
    """Return ``{(line, rule_id): reason}`` for every valid directive."""
    found: dict[tuple[int, str], str] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            match = _DIRECTIVE.fullmatch(token.string.strip())
            if match is None:
                continue
            reason = (match.group("double") or match.group("single") or "").strip()
            if not reason:
                continue
            for rule_id in match.group("rules").split(","):
                found[(token.start[0], rule_id.strip())] = reason
    except (IndentationError, tokenize.TokenError):
        return {}
    return found


def suppression_lines(source: str) -> frozenset[tuple[int, str]]:
    """Return valid ``(line, rule_id)`` suppressions without reason text."""
    return frozenset(suppressions(source))


def comment_lines(source: str) -> frozenset[int]:
    """Return every line number that carries a comment token.

    Used to recognise documented intent (``except Exception: pass  # best
    effort``) the same way the regex-language empty-catch rules do.
    """
    lines = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                lines.add(token.start[0])
    except (tokenize.TokenError, SyntaxError):
        return frozenset(lines)
    return frozenset(lines)
