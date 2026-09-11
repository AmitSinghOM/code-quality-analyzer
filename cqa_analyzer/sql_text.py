"""Decide whether a string literal is the start of a SQL statement.

Shared by the Python AST rule (PY-COR-007) and the token-based detector used
by every other language, so the definition of "looks like SQL" is identical
everywhere and can be tuned in one place.

Precision comes from two requirements, not one:

1. The literal starts with a statement keyword (``SELECT``, ``INSERT INTO``,
   ``UPDATE`` ...).
2. A clause keyword follows (``FROM``, ``WHERE``, ``SET``, ``VALUES`` ...) and
   both keywords use the *same* case (all upper or all lower). Prose such as
   ``"Select an item from the list"`` mixes case and is rejected; code writes
   ``SELECT ... FROM`` or ``select ... from``.
"""

from __future__ import annotations

import re

_STATEMENT = (
    r"(?P<stmt>SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|"
    r"REPLACE\s+INTO|WITH(?=\s+\w+\s+AS\s*\()|CREATE\s+(?:TABLE|INDEX|VIEW)|"
    r"DROP\s+(?:TABLE|INDEX|VIEW)|ALTER\s+TABLE|TRUNCATE\s+TABLE)"
)
_CLAUSE = (
    r"(?P<clause>FROM|WHERE|SET|VALUES|JOIN|INTO|TABLE|INDEX|VIEW|AS|"
    r"ADD|RENAME|ORDER\s+BY|GROUP\s+BY|LIMIT|RETURNING)"
)
_SQL_SHAPE = re.compile(
    rf"^\s*{_STATEMENT}\b.*?\b{_CLAUSE}\b",
    re.IGNORECASE | re.DOTALL,
)

# Placeholders that mean "a runtime value is substituted *by string
# formatting*" — as opposed to driver parameters (``?``, ``$1``, ``:name``,
# ``@p``) which are safe and never trigger a finding on their own.
FORMAT_PLACEHOLDER = re.compile(
    r"%[-+ 0#]*\d*(?:\.\d+)?[sdivqxXfF]|\{[\w.\[\]]*(?::[^{}]*)?\}"
)


def _same_case(first: str, second: str) -> bool:
    letters_first = "".join(ch for ch in first if ch.isalpha())
    letters_second = "".join(ch for ch in second if ch.isalpha())
    return (letters_first.isupper() and letters_second.isupper()) or (
        letters_first.islower() and letters_second.islower()
    )


def is_sql_statement(text: str) -> bool:
    """Return True when ``text`` reads as the head of a SQL statement."""
    match = _SQL_SHAPE.match(text)
    if match is None:
        return False
    return _same_case(match.group("stmt"), match.group("clause"))


def has_format_placeholder(text: str) -> bool:
    """Return True when ``text`` carries printf/brace formatting slots."""
    return FORMAT_PLACEHOLDER.search(text) is not None
