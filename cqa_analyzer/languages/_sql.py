"""Detect SQL statements assembled from runtime values (shared, token based).

Every regex-language adapter blanks string and comment contents in
``facts.code_text`` while preserving offsets 1:1 with ``source.content``
(verified per adapter in ``tests/test_sql_rules.py``). That gives a cheap,
parser-free way to find string literals: a maximal run of blanked
characters whose first original character is a quote. The detector reads the
*original* literal, asks :mod:`cqa_analyzer.sql_text` whether it is the head
of a SQL statement, and then checks the three ways a runtime value can be
spliced in:

* string interpolation inside the literal (language specific: Kotlin ``$x``,
  TypeScript template ``${x}``, C# ``$"...{x}"``);
* ``+`` concatenation with a non-literal operand on either side;
* the literal being an argument of a formatting call (``String.format``,
  ``fmt.Sprintf``, ``snprintf`` ...) *and* carrying a format placeholder.

Driver parameters (``?``, ``$1``, ``:name``, ``@p``) never trigger a finding.
The rule is deliberately narrow: it reports how the statement is *built*, not
where it is executed, so a dynamically built query that is later passed to a
prepared-statement API is still reported — the string itself is the hazard.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..findings import Finding, Location
from ..protocols import ParsedFile
from ..sql_text import has_format_placeholder, is_sql_statement
from ._shared import line_column

_QUOTES = frozenset('"\'`')

# ``+`` on the right with a non-literal operand: ``"SELECT ..." + id``. An
# optional ``)`` lets ``std::string("SELECT ...") + id`` through.
_CONCAT_RIGHT = re.compile(r"^\s*\)?\s*\+\s*(?=[A-Za-z_(\[])")
# ``+`` on the left with a non-literal operand: ``prefix + "SELECT ..."``.
_CONCAT_LEFT = re.compile(r"[A-Za-z0-9_)\]]\s*\+\s*\(?\s*$")
# Literal prefixes the adapters blank together with the quote: C# ``$``/``@``
# (interpolated/verbatim), Rust ``r#``/``b``/``br#`` (raw/byte strings).
_PREFIXED_QUOTE = re.compile(r'(?:\$@|@\$|\$|@|br#*|r#*|b)?(["\'`])')


@dataclass(frozen=True, slots=True)
class SqlSyntax:
    """Per-language knobs for the detector."""

    interpolates: Callable[[str, str, str], bool]
    """``(delimiter, prefix, content) -> bool`` — literal has interpolation.
    ``prefix`` is the (up to) two source characters before the delimiter."""

    format_call: re.Pattern | None
    """Matches ``code_text`` immediately *before* the literal when the literal
    is an argument of a formatting call (any earlier arguments allowed)."""

    format_method: re.Pattern | None = None
    """Matches ``code_text`` immediately *after* the literal for
    ``"...".format(x)`` / ``"...".formatted(x)`` styles."""

    concat_right: re.Pattern = _CONCAT_RIGHT
    """``+`` with a non-literal right operand; languages that need an adapter
    call between literal and ``+`` (Rust ``"…".to_string() + &id``) override."""


def _no_interpolation(delimiter: str, prefix: str, content: str) -> bool:
    return False


NO_INTERPOLATION = _no_interpolation


def _format_call(*names: str) -> re.Pattern:
    alternatives = "|".join(re.escape(name) for name in names)
    # ``name(`` followed by zero or more complete earlier arguments, ending
    # right before the literal. Arguments are approximated as comma-free
    # runs without parentheses, which covers ``snprintf(buf, n, "...")``.
    return re.compile(rf"(?:{alternatives})\s*\(\s*(?:[^,()]*,\s*)*$")


def _find_closer(source: str, start: int, limit: int, delimiter: str) -> int | None:
    """Return the offset just past the closing ``delimiter`` or ``None``.

    Backslash escapes are honoured for single-character delimiters; triple
    quotes (Java/Kotlin text blocks) close on the next triple.
    """
    if len(delimiter) == 3:
        close = source.find(delimiter, start, limit)
        return None if close < 0 else close + 3
    index = start
    while index < limit:
        current = source[index]
        if current == "\\":
            index += 2
            continue
        if current == delimiter:
            return index + 1
        index += 1
    return None


def literal_spans(source: str, code_text: str) -> Iterable[tuple[int, int]]:
    """Yield ``(start, end)`` of string literals as offsets into ``source``.

    Blanked runs (``code_text`` is a space where ``source`` is not) hold
    strings and comments; within a run the *source* is scanned for the
    closing delimiter so a literal followed by a comment on the same line is
    split correctly. Multi-line literals are yielded as one span.
    """
    length = len(code_text)
    index = 0
    pending: tuple[int, str] | None = None  # (start, delimiter)
    pending_end = 0
    while index < length:
        if code_text[index] != " " or source[index] in " \t\r":
            index += 1
            continue
        run_start = index
        while index < length and code_text[index] == " " and source[index] != "\n":
            index += 1
        run_end = index
        if pending is not None and code_text[pending_end:run_start].strip():
            # Code intervened: the literal ended where the adapter stopped
            # blanking (unterminated literals never reach a rule pack).
            yield pending[0], pending_end
            pending = None
        position = run_start
        while position < run_end:
            if source[position] in " \t":
                position += 1
                continue
            if pending is not None:
                close = _find_closer(source, position, run_end, pending[1])
                if close is None:
                    pending_end = run_end
                    break
                yield pending[0], close
                pending = None
                position = close
                continue
            prefixed = _PREFIXED_QUOTE.match(source, position, run_end)
            if prefixed is None:
                break  # comment or directive: skip the rest of the run
            position = prefixed.start(1)  # step over a blanked prefix to the quote
            current = source[position]
            delimiter = current * 3 if source.startswith(current * 3, position) else current
            close = _find_closer(source, position + len(delimiter), run_end, delimiter)
            if close is None:
                pending = (position, delimiter)
                pending_end = run_end
                break
            yield position, close
            position = close
    if pending is not None:
        yield pending[0], pending_end


def dynamic_sql_offsets(
    source: str,
    code_text: str,
    syntax: SqlSyntax,
) -> list[tuple[int, str]]:
    """Return ``(offset, reason)`` for every dynamically built SQL literal."""
    hits: list[tuple[int, str]] = []
    seen_lines: set[int] = set()
    for start, end in literal_spans(source, code_text):
        delimiter = source[start]
        # ``strip`` handles triple-quoted text blocks (Java/Kotlin ``\"\"\"``)
        # as well as single delimiters.
        content = source[start:end].strip(delimiter)
        if not is_sql_statement(content):
            continue
        prefix = source[max(0, start - 2) : start]
        reason = None
        if syntax.interpolates(delimiter, prefix, content):
            reason = "string interpolation"
        elif syntax.concat_right.match(code_text[end:]) or (
            _CONCAT_LEFT.search(code_text[:start])
        ):
            reason = "string concatenation"
        elif has_format_placeholder(content) and (
            (syntax.format_call is not None and syntax.format_call.search(code_text[:start]))
            or (syntax.format_method is not None and syntax.format_method.match(code_text[end:]))
        ):
            reason = "string formatting"
        if reason is None:
            continue
        line = source.count("\n", 0, start) + 1
        if line in seen_lines:  # one finding per statement line
            continue
        seen_lines.add(line)
        hits.append((start, reason))
    return hits


def dynamic_sql_findings(
    rule_id: str,
    parsed: ParsedFile,
    syntax: SqlSyntax,
) -> Iterable[Finding]:
    """Build the shared finding for each dynamically built SQL literal."""
    code_text = parsed.facts.code_text
    source = parsed.source.content
    if len(code_text) != len(source):  # adapter contract broken: fail closed
        return
    for offset, reason in dynamic_sql_offsets(source, code_text, syntax):
        line, column = line_column(code_text, offset)
        yield Finding(
            rule_id=rule_id,
            category="correctness",
            severity="warning",
            confidence="medium",
            message=f"SQL statement is assembled with {reason}.",
            location=Location(
                path=parsed.source.display_path,
                line=line,
                column=column,
                identity_path=parsed.source.identity_path,
            ),
            remediation=(
                "Pass runtime values as driver parameters (bind variables); "
                "allowlist identifiers such as table or column names."
            ),
        )


# ---- per-language syntaxes -------------------------------------------------

def _kotlin_interpolates(delimiter: str, prefix: str, content: str) -> bool:
    return delimiter == '"' and re.search(r"(?<!\\)\$\{?[A-Za-z_]", content) is not None


def _typescript_interpolates(delimiter: str, prefix: str, content: str) -> bool:
    return delimiter == "`" and "${" in content


def _csharp_interpolates(delimiter: str, prefix: str, content: str) -> bool:
    # ``$"..."``, ``$@"..."`` and ``@$"..."`` all interpolate; a plain
    # verbatim ``@"..."`` does not. ``{{`` is an escaped brace, so require a
    # brace that opens a real hole.
    return "$" in prefix and re.search(r"(?<!\{)\{[A-Za-z_]", content) is not None


KOTLIN_SQL = SqlSyntax(
    interpolates=_kotlin_interpolates,
    format_call=_format_call("String.format"),
    format_method=re.compile(r"^\s*\.format\s*\("),
)
JAVA_SQL = SqlSyntax(
    interpolates=NO_INTERPOLATION,
    format_call=_format_call("String.format", "MessageFormat.format"),
    format_method=re.compile(r"^\s*\.formatted\s*\("),
)
TYPESCRIPT_SQL = SqlSyntax(
    interpolates=_typescript_interpolates,
    format_call=_format_call("util.format", "format", "sprintf"),
)
CSHARP_SQL = SqlSyntax(
    interpolates=_csharp_interpolates,
    format_call=_format_call("string.Format", "String.Format"),
)
GO_SQL = SqlSyntax(
    interpolates=NO_INTERPOLATION,
    format_call=_format_call("fmt.Sprintf", "fmt.Sprint", "fmt.Sprintln"),
)
RUST_SQL = SqlSyntax(
    interpolates=NO_INTERPOLATION,  # ``format!("{id}")`` is a formatting call below
    format_call=_format_call("format!", "write!", "writeln!", "print!", "println!"),
    concat_right=re.compile(
        r"^\s*(?:\.(?:to_string|to_owned|into)\(\))?\s*\+\s*(?=[&A-Za-z_(\[])"
    ),
)
C_SQL = SqlSyntax(
    interpolates=NO_INTERPOLATION,
    format_call=_format_call(
        "snprintf", "sprintf", "asprintf", "std::format", "fmt::format", "fmt::sprintf"
    ),
)
