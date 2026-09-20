"""Security rules shared by the regex-language adapters (``*-SEC-*``).

Every rule here fires on a *call shape* or a *literal* the lexer can see —
never on where a value came from. That is the honest boundary for a bounded
lexer: ``system(cmd)`` with a non-literal ``cmd`` is reportable, "user input
reaches ``open()``" is not (that needs taint tracking, which Semgrep and
CodeQL own). Each rule is anchored to a CWE and carries a SARIF
``security-severity`` so code-scanning UIs rank it as a security alert.

Three detector shapes cover the family:

* :func:`marker_findings` — a pattern on blanked ``code_text`` is the whole
  defect (``InsecureSkipVerify: true``, ``new BinaryFormatter(``).
* :func:`dynamic_call_findings` — a call whose *n*-th argument must be
  non-literal, optionally with other arguments pinned to literal values
  (``exec.Command("sh", "-c", <dynamic>)``).
* :func:`secret_random_findings` — a non-cryptographic random call bound to
  a secret-shaped name.

Arguments are classified on the original source: a literal is a quoted
string (with the language's prefixes) followed by nothing else in its
argument slot; a literal followed by ``+``, or carrying interpolation
(``${x}``, Kotlin ``$x``, C# ``$"{x}"``), is *dynamic*.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..findings import Finding, Location
from ..protocols import ParsedFile
from ._parity import downgrade_in_tests
from ._shared import line_column
from ._sql import PREFIXED_QUOTE, find_closer

Interpolates = Callable[[str, str, str], bool]

_SEGMENT = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")

_SECRET_SEGMENTS = frozenset(
    {
        "token",
        "tokens",
        "secret",
        "secrets",
        "password",
        "passwd",
        "passphrase",
        "nonce",
        "salt",
        "otp",
        "apikey",
        "csrf",
        "sessionid",
    }
)
_SECRET_PAIRS = frozenset(
    {
        ("api", "key"),
        ("session", "id"),
        ("session", "key"),
        ("auth", "code"),
        ("verification", "code"),
        ("reset", "code"),
    }
)
_QUANTITY_SEGMENTS = frozenset(
    {
        "max",
        "min",
        "num",
        "count",
        "len",
        "length",
        "size",
        "index",
        "idx",
        "per",
        "rate",
        "limit",
        "budget",
        "delay",
        "timeout",
        "ttl",
        "rounds",
        "offset",
        "position",
        "pos",
    }
)


def is_secret_name(name: str) -> bool:
    """Whether ``name`` is an identifier that holds a security-relevant value.

    Identifiers are split into snake/camel segments and matched as WHOLE
    segments (``reset_token``, ``sessionKey``, ``API_KEY``), never as
    substrings: ``max_tokens``, ``footprint`` and ``hotplug_delay`` used to
    fire on ``token``/``otp``. A name that also carries a quantity or position
    word (``max_tokens``, ``token_index``, ``salt_rounds``) is a count, not a
    secret, and stays silent. Kept deliberately short: a broad list is how
    ``random``-for-secrets rules earn their reputation.
    """
    segments = [segment.lower() for segment in _SEGMENT.findall(name)]
    if not segments or _QUANTITY_SEGMENTS.intersection(segments):
        return False
    if _SECRET_SEGMENTS.intersection(segments):
        return True
    return any(pair in _SECRET_PAIRS for pair in zip(segments, segments[1:], strict=False))


SHELL_BINARIES = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/zsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
    },
)
SHELL_COMMAND_FLAGS = frozenset({"-c", "/c", "/C", "-Command"})


def _location(parsed: ParsedFile, offset: int) -> Location:
    line, column = line_column(parsed.facts.code_text, offset)
    return Location(
        path=parsed.source.display_path,
        line=line,
        column=column,
        identity_path=parsed.source.identity_path,
    )


def security_finding(
    rule_id: str,
    parsed: ParsedFile,
    offset: int,
    message: str,
    remediation: str,
    *,
    confidence: str = "high",
    in_tests: str = "warning",
) -> Finding:
    """Build a ``security`` finding; ``in_tests="note"`` applies the
    idiom-in-tests downgrade used by the correctness parity rules."""
    finding = Finding(
        rule_id=rule_id,
        category="security",
        severity="warning",
        confidence=confidence,
        message=message,
        location=_location(parsed, offset),
        remediation=remediation,
    )
    return downgrade_in_tests(parsed, finding) if in_tests == "note" else finding


# ---- argument classification ------------------------------------------------


def split_arguments(code_text: str, open_paren: int) -> tuple[list[tuple[int, int]], int]:
    """Split a call's arguments at top-level commas.

    Returns ``([(start, end), ...], close)`` where spans index ``code_text``
    (and, offsets being 1:1, the source) and ``close`` is the offset of the
    matching ``)``. Strings are blanked in ``code_text`` so commas inside
    them cannot split. Unbalanced input yields what was seen up to the end.
    """
    spans: list[tuple[int, int]] = []
    depth = 0
    start = open_paren + 1
    index = start
    length = len(code_text)
    while index < length:
        char = code_text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                spans.append((start, index))
                return spans, index
            depth -= 1
        elif char == "," and depth == 0:
            spans.append((start, index))
            start = index + 1
        index += 1
    spans.append((start, length))
    return spans, length


@dataclass(frozen=True, slots=True)
class Argument:
    """Classification of one argument slot."""

    kind: str
    """``"literal"``, ``"dynamic"`` or ``"empty"``."""
    text: str | None = None
    """Literal content without quotes (``kind == "literal"`` only)."""


def _trim(source: str, span: tuple[int, int]) -> tuple[int, int]:
    start, end = span
    while start < end and source[start] in " \t\r\n":
        start += 1
    while end > start and source[end - 1] in " \t\r\n":
        end -= 1
    return start, end


def _read_literal(source: str, start: int, end: int) -> tuple[str, str, str, int] | None:
    """Read one quoted literal at ``start``: ``(delimiter, prefix, content, close)``."""
    prefixed = PREFIXED_QUOTE.match(source, start, end)
    if prefixed is None or prefixed.start() != start:
        return None
    quote = prefixed.start(1)
    current = source[quote]
    delimiter = current * 3 if source.startswith(current * 3, quote) else current
    close = find_closer(source, quote + len(delimiter), end, delimiter)
    if close is None:
        return None
    prefix = source[start:quote]
    hashes = prefix.count("#")  # Rust ``r#"..."#`` closes on the quote *and* the hashes
    while hashes and source[close : close + hashes] != "#" * hashes:
        close = find_closer(source, close, end, delimiter)
        if close is None:
            return None
    content = source[quote + len(delimiter) : close - len(delimiter)]
    return delimiter, prefix, content, close + hashes


def _absorb_adjacent_literals(
    source: str, close: int, end: int, content: str
) -> tuple[str, int] | None:
    """C/C++ ``"a" "b"`` concatenation (with ``#ifdef`` lines allowed between
    pieces) is still one literal; returns the joined content and new close, or
    ``None`` if a piece is unterminated."""
    while True:
        rest = source[close:end].lstrip()
        if rest.startswith("#"):
            newline = source.find("\n", close)
            if newline < 0 or newline >= end:
                return None
            close = newline + 1
            continue
        if not rest or rest[0] not in "\"'":
            return content, close
        next_start = end - len(rest)
        next_close = find_closer(source, next_start + 1, end, rest[0])
        if next_close is None:
            return None
        content += source[next_start + 1 : next_close - 1]
        close = next_close


def classify_argument(
    parsed: ParsedFile,
    span: tuple[int, int],
    interpolates: Interpolates | None = None,
) -> Argument:
    """Classify the source in ``span`` as a plain literal, dynamic, or empty."""
    source = parsed.source.content
    start, end = _trim(source, span)
    if start >= end:
        return Argument("empty")
    literal = _read_literal(source, start, end)
    if literal is None:
        return Argument("dynamic")
    delimiter, prefix, content, close = literal
    absorbed = _absorb_adjacent_literals(source, close, end, content)
    if absorbed is None:
        return Argument("dynamic")
    content, close = absorbed
    if source[close:end].strip():
        return Argument("dynamic")  # ``"..." + x``, ``"...".format(x)``, ...
    if interpolates is not None and interpolates(delimiter, prefix, content):
        return Argument("dynamic")
    return Argument("literal", content)


# ---- detector shapes --------------------------------------------------------


def marker_findings(
    rule_id: str,
    parsed: ParsedFile,
    pattern: re.Pattern,
    message: str,
    remediation: str,
    *,
    confidence: str = "high",
    in_tests: str = "warning",
) -> Iterable[Finding]:
    """One finding per line where ``pattern`` matches the blanked code."""
    code_text = parsed.facts.code_text
    seen_lines: set[int] = set()
    for match in pattern.finditer(code_text):
        line = code_text.count("\n", 0, match.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        yield security_finding(
            rule_id,
            parsed,
            match.start(),
            message,
            remediation,
            confidence=confidence,
            in_tests=in_tests,
        )


@dataclass(frozen=True, slots=True)
class DynamicCall:
    """A call whose ``dynamic`` argument must be non-literal to report.

    ``pinned`` maps argument index to the literal values that must appear
    there (``{0: SHELL_BINARIES, 1: SHELL_COMMAND_FLAGS}``); a call whose
    pinned slots hold anything else is not this shape and stays silent.
    """

    call: re.Pattern
    """Matches the callee on blanked code, ending right before ``(``."""
    dynamic: int
    pinned: dict[int, frozenset[str]] | None = None
    interpolates: Interpolates | None = None
    requires: str | None = None
    """Regex that must also match somewhere inside the argument list
    (``shell\\s*:\\s*true`` for ``spawn``)."""
    confidence: str = "medium"
    in_tests: str = "warning"
    """``"note"`` applies the idiom-in-tests downgrade to findings of this shape."""

    def matches(self, parsed: ParsedFile, open_paren: int) -> bool:
        """True when the call whose ``(`` is at ``open_paren`` has this shape."""
        return _dynamic_call_matches(self, parsed, open_paren)


def dynamic_call_findings(
    rule_id: str,
    parsed: ParsedFile,
    spec: DynamicCall,
    message: str,
    remediation: str,
    *,
    skip_at: Callable[[str, int], bool] | None = None,
) -> Iterable[Finding]:
    """Report calls matching ``spec``; ``skip_at(code_text, offset)`` may veto
    a match (C uses it to ignore declarations such as ``int system(``)."""
    code_text = parsed.facts.code_text
    for match in spec.call.finditer(code_text):
        if skip_at is not None and skip_at(code_text, match.start()):
            continue
        if spec.matches(parsed, match.end()):
            yield security_finding(
                rule_id,
                parsed,
                match.start(),
                message,
                remediation,
                confidence=spec.confidence,
                in_tests=spec.in_tests,
            )


def _is_declaration_tail(code_text: str, close: int) -> bool:
    """``eval(script: string): T`` / ``void exec(String cmd) {`` declare a
    method named like the sink; a call expression is never followed by a
    block or a type annotation."""
    after = code_text[close + 1 : close + 40].lstrip()
    return after[:1] in {"{", ":"}


def _pinned_match(parsed: ParsedFile, spans: list, pinned: dict[int, frozenset[str]]) -> bool:
    for index, values in pinned.items():
        if index >= len(spans):
            return False
        argument = classify_argument(parsed, spans[index])
        if argument.kind != "literal" or argument.text not in values:
            return False
    return True


def _dynamic_call_matches(spec: DynamicCall, parsed: ParsedFile, open_paren: int) -> bool:
    code_text = parsed.facts.code_text
    if open_paren >= len(code_text) or code_text[open_paren] != "(":
        return False
    spans, close = split_arguments(code_text, open_paren)
    if spec.dynamic >= len(spans) or _is_declaration_tail(code_text, close):
        return False
    if spec.pinned and not _pinned_match(parsed, spans, spec.pinned):
        return False
    if classify_argument(parsed, spans[spec.dynamic], spec.interpolates).kind != "dynamic":
        return False
    if spec.requires and re.search(spec.requires, code_text[open_paren:close]) is None:
        return False
    return True


def secret_random_findings(
    rule_id: str,
    parsed: ParsedFile,
    random_call: re.Pattern,
    *,
    assignment: re.Pattern,
    message: str,
    remediation: str,
) -> Iterable[Finding]:
    """Report ``<secret-shaped name> = ... <random call> ...`` statements.

    ``assignment`` matches a binding with a named group ``name`` and ends at
    the start of the assigned expression; the expression runs to the end of
    the statement (``;`` or newline at depth 0). ``random_call`` is searched
    within it. Callers decide whether the file imports a non-cryptographic
    random module at all before invoking this.
    """
    code_text = parsed.facts.code_text
    for match in assignment.finditer(code_text):
        name = match.group("name")
        if not is_secret_name(name):
            continue
        end = _statement_end(code_text, match.end())
        expression = code_text[match.end() : end]
        if random_call.search(expression) is None:
            continue
        yield security_finding(
            rule_id,
            parsed,
            match.start("name"),  # not match.start(): a leading `{` sits on the previous line
            message,
            remediation,
            confidence="medium",
        )


def _statement_end(code_text: str, start: int) -> int:
    depth = 0
    for index in range(start, len(code_text)):
        char = code_text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth <= 0 and char in ";\n":
            return index
    return len(code_text)


# ---- comment-adjacent checks (Rust SAFETY) ----------------------------------


def preceding_comment_block(source: str, offset: int) -> str:
    """Return the comment lines immediately above the line at ``offset``,
    plus that line's own trailing comment and the first line after it.

    Used for conventions like Rust's ``// SAFETY:`` which may sit above the
    ``unsafe`` block, on its line, or as the first line inside it.
    """
    lines = source.splitlines()
    line_index = source.count("\n", 0, offset)
    collected: list[str] = []
    cursor = line_index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if stripped.startswith(("//", "/*", "*", "#[")) or stripped.endswith("*/"):
            collected.append(stripped)
            cursor -= 1
            continue
        break
    if line_index < len(lines):
        collected.append(lines[line_index])
    if line_index + 1 < len(lines):
        collected.append(lines[line_index + 1])
    return "\n".join(collected)
