"""Correctness rules that mirror the Python catalog in the regex languages.

Python has had broad-catch (PY-COR-002), silent-swallow (PY-COR-003) and
blocking-in-async (PY-COR-005) rules since 2.x; every other language had only
"empty catch". Stack Overflow's most-voted questions per language tag show the
same defect classes are the top concerns there too ("Catch multiple
exceptions at once" for C#, "Proper use of IDisposable", Kotlin's
``runBlocking`` questions, TypeScript's ``!`` operator). These helpers give
each regex adapter the same rules with the same grading, on blanked text.

All helpers operate on ``facts.code_text`` (strings and comments blanked,
offsets preserved), so brace matching is exact and literals are never
evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace

from ..findings import Finding, Location
from ..protocols import ParsedFile
from ._shared import line_column

_THROW = re.compile(r"\b(?:throw|rethrow)\b")


def _location(parsed: ParsedFile, offset: int) -> Location:
    line, column = line_column(parsed.facts.code_text, offset)
    return Location(
        path=parsed.source.display_path,
        line=line,
        column=column,
        identity_path=parsed.source.identity_path,
    )


def block_end(code_text: str, open_brace: int) -> int:
    """Return the offset just past the ``}`` matching ``open_brace``.

    ``code_text`` has strings and comments blanked, so counting braces is
    exact. Falls back to end-of-text for unbalanced input.
    """
    depth = 0
    for index in range(open_brace, len(code_text)):
        char = code_text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(code_text)


def strip_nested_blocks(body: str, opener: re.Pattern) -> str:
    """Blank nested function/lambda bodies so their contents are not counted.

    ``opener`` matches the construct that introduces a nested scope *up to and
    including* its opening brace (``func(...) {`` in Go, ``=> {`` or
    ``function ... {`` in TypeScript); the brace block is replaced by spaces
    of equal length so offsets stay valid. Braceless arrow expressions are
    left alone by construction.
    """
    output = list(body)
    for match in opener.finditer(body):
        brace = match.end() - 1
        if body[brace] != "{":
            continue
        end = block_end(body, brace)
        for index in range(brace, end):
            if output[index] != "\n":
                output[index] = " "
    return "".join(output)


def broad_catch_findings(
    rule_id: str,
    parsed: ParsedFile,
    pattern: re.Pattern,
    *,
    caught_group: str = "type",
) -> Iterable[Finding]:
    """Report catch clauses that take every (or nearly every) exception.

    ``pattern`` must match the whole ``catch (...) {`` header on blanked text
    with a named group ``caught_group`` describing what is caught (or an
    empty string for a bare catch). Bodies that rethrow are graded ``note``:
    wrap-and-rethrow is an accepted idiom, while catch-and-continue is the
    defect PY-COR-002 exists for.
    """
    code_text = parsed.facts.code_text
    for match in pattern.finditer(code_text):
        open_brace = code_text.index("{", match.start())
        body = code_text[open_brace + 1 : block_end(code_text, open_brace) - 1]
        rethrows = _THROW.search(body) is not None
        caught = match.group(caught_group) or "all exceptions"
        yield Finding(
            rule_id=rule_id,
            category="correctness",
            severity="note" if rethrows else "warning",
            confidence="high",
            message=(
                f"Exception handler catches {caught} and rethrows; confirm the "
                "wrap is intentional."
                if rethrows
                else f"Exception handler catches {caught}."
            ),
            location=_location(parsed, match.start()),
            remediation="Catch the narrow exception types the operation can recover from.",
        )


def blocking_in_async_findings(
    rule_id: str,
    parsed: ParsedFile,
    *,
    async_header: re.Pattern,
    blocking_call: re.Pattern,
    nested_opener: re.Pattern | None = None,
    what: str,
) -> Iterable[Finding]:
    """Report synchronous blocking calls inside asynchronous bodies.

    ``async_header`` matches the declaration up to (not including) the opening
    brace; ``blocking_call`` is searched inside the body with nested scopes
    (``nested_opener``) blanked first so a sync call inside a lambda passed to
    the async function is not attributed to it.
    """
    code_text = parsed.facts.code_text
    seen: set[int] = set()
    for header in async_header.finditer(code_text):
        open_brace = code_text.find("{", header.end())
        if open_brace < 0:
            continue
        # Expression-bodied members (C# ``=> ...;``) and abstract signatures
        # have a ``;`` before any brace: they own no block.
        between = code_text[header.end() : open_brace]
        if ";" in between:
            continue
        # Search from the end of the header so Kotlin's expression body
        # ``suspend fun f() = runBlocking { ... }`` is seen as well. Nested
        # scopes are blanked only *inside* the declaration's own block so an
        # async lambda's body is not mistaken for a nested scope of itself.
        region_start = header.end()
        end = block_end(code_text, open_brace)
        prefix = code_text[region_start : open_brace + 1]
        body = code_text[open_brace + 1 : end]
        if nested_opener is not None:
            body = strip_nested_blocks(body, nested_opener)
        region = prefix + body
        for call in blocking_call.finditer(region):
            offset = region_start + call.start()
            if offset in seen:
                continue
            seen.add(offset)
            yield Finding(
                rule_id=rule_id,
                category="correctness",
                severity="warning",
                confidence="medium",
                message=f"{what} blocks inside an asynchronous body.",
                location=_location(parsed, offset),
                remediation=(
                    "Await the asynchronous form of the call, or move the "
                    "blocking work off the async path."
                ),
            )


NON_NULL_LIMIT = 4
"""A file may use up to this many non-null assertions before it is reported."""


def non_null_density_findings(
    rule_id: str,
    parsed: ParsedFile,
    pattern: re.Pattern,
    *,
    operator: str,
) -> Iterable[Finding]:
    """Report a file that leans on non-null assertions (``!`` / ``!!``).

    One finding per file, anchored on the first assertion, once the count
    exceeds :data:`NON_NULL_LIMIT`. Each assertion switches off the type
    checker's null safety at that point; a handful is a local judgement call,
    a file full of them is a design signal ("the `!` operator" is the
    4th-most-voted TypeScript question on Stack Overflow).
    """
    matches = list(pattern.finditer(parsed.facts.code_text))
    if len(matches) <= NON_NULL_LIMIT:
        return
    yield Finding(
        rule_id=rule_id,
        category="correctness",
        severity="warning",
        confidence="medium",
        message=(
            f"File uses {len(matches)} non-null assertions ({operator}) "
            f"(limit {NON_NULL_LIMIT})."
        ),
        location=_location(parsed, matches[0].start()),
        remediation=(
            "Narrow the type with a check or early return instead of asserting; "
            "keep assertions to the few places the invariant is documented."
        ),
    )


_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|e2e|integration|testdata)(?:/|$)|"
    r"(?:_test\.go|\.(?:test|spec)\.[cm]?[jt]sx?|Tests?\.(?:kt|cs|java)|"
    r"(?:^|/)test_[^/]*\.py)$",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    """True for paths that conventionally hold tests (Go ``_test.go``, TS
    ``*.spec.ts``, JVM ``*Test.kt``, ``tests/`` and ``__tests__/`` trees)."""
    return _TEST_PATH.search(path.replace("\\", "/")) is not None


def downgrade_in_tests(parsed: ParsedFile, finding: Finding) -> Finding:
    """Grade an idiom-in-tests finding as ``note`` when the file is a test.

    Unchecked assertions and non-null operators are the idiomatic way to
    write compact test bodies (calibration: 100 % of go-redis's 209 unchecked
    assertions and most of ktor's ``!!`` density were in tests). The finding
    stays visible; it just carries no warning weight.
    """
    path = parsed.source.identity_path or parsed.source.display_path
    if finding.severity == "warning" and is_test_path(path):
        return replace(finding, severity="note")
    return finding
