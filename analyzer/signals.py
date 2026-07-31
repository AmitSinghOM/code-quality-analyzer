"""Per-file signal extraction.

Detection used to be ``keyword.lower() in whole_file.lower()``, which fired on
prose in docstrings and comments. Two things fix that:

  1. Comments and string literals are blanked out before any text matching, so
     "we should use Dijkstra here" in a docstring no longer counts.
  2. Bare words are matched against identifiers collected from the AST, not
     against raw text, so ``pop`` matches ``x.pop()`` but not ``population``.

Signals are per file. The previous scanner accumulated imports across the whole
project, so one ``import heapq`` anywhere made every later file look like it
used heaps.
"""

from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Iterable, Sequence

# Token types whose text must not be searched. FSTRING_MIDDLE only exists on
# Python 3.12+, where f-strings are tokenized into parts.
_LITERAL_TOKENS = {tokenize.STRING, tokenize.COMMENT}
_FSTRING_MIDDLE = getattr(tokenize, 'FSTRING_MIDDLE', None)
if _FSTRING_MIDDLE is not None:  # pragma: no branch
    _LITERAL_TOKENS.add(_FSTRING_MIDDLE)


@dataclass
class FileSignals:
    """Everything the pattern matcher is allowed to look at for one file."""

    path: Path
    line_count: int
    code_text: str = ""
    identifiers: set[str] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    parsed: bool = True
    literals_stripped: bool = True

    def has_identifier(self, name: str) -> bool:
        return name.lower() in self.identifiers

    def identifier_contains(self, fragment: str) -> bool:
        frag = fragment.lower()
        return any(frag in ident for ident in self.identifiers)

    def has_text(self, fragment: str) -> bool:
        return fragment.lower() in self.code_text

    def has_import(self, fragment: str) -> bool:
        frag = fragment.lower()
        return any(frag in imported for imported in self.imports)


def extract_signals(path: Path, source: str) -> FileSignals:
    """Build the signal set for one source file."""
    code_text, stripped = strip_comments_and_strings(source)
    signals = FileSignals(
        path=path,
        line_count=len(source.splitlines()),
        code_text=code_text.lower(),
        literals_stripped=stripped,
    )

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        signals.parsed = False
        return signals

    collector = _SymbolCollector()
    try:
        collector.visit(tree)
    except RecursionError:
        # Deeply nested source can blow the visitor stack. Keep what we have.
        signals.parsed = False

    signals.identifiers = collector.identifiers
    signals.imports = collector.imports
    return signals


def strip_comments_and_strings(source: str) -> tuple[str, bool]:
    """Blank out comments and string literals, preserving line/column layout.

    Returns ``(text, stripped_successfully)``. Layout is preserved so text
    patterns like ``root.left`` or ``mid =`` still match exactly as written.
    On a tokenizer error the original source is returned with ``False`` so the
    caller knows matches from this file are less trustworthy.
    """
    lines = source.splitlines()
    buffer: list[list[str]] = [list(line) for line in lines]

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return source, False

    for token in tokens:
        if token.type not in _LITERAL_TOKENS:
            continue
        _blank_region(buffer, token.start, token.end)

    return "\n".join("".join(row) for row in buffer), True


def _blank_region(
    buffer: list[list[str]],
    start: tuple[int, int],
    end: tuple[int, int],
) -> None:
    start_row, start_col = start
    end_row, end_col = end
    for row in range(start_row, end_row + 1):
        index = row - 1
        if not 0 <= index < len(buffer):
            continue
        line = buffer[index]
        lo = start_col if row == start_row else 0
        hi = end_col if row == end_row else len(line)
        for col in range(lo, min(hi, len(line))):
            line[col] = ' '


class _SymbolCollector(ast.NodeVisitor):
    """Collects identifiers and imports actually present in the syntax tree."""

    def __init__(self) -> None:
        self.identifiers: set[str] = set()
        self.imports: set[str] = set()

    def _add(self, name: str | None) -> None:
        if name:
            self.identifiers.add(name.lower())

    def visit_Name(self, node: ast.Name) -> None:
        self._add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._add(node.attr)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._add(node.name)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        self._add(node.arg)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> None:
        self._add(node.arg)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.lower())
            self._add(alias.asname or alias.name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = (node.module or '').lower()
        if module:
            self.imports.add(module)
        for alias in node.names:
            if module:
                self.imports.add(f"{module}.{alias.name.lower()}")
            self._add(alias.asname or alias.name)
        self.generic_visit(node)


# --------------------------------------------------------------------------
# Pattern normalization
# --------------------------------------------------------------------------

_SIGNAL_KEYS = ('identifiers', 'identifier_contains', 'text', 'imports')


def normalize_pattern(definition: dict) -> dict:
    """Accept both the current and the legacy ``keywords`` pattern schema.

    Legacy keywords are split by shape: a bare word becomes an identifier
    signal, anything containing punctuation becomes a text signal. That keeps
    externally defined pattern files working without reintroducing the
    match-anything-in-a-docstring behaviour.
    """
    normalized = {key: list(definition.get(key, ())) for key in _SIGNAL_KEYS}

    for keyword in definition.get('keywords', ()):
        if keyword.isidentifier():
            normalized['identifiers'].append(keyword)
        else:
            normalized['text'].append(keyword)

    normalized['weight'] = float(definition.get('weight', 1.0))
    normalized['description'] = definition.get('description', '')
    normalized['min_signals'] = max(1, int(definition.get('min_signals', 1)))
    return normalized


def match_pattern(signals: FileSignals, definition: dict) -> list[str]:
    """Return the list of distinct signals this file provides for a pattern.

    A pattern is considered present when ``len(result) >= min_signals``.
    Returning the list (rather than a bool) lets the report show *why* a
    pattern was reported, which makes false positives reviewable.
    """
    spec = normalize_pattern(definition)
    matched: list[str] = []

    for name in spec['identifiers']:
        if signals.has_identifier(name):
            matched.append(f"name:{name}")
    for fragment in spec['identifier_contains']:
        if signals.identifier_contains(fragment):
            matched.append(f"name~{fragment}")
    for fragment in spec['text']:
        if signals.has_text(fragment):
            matched.append(f"code:{fragment}")
    for module in spec['imports']:
        if signals.has_import(module):
            matched.append(f"import:{module}")

    return matched


def pattern_is_present(signals: FileSignals, definition: dict) -> tuple[bool, Sequence[str]]:
    """Convenience wrapper around :func:`match_pattern`."""
    matched = match_pattern(signals, definition)
    threshold = max(1, int(definition.get('min_signals', 1)))
    return len(matched) >= threshold, matched


def iter_signal_values(definition: dict) -> Iterable[str]:
    """All raw signal strings for a pattern — used by validation tests."""
    spec = normalize_pattern(definition)
    for key in _SIGNAL_KEYS:
        yield from spec[key]
