"""Plain-text rendering for the CLI (stdlib only).

3.0 removed ``rich`` (docs/adr/004): a pure-stdlib core has nothing left to
rot, and a gate's text output must be identical in CI logs, in tests, on a
terminal and in a pipe. This module keeps the small vocabulary the CLI used
— ``console.print`` with inline style tags, ``Panel``, ``Table``,
``console.capture()`` — and renders it deterministically without colour.
Style tags such as ``[bold blue]`` are stripped; ``escape()`` protects
literal brackets in user-controlled text exactly as before.
"""

from __future__ import annotations

import io
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import IO, Any

# Inline style tags in the rich dialect: [bold blue], [/dim], [/], [yellow].
# A tag preceded by a backslash is an escaped literal bracket, not a tag.
_STYLE_TAG = re.compile(r"(?<!\\)\[/?(?:[a-zA-Z][\w#.\-]*(?: [a-zA-Z][\w#.\-]*)*)?\]")
_ESCAPED_BRACKET = re.compile(r"\\(\[)")


def escape(text: str) -> str:
    """Escape only brackets that would otherwise parse as a style tag.

    Mirrors the behaviour the CLI had: ``[31m`` is left alone (a tag must
    start with a letter or ``/``), ``[/i]`` becomes ``\\[/i]``.
    """
    return _STYLE_TAG.sub(lambda match: "\\" + match.group(0), text)


def strip_markup(text: str) -> str:
    """Remove style tags and unescape literal brackets."""
    return _ESCAPED_BRACKET.sub(r"\1", _STYLE_TAG.sub("", text))


@dataclass
class Panel:
    """A bordered block of text with an optional title."""

    renderable: str
    title: str | None = None
    border_style: str | None = None  # accepted for call-site compatibility; no colour in plain text
    expand: bool = True


@dataclass
class Table:
    """A simple grid: columns added first, then rows of strings."""

    title: str | None = None
    show_header: bool = True
    columns: list[dict[str, Any]] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)

    def add_column(self, header: str, **_: Any) -> None:
        self.columns.append({"header": header})

    def add_row(self, *cells: Any) -> None:
        self.rows.append([strip_markup(str(cell)) for cell in cells])


class _Capture:
    def __init__(self, console: PlainConsole) -> None:
        self._console = console
        self._buffer = io.StringIO()

    def get(self) -> str:
        return self._buffer.getvalue()


class PlainConsole:
    """Deterministic, colourless renderer writing to a text stream."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream
        self._capture: _Capture | None = None

    @property
    def stream(self) -> IO[str]:
        if self._capture is not None:
            return self._capture._buffer
        return self._stream if self._stream is not None else sys.stdout

    def print(self, *objects: Any) -> None:
        if not objects:
            self.stream.write("\n")
            return
        for obj in objects:
            self.stream.write(self._render(obj))
            if not isinstance(obj, str) or not obj.endswith("\n"):
                self.stream.write("\n")

    @contextmanager
    def capture(self) -> Iterator[_Capture]:
        previous = self._capture
        self._capture = _Capture(self)
        try:
            yield self._capture
        finally:
            self._capture = previous

    # -- renderers -----------------------------------------------------------

    def _render(self, obj: Any) -> str:
        if isinstance(obj, Panel):
            return self._render_panel(obj)
        if isinstance(obj, Table):
            return self._render_table(obj)
        return strip_markup(str(obj))

    @staticmethod
    def _render_panel(panel: Panel) -> str:
        body_lines = strip_markup(panel.renderable).splitlines() or [""]
        width = max(len(line) for line in body_lines)
        title = strip_markup(panel.title) if panel.title else ""
        if title:
            width = max(width, len(title) + 4)
        rule = "─" * (width + 2)
        top = f"┌─ {title} {'─' * max(0, width - len(title) - 1)}┐" if title else f"┌{rule}┐"
        bottom = f"└{rule}┘"
        middle = [f"│ {line.ljust(width)} │" for line in body_lines]
        return "\n".join([top, *middle, bottom])

    @staticmethod
    def _render_table(table: Table) -> str:
        headers = [strip_markup(col["header"]) for col in table.columns]
        rows = [list(row) + [""] * (len(headers) - len(row)) for row in table.rows]
        widths = _column_widths(headers, rows)
        lines: list[str] = []
        if table.title:
            lines.append(strip_markup(table.title))
        if table.show_header and headers:
            lines.append(_format_row(headers, widths))
            lines.append(_format_row(["─" * width for width in widths], widths))
        lines.extend(_format_row(row, widths) for row in rows)
        return "\n".join(line.rstrip() for line in lines)


def _column_widths(headers: list[str], rows: list[list[str]]) -> list[int]:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row[: len(widths)]):
            widths[index] = max(widths[index], len(cell))
    return widths


def _format_row(cells: list[str], widths: list[int]) -> str:
    return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells[: len(widths)]))


def get_console() -> PlainConsole:
    """The console the CLI prints through. Plain text, always."""
    return PlainConsole()
