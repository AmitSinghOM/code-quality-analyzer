"""A stdlib stand-in for ``click.testing.CliRunner`` (3.0 removed click).

``CliRunner().invoke(main, args)`` runs the argparse entry point in-process,
captures stdout and stderr, and returns a result with the attributes the
suite already uses: ``exit_code``, ``output`` (stdout and stderr interleaved,
as click 8.2+ does), ``stdout``, ``stderr`` and ``exception``. Keeping this
shape meant the 3.0 rewrite touched one import line per test file and left
every assertion untouched — the strongest regression net a CLI rewrite can
have.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from typing import Any


class _Tee(io.TextIOBase):
    """Write to a private buffer and to the shared, interleaved ``output``."""

    def __init__(self, combined: io.StringIO) -> None:
        super().__init__()
        self._own = io.StringIO()
        self._combined = combined

    def write(self, text: str) -> int:  # type: ignore[override]
        self._own.write(text)
        self._combined.write(text)
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return "utf-8"

    def getvalue(self) -> str:
        return self._own.getvalue()


@dataclass
class Result:
    exit_code: int
    output: str
    stdout: str
    stderr: str
    exception: BaseException | None = None

    @property
    def return_value(self) -> None:  # click parity; main() never returns a value
        return None


class CliRunner:
    def invoke(
        self,
        main: Callable[[list[str] | None], Any],
        args: Sequence[Any] | None = None,
        **_: Any,
    ) -> Result:
        combined = io.StringIO()
        out, err = _Tee(combined), _Tee(combined)
        argv = [str(item) for item in (args or [])]
        exit_code = 0
        exception: BaseException | None = None
        with redirect_stdout(out), redirect_stderr(err):
            try:
                main(argv)
            except SystemExit as exc:
                code = exc.code
                if code is None:
                    exit_code = 0
                elif isinstance(code, int):
                    exit_code = code
                else:  # a message: argparse never does this, but mirror the interpreter
                    err.write(f"{code}\n")
                    exit_code = 1
            except Exception as exc:  # noqa: BLE001 - surfaced on the result like click does
                exception = exc
                exit_code = 1
        return Result(
            exit_code=exit_code,
            output=combined.getvalue(),
            stdout=out.getvalue(),
            stderr=err.getvalue(),
            exception=exception,
        )


def invoke(main: Callable[..., Any], args: Sequence[Any]) -> Result:
    return CliRunner().invoke(main, args)


__all__ = ["CliRunner", "Result", "invoke"]
