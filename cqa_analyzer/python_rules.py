"""Source-located maintainability and correctness rules for Python."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
from typing import Protocol

from .findings import Finding, Location
from .maintainability import (
    BooleanParameterRule,
    CognitiveComplexityRule,
    CyclomaticComplexityRule,
    ExcessiveParametersRule,
    LongFunctionRule,
)
from .python_resources import AsyncBlockingCallRule, UnmanagedResourceRule
from .python_security import SECURITY_RULES
from .python_sql import DynamicSqlRule


class PythonRule(Protocol):
    """Contract implemented by Python AST rules."""

    rule_id: str

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]: ...


class MutableDefaultRule:
    """Detect mutable values created once at function definition time."""

    rule_id = "PY-COR-001"
    category = "correctness"
    severity = "warning"
    confidence = "high"
    remediation = (
        "Use None as the default and create a new value inside the function."
    )

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            yield from self._function_findings(node, path, identity_path)

    def _function_findings(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        path: str,
        identity_path: str,
    ) -> Iterable[Finding]:
        positional = [*node.args.posonlyargs, *node.args.args]
        positional_with_defaults = (
            positional[-len(node.args.defaults):]
            if node.args.defaults
            else ()
        )
        defaults = zip(
            positional_with_defaults,
            node.args.defaults,
            strict=True,
        )
        for argument, default in defaults:
            if kind := _mutable_default_kind(default):
                yield self._finding(
                    node.name,
                    argument.arg,
                    default,
                    kind,
                    path,
                    identity_path,
                )

        for argument, default in zip(
            node.args.kwonlyargs,
            node.args.kw_defaults,
            strict=True,
        ):
            kind = (
                _mutable_default_kind(default)
                if default is not None
                else None
            )
            if kind is not None:
                yield self._finding(
                    node.name,
                    argument.arg,
                    default,
                    kind,
                    path,
                    identity_path,
                )

    def _finding(
        self,
        function_name: str,
        argument_name: str,
        default: ast.expr,
        kind: str,
        path: str,
        identity_path: str,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            category=self.category,
            severity=self.severity,
            confidence=self.confidence,
            message=(
                f"Argument '{argument_name}' in '{function_name}' uses "
                f"a mutable {kind} default."
            ),
            location=Location(
                path=path,
                line=default.lineno,
                column=default.col_offset + 1,
                end_line=getattr(default, "end_lineno", None),
                end_column=(
                    default.end_col_offset + 1
                    if getattr(default, "end_col_offset", None) is not None
                    else None
                ),
                identity_path=identity_path,
            ),
            remediation=self.remediation,
        )


_MUTABLE_LITERALS = {
    ast.List: "list",
    ast.Dict: "dictionary",
    ast.Set: "set",
    ast.ListComp: "list comprehension",
    ast.DictComp: "dictionary comprehension",
    ast.SetComp: "set comprehension",
}
_MUTABLE_FACTORIES = {"list", "dict", "set", "bytearray"}


def _mutable_default_kind(node: ast.expr) -> str | None:
    for node_type, label in _MUTABLE_LITERALS.items():
        if isinstance(node, node_type):
            return label
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _MUTABLE_FACTORIES
    ):
        return f"{node.func.id}()"
    return None


class BroadExceptionRule:
    """Detect handlers that catch every or nearly every exception."""

    rule_id = "PY-COR-002"
    category = "correctness"
    severity = "warning"
    confidence = "high"
    remediation = (
        "Catch the narrow exception types the operation can recover from."
    )

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        for handler in (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler)
        ):
            caught = _broad_exception(handler.type)
            if caught is None or _reraises(handler):
                continue
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                message=f"Exception handler catches {caught}.",
                location=_node_location(
                    handler.type or handler,
                    path,
                    identity_path,
                ),
                remediation=self.remediation,
            )


class SwallowedExceptionRule:
    """Detect handlers whose body silently discards an exception."""

    rule_id = "PY-COR-003"
    category = "correctness"
    severity = "warning"
    confidence = "high"
    remediation = (
        "Handle the failure, log actionable context, or re-raise the "
        "exception."
    )

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        for handler in (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler)
        ):
            if not _silently_discards(handler.body):
                continue
            if _only_expected_exceptions(handler.type):
                yield Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity="note",
                    confidence=self.confidence,
                    message=(
                        "Exception handler swallows an expected control-flow "
                        "exception (optional import or exhausted iterator); "
                        "confirm nothing else can raise inside the try."
                    ),
                    location=_node_location(handler, path, identity_path),
                    remediation=self.remediation,
                )
                continue
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                message="Exception handler silently discards the failure.",
                location=_node_location(handler, path, identity_path),
                remediation=self.remediation,
            )


class UnreachableCodeRule:
    """Detect statements after an unconditional suite terminator."""

    rule_id = "PY-COR-004"
    category = "correctness"
    severity = "warning"
    confidence = "high"
    remediation = (
        "Remove the statement or move it before the control transfer."
    )

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        for parent in ast.walk(tree):
            for _, value in ast.iter_fields(parent):
                if not value or not isinstance(value, list):
                    continue
                if not isinstance(value[0], ast.stmt):
                    continue
                unreachable = _first_unreachable(value)
                if unreachable is None:
                    continue
                statement, terminator = unreachable
                yield Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    message=(
                        f"Statement is unreachable after "
                        f"{type(terminator).__name__.lower()}."
                    ),
                    location=_node_location(statement, path, identity_path),
                    remediation=self.remediation,
                )


_EXPECTED_SWALLOWED = frozenset(
    {"ImportError", "ModuleNotFoundError", "StopIteration", "StopAsyncIteration"}
)


def _only_expected_exceptions(caught: ast.expr | None) -> bool:
    """True when every caught type is one raised as normal control flow.

    ``except ImportError: pass`` is the optional-dependency probe (requests'
    compat.py, __init__.py and utils.py all do it) and ``except StopIteration:
    pass`` is how a hand-driven iterator signals exhaustion. Swallowing them
    is the documented way to use them, so the finding stays visible at note
    weight rather than warning. A bare ``except:`` or any broader type keeps
    the warning: those swallow real failures too.
    """
    if caught is None:
        return False
    types = caught.elts if isinstance(caught, ast.Tuple) else [caught]
    if not types:
        return False
    for node in types:
        name = node.id if isinstance(node, ast.Name) else getattr(node, "attr", None)
        if name not in _EXPECTED_SWALLOWED:
            return False
    return True


def _reraises(handler: ast.ExceptHandler) -> bool:
    """True when the handler ends by re-raising what it caught.

    ``except BaseException: cleanup(); raise`` is the idiom for guaranteed
    cleanup that must also run on KeyboardInterrupt/SystemExit -- it is a
    ``finally`` with access to the exception, not a broad catch. ruff's
    BLE001 exempts the same shape. Only a bare ``raise`` or ``raise <name>``
    of the bound exception as the final statement qualifies; wrapping the
    error in a new type is a different decision and still reported.
    """
    if not handler.body:
        return False
    last = handler.body[-1]
    if not isinstance(last, ast.Raise) or last.cause is not None:
        return False
    if last.exc is None:
        return True
    return (
        handler.name is not None
        and isinstance(last.exc, ast.Name)
        and last.exc.id == handler.name
    )


def _broad_exception(node: ast.expr | None) -> str | None:
    if node is None:
        return "all exceptions with a bare except"
    names = (
        node.elts
        if isinstance(node, ast.Tuple)
        else (node,)
    )
    for name in names:
        if (
            isinstance(name, ast.Name)
            and name.id in {"Exception", "BaseException"}
        ):
            return name.id
    return None


def _silently_discards(body: list[ast.stmt]) -> bool:
    if len(body) != 1:
        return False
    statement = body[0]
    return isinstance(statement, ast.Pass) or (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    )


def _first_unreachable(
    statements: list[ast.stmt],
) -> tuple[ast.stmt, ast.stmt] | None:
    terminators = (ast.Return, ast.Raise, ast.Break, ast.Continue)
    for index, statement in enumerate(statements[:-1]):
        if isinstance(statement, terminators):
            return statements[index + 1], statement
    return None


def _node_location(
    node: ast.AST,
    path: str,
    identity_path: str,
) -> Location:
    return Location(
        path=path,
        line=node.lineno,
        column=node.col_offset + 1,
        end_line=getattr(node, "end_lineno", None),
        end_column=(
            node.end_col_offset + 1
            if getattr(node, "end_col_offset", None) is not None
            else None
        ),
        identity_path=identity_path,
    )


class PythonRuleAnalyzer:
    """Run registered Python rules and return deterministic findings."""

    def __init__(self, rules: Sequence[PythonRule] | None = None) -> None:
        self.rules = (
            tuple(rules)
            if rules is not None
            else (
                MutableDefaultRule(),
                BroadExceptionRule(),
                SwallowedExceptionRule(),
                UnreachableCodeRule(),
                CyclomaticComplexityRule(),
                CognitiveComplexityRule(),
                LongFunctionRule(),
                ExcessiveParametersRule(),
                BooleanParameterRule(),
                AsyncBlockingCallRule(),
                UnmanagedResourceRule(),
                DynamicSqlRule(),
                *(rule() for rule in SECURITY_RULES),
            )
        )

    def analyze(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> list[Finding]:
        findings = [
            finding
            for rule in self.rules
            for finding in rule.evaluate(tree, path, identity_path)
        ]
        return sorted(
            findings,
            key=lambda item: (
                item.location.path,
                item.location.line,
                item.location.column,
                item.rule_id,
            ),
        )
