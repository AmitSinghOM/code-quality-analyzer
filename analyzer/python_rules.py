"""Source-located maintainability and correctness rules for Python."""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
from typing import Protocol

from .findings import Finding, Location


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


class PythonRuleAnalyzer:
    """Run registered Python rules and return deterministic findings."""

    def __init__(self, rules: Sequence[PythonRule] | None = None) -> None:
        self.rules = (
            tuple(rules)
            if rules is not None
            else (MutableDefaultRule(),)
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
