"""PY-COR-007: SQL statement assembled from runtime values (Python AST)."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from .findings import Finding, Location
from .sql_text import has_format_placeholder, is_sql_statement


def _leftmost_constant(node: ast.expr) -> ast.Constant | None:
    """Return the leftmost string constant of a ``+`` chain, if any."""
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        node = node.left
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node
    return None


def _has_dynamic_operand(node: ast.expr) -> bool:
    """True when a ``+`` chain contains a non-constant operand."""
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            stack.extend((current.left, current.right))
        elif not isinstance(current, ast.Constant):
            return True
    return False


class DynamicSqlRule:
    """Detect SQL text built with f-strings, ``%``, ``.format`` or ``+``."""

    rule_id = "PY-COR-007"
    category = "correctness"
    severity = "warning"
    confidence = "medium"
    remediation = (
        "Pass runtime values as driver parameters (bind variables); "
        "allowlist identifiers such as table or column names."
    )

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        seen_lines: set[int] = set()
        for node in ast.walk(tree):
            hit = self._classify(node)
            if hit is None:
                continue
            anchor, reason = hit
            if anchor.lineno in seen_lines:  # one finding per statement line
                continue
            seen_lines.add(anchor.lineno)
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                message=f"SQL statement is assembled with {reason}.",
                location=Location(
                    path=path,
                    line=anchor.lineno,
                    column=anchor.col_offset + 1,
                    end_line=getattr(anchor, "end_lineno", None),
                    end_column=(
                        anchor.end_col_offset + 1
                        if getattr(anchor, "end_col_offset", None) is not None
                        else None
                    ),
                    identity_path=identity_path,
                ),
                remediation=self.remediation,
            )

    @staticmethod
    def _classify(node: ast.AST) -> tuple[ast.expr, str] | None:
        # f"SELECT ... {value}"
        if isinstance(node, ast.JoinedStr) and node.values:
            head = node.values[0]
            if (
                isinstance(head, ast.Constant)
                and isinstance(head.value, str)
                and is_sql_statement(head.value)
                and any(isinstance(part, ast.FormattedValue) for part in node.values)
            ):
                return node, "an f-string"
            return None
        if isinstance(node, ast.BinOp):
            # "SELECT ... %s" % value
            if isinstance(node.op, ast.Mod):
                left = node.left
                if (
                    isinstance(left, ast.Constant)
                    and isinstance(left.value, str)
                    and is_sql_statement(left.value)
                    and has_format_placeholder(left.value)
                ):
                    return left, "%-formatting"
                return None
            # "SELECT ... " + value  (anchored on the leftmost literal)
            if isinstance(node.op, ast.Add):
                head = _leftmost_constant(node)
                if (
                    head is not None
                    and is_sql_statement(head.value)
                    and _has_dynamic_operand(node)
                ):
                    return head, "string concatenation"
            return None
        # "SELECT ... {}".format(value)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)
            and is_sql_statement(node.func.value.value)
            and has_format_placeholder(node.func.value.value)
            and (node.args or node.keywords)
        ):
            return node.func.value, "str.format"
        return None
