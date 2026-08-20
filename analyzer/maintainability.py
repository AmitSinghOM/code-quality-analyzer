"""Measured Python maintainability rules using shared parse artifacts."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass

from .findings import Finding, Location

CYCLOMATIC_COMPLEXITY_LIMIT = 10
COGNITIVE_COMPLEXITY_LIMIT = 15


@dataclass(frozen=True, slots=True)
class FunctionComplexity:
    """Deterministic syntax-derived complexity for one function."""

    name: str
    line: int
    column: int
    cyclomatic: int
    cognitive: int


def function_complexities(tree: ast.AST) -> tuple[FunctionComplexity, ...]:
    """Measure each function independently without entering nested units."""
    metrics = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        counter = _ComplexityCounter()
        for statement in node.body:
            counter.visit(statement)
        metrics.append(FunctionComplexity(
            name=node.name,
            line=node.lineno,
            column=node.col_offset + 1,
            cyclomatic=counter.cyclomatic,
            cognitive=counter.cognitive,
        ))
    return tuple(sorted(metrics, key=lambda item: (item.line, item.column)))


class CyclomaticComplexityRule:
    """Report functions above the measured cyclomatic limit."""

    rule_id = "PY-MAINT-001"
    category = "maintainability"
    severity = "warning"
    confidence = "high"

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        for metric in function_complexities(tree):
            if metric.cyclomatic <= CYCLOMATIC_COMPLEXITY_LIMIT:
                continue
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                message=(
                    f"Function '{metric.name}' has cyclomatic complexity "
                    f"{metric.cyclomatic} (limit "
                    f"{CYCLOMATIC_COMPLEXITY_LIMIT})."
                ),
                location=_location(metric, path, identity_path),
                remediation=(
                    "Extract independent decisions into focused helper "
                    "functions."
                ),
            )


class CognitiveComplexityRule:
    """Report functions above the measured cognitive limit."""

    rule_id = "PY-MAINT-002"
    category = "maintainability"
    severity = "warning"
    confidence = "high"

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        for metric in function_complexities(tree):
            if metric.cognitive <= COGNITIVE_COMPLEXITY_LIMIT:
                continue
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                message=(
                    f"Function '{metric.name}' has cognitive complexity "
                    f"{metric.cognitive} (limit "
                    f"{COGNITIVE_COMPLEXITY_LIMIT})."
                ),
                location=_location(metric, path, identity_path),
                remediation=(
                    "Flatten nested control flow and extract focused helper "
                    "functions."
                ),
            )


def _location(
    metric: FunctionComplexity,
    path: str,
    identity_path: str,
) -> Location:
    return Location(
        path=path,
        line=metric.line,
        column=metric.column,
        identity_path=identity_path,
    )


class _ComplexityCounter(ast.NodeVisitor):
    """Count decision paths and nesting pressure within one function."""

    def __init__(self) -> None:
        self.cyclomatic = 1
        self.cognitive = 0
        self.nesting = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_If(self, node: ast.If) -> None:
        self._decision(node.test, node.body, node.orelse)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.target)
        self._decision(node.iter, node.body, node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit(node.target)
        self._decision(node.iter, node.body, node.orelse)

    def visit_While(self, node: ast.While) -> None:
        self._decision(node.test, node.body, node.orelse)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.cyclomatic += 1
        self.cognitive += 1 + self.nesting
        if node.type is not None:
            self.visit(node.type)
        self._nested(node.body)


    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.cyclomatic += 1
        self.cognitive += 1 + self.nesting
        self.visit(node.test)
        self._nested((node.body, node.orelse))

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.cyclomatic += max(len(node.values) - 1, 0)
        self.cognitive += int(len(node.values) > 1)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.cyclomatic += 1 + len(node.ifs)
        self.cognitive += 1 + self.nesting
        self.visit(node.target)
        self.visit(node.iter)
        self._nested(node.ifs)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        branches = max(len(node.cases) - 1, 0)
        self.cyclomatic += branches
        self.cognitive += int(bool(node.cases)) * (1 + self.nesting)
        old_nesting = self.nesting
        self.nesting += 1
        for case in node.cases:
            self.visit(case.pattern)
            if case.guard is not None:
                self.cyclomatic += 1
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
        self.nesting = old_nesting

    def _decision(
        self,
        condition: ast.AST,
        body: Iterable[ast.AST],
        alternate: Iterable[ast.AST],
    ) -> None:
        self.cyclomatic += 1
        self.cognitive += 1 + self.nesting
        self.visit(condition)
        self._nested((*body, *alternate))

    def _nested(self, nodes: Iterable[ast.AST]) -> None:
        old_nesting = self.nesting
        self.nesting += 1
        for node in nodes:
            self.visit(node)
        self.nesting = old_nesting
