"""Cross-file duplicate function implementation detection.

Detection is purely structural and deterministic. Two functions are
duplicates when their docstring-stripped bodies, parameter lists, and
return annotations produce identical AST dumps. Function names and
decorators are deliberately excluded from the comparison: a renamed or
re-decorated copy of the same implementation is still a copy.

Only significant functions participate. A function is significant when
its docstring-stripped body contains at least ``MIN_BODY_STATEMENTS``
statements and at least ``MIN_BODY_NODES`` AST nodes, so trivial
getters and delegation stubs never report.

When a duplicated function encloses other duplicated functions, only
the outermost duplicate reports, so one copied class or factory does
not cascade into a finding per inner helper.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .findings import Finding, Location

RULE_ID = "PY-DUP-001"
MIN_BODY_STATEMENTS = 3
MIN_BODY_NODES = 40
MAX_REPORTED_GROUPS = 100

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass(frozen=True, slots=True)
class _Occurrence:
    """One significant function occurrence, ready for deterministic sorting."""

    identity_path: str
    display_path: str
    name: str
    line: int
    column: int
    end_line: int | None
    end_column: int | None
    node_id: int
    ancestor_ids: tuple[int, ...]

    @property
    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.identity_path, self.line, self.column, self.name)


def _stripped_body(node: ast.AST) -> list[ast.stmt]:
    """Return the function body without a leading docstring expression."""
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _structure_key(node: ast.AST, body: list[ast.stmt]) -> str:
    """Build the normalized structural fingerprint for one function."""
    returns = ast.dump(node.returns) if node.returns is not None else ""
    body_dump = "\x00".join(ast.dump(statement) for statement in body)
    return "\x1f".join(
        (type(node).__name__, ast.dump(node.args), returns, body_dump)
    )


def _body_node_count(body: list[ast.stmt]) -> int:
    return sum(1 for statement in body for _ in ast.walk(statement))


class PythonDuplicationAnalyzer:
    """Detect structurally identical significant functions across files."""

    def __init__(self) -> None:
        self._groups: dict[str, list[_Occurrence]] = {}
        self._suppressions: dict[str, frozenset[tuple[int, str]]] = {}
        # Occurrences reference AST nodes by id(); pinning every added tree
        # guarantees no node is garbage-collected (and its id reused by a
        # different node) between add_file() and analyze().
        self._pinned_trees: list[ast.AST] = []
        self.functions_analyzed = 0

    def add_file(
        self,
        identity_path: str,
        display_path: str,
        tree: ast.AST,
        suppressed: frozenset[tuple[int, str]] = frozenset(),
    ) -> None:
        """Register one parsed module's significant functions."""
        self._pinned_trees.append(tree)
        self._suppressions[identity_path] = suppressed
        for node, ancestors in _walk_functions(tree):
            body = _stripped_body(node)
            if len(body) < MIN_BODY_STATEMENTS:
                continue
            if _body_node_count(body) < MIN_BODY_NODES:
                continue
            self.functions_analyzed += 1
            occurrence = _Occurrence(
                identity_path=identity_path,
                display_path=display_path,
                name=node.name,
                line=node.lineno,
                column=node.col_offset + 1,
                end_line=getattr(node, "end_lineno", None),
                end_column=(
                    node.end_col_offset + 1
                    if getattr(node, "end_col_offset", None) is not None
                    else None
                ),
                node_id=id(node),
                ancestor_ids=tuple(id(ancestor) for ancestor in ancestors),
            )
            self._groups.setdefault(
                _structure_key(node, body),
                [],
            ).append(occurrence)

    def analyze(self) -> tuple[dict, tuple[Finding, ...]]:
        """Return the aggregate payload and deterministic findings."""
        groups = self._duplicate_groups()
        findings = []
        reported_groups = []
        for occurrences in groups:
            first = occurrences[0]
            reported_groups.append({
                "function_count": len(occurrences),
                "occurrences": [
                    {
                        "path": occurrence.display_path,
                        "line": occurrence.line,
                        "function": occurrence.name,
                    }
                    for occurrence in occurrences
                ],
            })
            for occurrence in occurrences:
                other = occurrences[1] if occurrence is first else first
                suppressed = self._suppressions.get(
                    occurrence.identity_path,
                    frozenset(),
                )
                if (occurrence.line, RULE_ID) in suppressed:
                    continue
                findings.append(self._finding(occurrence, other, len(occurrences)))
        payload = {
            "functions_analyzed": self.functions_analyzed,
            "duplicate_groups": len(groups),
            "duplicated_functions": sum(len(group) for group in groups),
            "groups": reported_groups[:MAX_REPORTED_GROUPS],
            "groups_truncated": len(reported_groups) > MAX_REPORTED_GROUPS,
        }
        return payload, tuple(findings)

    def analysis_health(self) -> dict:
        return {
            "complete": True,
            "errors": 0,
            "functions_analyzed": self.functions_analyzed,
        }

    def _duplicate_groups(self) -> list[list[_Occurrence]]:
        """Return sorted duplicate groups with nested duplicates removed."""
        candidates = [
            sorted(occurrences, key=lambda item: item.sort_key)
            for occurrences in self._groups.values()
            if len(occurrences) >= 2
        ]
        duplicate_ids = {
            occurrence.node_id
            for occurrences in candidates
            for occurrence in occurrences
        }
        groups = []
        for occurrences in candidates:
            surviving = [
                occurrence
                for occurrence in occurrences
                if not any(
                    ancestor_id in duplicate_ids
                    for ancestor_id in occurrence.ancestor_ids
                )
            ]
            if len(surviving) >= 2:
                groups.append(surviving)
        groups.sort(key=lambda group: group[0].sort_key)
        return groups

    @staticmethod
    def _finding(
        occurrence: _Occurrence,
        other: _Occurrence,
        group_size: int,
    ) -> Finding:
        copies = group_size - 1
        plural = "s" if copies != 1 else ""
        return Finding(
            rule_id=RULE_ID,
            category="duplication",
            severity="warning",
            confidence="high",
            message=(
                f"Function '{occurrence.name}' has {copies} structural "
                f"duplicate{plural}; one is '{other.name}' at "
                f"{other.display_path}:{other.line}."
            ),
            location=Location(
                path=occurrence.display_path,
                line=occurrence.line,
                column=occurrence.column,
                end_line=occurrence.end_line,
                end_column=occurrence.end_column,
                identity_path=occurrence.identity_path,
            ),
            remediation=(
                "Extract the shared implementation into one function and "
                "call it from each location."
            ),
        )


def _walk_functions(
    tree: ast.AST,
) -> Iterable[tuple[ast.FunctionDef | ast.AsyncFunctionDef, tuple]]:
    """Yield every function with its enclosing function ancestry."""
    stack: list[tuple[ast.AST, tuple]] = [(tree, ())]
    while stack:
        node, ancestors = stack.pop()
        children_ancestors = ancestors
        if isinstance(node, _FUNCTION_NODES):
            yield node, ancestors
            children_ancestors = (*ancestors, node)
        for child in reversed(list(ast.iter_child_nodes(node))):
            stack.append((child, children_ancestors))


def analyze_duplication(
    parsed_modules: Mapping[str, tuple[str, ast.AST, frozenset]],
) -> tuple[dict, tuple[Finding, ...], dict]:
    """Analyze modules keyed by identity path; return payload, findings, health."""
    analyzer = PythonDuplicationAnalyzer()
    for identity_path in sorted(parsed_modules):
        display_path, tree, suppressed = parsed_modules[identity_path]
        analyzer.add_file(identity_path, display_path, tree, suppressed)
    payload, findings = analyzer.analyze()
    return payload, findings, analyzer.analysis_health()
