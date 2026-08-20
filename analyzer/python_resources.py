"""Conservative blocking-call and resource-ownership Python rules."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from .findings import Finding, Location

_BLOCKING_CALLS = frozenset({
    "builtins.open",
    "io.open",
    "os.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
    "time.sleep",
    "urllib.request.urlopen",
    "pathlib.Path.open",
    "pathlib.Path.read_bytes",
    "pathlib.Path.read_text",
    "pathlib.Path.write_bytes",
    "pathlib.Path.write_text",
})
_RESOURCE_CALLS = frozenset({
    "builtins.open",
    "io.open",
    "pathlib.Path.open",
    "tempfile.NamedTemporaryFile",
    "tempfile.SpooledTemporaryFile",
    "tempfile.TemporaryDirectory",
    "tempfile.TemporaryFile",
})


class AsyncBlockingCallRule:
    """Detect a small allowlist of synchronous calls in async functions."""

    rule_id = "PY-COR-005"
    category = "correctness"
    severity = "warning"
    confidence = "high"

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        module_aliases, module_shadowed = _scope_bindings(tree)
        for function in _functions(tree, async_only=True):
            aliases, shadowed = _scope_bindings(
                function,
                inherited=module_aliases,
                inherited_shadowed=module_shadowed,
            )
            _, nodes = _runtime_tree(function)
            for call in (node for node in nodes if isinstance(node, ast.Call)):
                name = _call_name(call, aliases, shadowed)
                if name not in _BLOCKING_CALLS:
                    continue
                yield Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    message=(
                        f"Synchronous call '{name}' can block async function "
                        f"'{function.name}'."
                    ),
                    location=_location(call, path, identity_path),
                    remediation=(
                        "Use an async API or move unavoidable synchronous work "
                        "to a worker thread."
                    ),
                )


class UnmanagedResourceRule:
    """Detect locally owned resources without structural cleanup."""

    rule_id = "PY-COR-006"
    category = "correctness"
    severity = "warning"
    confidence = "high"

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        module_aliases, module_shadowed = _scope_bindings(tree)
        for function in _functions(tree):
            aliases, shadowed = _scope_bindings(
                function,
                inherited=module_aliases,
                inherited_shadowed=module_shadowed,
            )
            parents, nodes = _runtime_tree(function)
            guaranteed = _guaranteed_cleanup_names(nodes, parents)
            for call in (node for node in nodes if isinstance(node, ast.Call)):
                name = _call_name(call, aliases, shadowed)
                if name not in _RESOURCE_CALLS:
                    continue
                if _managed_or_escaped(call, parents, guaranteed):
                    continue
                yield Finding(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    message=(
                        f"Resource from '{name}' lacks guaranteed cleanup."
                    ),
                    location=_location(call, path, identity_path),
                    remediation=(
                        "Use a context manager or guarantee cleanup with "
                        "try/finally."
                    ),
                )


def _functions(
    tree: ast.AST,
    *,
    async_only: bool = False,
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    accepted = (ast.AsyncFunctionDef,) if async_only else (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
    )
    return tuple(sorted(
        (node for node in ast.walk(tree) if isinstance(node, accepted)),
        key=lambda node: (node.lineno, node.col_offset),
    ))


def _scope_bindings(
    scope: ast.AST,
    *,
    inherited: dict[str, str] | None = None,
    inherited_shadowed: set[str] | None = None,
) -> tuple[dict[str, str], set[str]]:
    collector = _BindingCollector()
    if isinstance(scope, ast.Module):
        for statement in scope.body:
            collector.visit(statement)
    else:
        for argument in _arguments(scope):
            collector.assigned.add(argument.arg)
        for statement in scope.body:
            collector.visit(statement)
    aliases = dict(inherited or {})
    shadowed = set(inherited_shadowed or set())
    aliases.update(collector.aliases)
    for name in collector.assigned - set(collector.aliases):
        aliases.pop(name, None)
        shadowed.add(name)
    for name in collector.conflicts:
        aliases.pop(name, None)
        shadowed.add(name)
    return aliases, shadowed


def _arguments(scope: ast.AST) -> tuple[ast.arg, ...]:
    if not isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef):
        return ()
    arguments = scope.args
    values = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        values.append(arguments.vararg)
    if arguments.kwarg is not None:
        values.append(arguments.kwarg)
    return tuple(values)


class _BindingCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.assigned: set[str] = set()
        self.conflicts: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.assigned.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.assigned.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.assigned.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            if node.id in self.aliases:
                self.conflicts.add(node.id)
            self.assigned.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            local = item.asname or item.name.partition(".")[0]
            canonical = item.name if item.asname else item.name.partition(".")[0]
            self._alias(local, canonical)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return
        for item in node.names:
            if item.name == "*":
                self.conflicts.update(self.aliases)
                continue
            self._alias(
                item.asname or item.name,
                f"{node.module}.{item.name}",
            )

    def _alias(self, local: str, canonical: str) -> None:
        existing = self.aliases.get(local)
        if existing is not None and existing != canonical:
            self.conflicts.add(local)
        self.aliases[local] = canonical


def _runtime_tree(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[dict[ast.AST, ast.AST], tuple[ast.AST, ...]]:
    parents: dict[ast.AST, ast.AST] = {}
    nodes: list[ast.AST] = []

    def walk(node: ast.AST, parent: ast.AST) -> None:
        if isinstance(
            node,
            ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda,
        ):
            return
        parents[node] = parent
        nodes.append(node)
        for child in ast.iter_child_nodes(node):
            walk(child, node)

    for statement in function.body:
        walk(statement, function)
    return parents, tuple(nodes)


def _call_name(
    call: ast.Call,
    aliases: dict[str, str],
    shadowed: set[str],
) -> str | None:
    if isinstance(call.func, ast.Name):
        if call.func.id in aliases:
            return aliases[call.func.id]
        if call.func.id == "open" and "open" not in shadowed:
            return "builtins.open"
        return None
    if not isinstance(call.func, ast.Attribute):
        return None
    if isinstance(call.func.value, ast.Call):
        receiver = _call_name(call.func.value, aliases, shadowed)
        if receiver == "pathlib.Path":
            return f"pathlib.Path.{call.func.attr}"
        return None
    base = _expression_name(call.func.value, aliases, shadowed)
    return f"{base}.{call.func.attr}" if base else None


def _expression_name(
    node: ast.AST,
    aliases: dict[str, str],
    shadowed: set[str],
) -> str | None:
    if isinstance(node, ast.Name):
        if node.id in shadowed and node.id not in aliases:
            return None
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _expression_name(node.value, aliases, shadowed)
        return f"{base}.{node.attr}" if base else None
    return None


def _managed_or_escaped(
    call: ast.Call,
    parents: dict[ast.AST, ast.AST],
    guaranteed: set[str],
) -> bool:
    current: ast.AST = call
    while current in parents:
        parent = parents[current]
        if isinstance(parent, ast.withitem) and parent.context_expr is current:
            return True
        if isinstance(parent, ast.Return | ast.Yield | ast.YieldFrom):
            return True
        if isinstance(parent, ast.Call):
            if parent.func is current:
                current = parent
                continue
            if (
                isinstance(parent.func, ast.Attribute)
                and parent.func.value is current
            ):
                current = parent
                continue
            if (
                isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "enter_context"
                and current in parent.args
            ):
                return True
            return True
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    return target.id in guaranteed
                if isinstance(target, ast.Attribute | ast.Subscript):
                    return True
        if isinstance(parent, ast.AnnAssign):
            if isinstance(parent.target, ast.Name):
                return parent.target.id in guaranteed
            return True
        current = parent
    return False


def _guaranteed_cleanup_names(
    nodes: tuple[ast.AST, ...],
    parents: dict[ast.AST, ast.AST],
) -> set[str]:
    names = set()
    for node in nodes:
        if not isinstance(node, ast.Try):
            continue
        final_nodes = {
            child
            for statement in node.finalbody
            for child in ast.walk(statement)
        }
        for child in final_nodes:
            if not isinstance(child, ast.Call):
                continue
            function = child.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr == "close"
                and isinstance(function.value, ast.Name)
            ):
                names.add(function.value.id)
    return names


def _location(node: ast.AST, path: str, identity_path: str) -> Location:
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
