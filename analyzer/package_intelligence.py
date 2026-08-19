"""Passive Python package metadata and import-graph analysis."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from .findings import Finding, Location


@dataclass(slots=True)
class PackageIntelligence:
    """Serializable facts about a Python package."""

    pyproject_present: bool = False
    metadata_valid: bool = True
    project_name: str | None = None
    requires_python: str | None = None
    build_backend: str | None = None
    dependencies: list[str] = field(default_factory=list)
    optional_dependencies: dict[str, list[str]] = field(default_factory=dict)
    scripts: dict[str, str] = field(default_factory=dict)
    layout: str = "none"
    source_roots: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    import_graph: dict[str, list[str]] = field(default_factory=dict)
    circular_imports: list[list[str]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pyproject_present": self.pyproject_present,
            "metadata_valid": self.metadata_valid,
            "project_name": self.project_name,
            "requires_python": self.requires_python,
            "build_backend": self.build_backend,
            "dependencies": self.dependencies,
            "optional_dependencies": self.optional_dependencies,
            "scripts": self.scripts,
            "layout": self.layout,
            "source_roots": self.source_roots,
            "modules": self.modules,
            "import_graph": self.import_graph,
            "circular_imports": self.circular_imports,
        }


class PythonPackageAnalyzer:
    """Analyze package structure without importing or building project code."""

    def __init__(
        self,
        root: Path,
        parsed_files: dict[str, ast.AST],
        redact_paths: bool = False,
    ) -> None:
        self.root = root
        self.parsed_files = parsed_files
        self.redact_paths = redact_paths
        self.result = PackageIntelligence()
        self.findings: list[Finding] = []
        self.errors = 0

    def analyze(self) -> PackageIntelligence:
        metadata = self._read_metadata()
        module_paths = _module_paths(self.parsed_files)
        self.result.layout = _layout(module_paths)
        if self.result.layout == "src":
            self.result.source_roots = ["src"]
        elif self.result.layout == "flat":
            self.result.source_roots = ["."]
        self.result.modules = sorted(module_paths)

        graph, locations = _build_import_graph(
            self.parsed_files,
            module_paths,
            redact_paths=self.redact_paths,
        )
        self.result.import_graph = {
            module: sorted(targets)
            for module, targets in sorted(graph.items())
        }
        self.result.circular_imports = _strongly_connected_cycles(graph)
        self.findings.extend(
            _cycle_findings(self.result.circular_imports, locations)
        )
        if metadata is not None:
            self.findings.extend(_entry_point_findings(metadata, module_paths))
        self.findings.sort(key=_finding_key)
        return self.result

    def analysis_health(self) -> dict:
        return {"errors": self.errors, "complete": self.errors == 0}

    def _read_metadata(self) -> dict | None:
        path = self.root / "pyproject.toml"
        self.result.pyproject_present = path.is_file()
        if not self.result.pyproject_present:
            return None

        try:
            with path.open("rb") as stream:
                data = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError):
            self.result.metadata_valid = False
            self.errors += 1
            self.findings.append(Finding(
                rule_id="PY-PKG-003",
                category="package-health",
                severity="error",
                confidence="high",
                message="pyproject.toml could not be read as valid TOML.",
                location=Location("pyproject.toml", 1, 1),
                remediation="Correct the TOML syntax and run analysis again.",
            ))
            return None

        project = _table(data.get("project"))
        build_system = _table(data.get("build-system"))
        self.result.project_name = _optional_string(project.get("name"))
        self.result.requires_python = _optional_string(
            project.get("requires-python")
        )
        self.result.build_backend = _optional_string(
            build_system.get("build-backend")
        )
        self.result.dependencies = _string_list(project.get("dependencies"))
        optional_dependencies = _table(project.get("optional-dependencies"))
        self.result.optional_dependencies = {
            str(group): _string_list(requirements)
            for group, requirements in sorted(optional_dependencies.items())
            if isinstance(requirements, list)
        }
        scripts = _table(project.get("scripts"))
        self.result.scripts = {
            str(name): target
            for name, target in sorted(scripts.items())
            if isinstance(target, str)
        }
        return data


def _table(value) -> dict:
    return value if isinstance(value, dict) else {}


def _optional_string(value) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _module_paths(parsed_files: dict[str, ast.AST]) -> dict[str, str]:
    paths = sorted(parsed_files)
    uses_src = any(Path(path).parts[:1] == ("src",) for path in paths)
    package_dirs = {
        Path(path).parts[0]
        for path in paths
        if len(Path(path).parts) > 1 and Path(path).name == "__init__.py"
    }

    modules: dict[str, str] = {}
    for path in paths:
        parts = list(Path(path).parts)
        if uses_src:
            if not parts or parts[0] != "src":
                continue
            parts = parts[1:]
        elif len(parts) > 1 and parts[0] not in package_dirs:
            continue
        elif len(parts) == 1 and parts[0] == "setup.py":
            continue

        if not parts or not parts[-1].endswith(".py"):
            continue
        parts[-1] = parts[-1][:-3]
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts:
            modules[".".join(parts)] = path
    return modules


def _layout(module_paths: dict[str, str]) -> str:
    if any(Path(path).parts[:1] == ("src",) for path in module_paths.values()):
        return "src"
    return "flat" if module_paths else "none"


def _build_import_graph(
    parsed_files: dict[str, ast.AST],
    module_paths: dict[str, str],
    redact_paths: bool = False,
) -> tuple[dict[str, set[str]], dict[tuple[str, str], Location]]:
    path_to_module = {path: module for module, path in module_paths.items()}
    graph = {module: set() for module in module_paths}
    locations: dict[tuple[str, str], Location] = {}
    import_nodes = ast.Import | ast.ImportFrom

    for path, tree in sorted(parsed_files.items()):
        source = path_to_module.get(path)
        if source is None:
            continue
        is_package = Path(path).name == "__init__.py"
        for node in ast.walk(tree):
            if not isinstance(node, import_nodes):
                continue
            for target in _import_targets(
                node,
                source,
                is_package,
                module_paths,
            ):
                if target == source:
                    continue
                graph[source].add(target)
                locations.setdefault(
                    (source, target),
                    Location(
                        path=Path(path).name if redact_paths else path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        end_line=getattr(node, "end_lineno", None),
                        end_column=(
                            node.end_col_offset + 1
                            if getattr(
                                node, "end_col_offset", None
                            ) is not None
                            else None
                        ),
                    ),
                )
    return graph, locations


def _import_targets(
    node: ast.Import | ast.ImportFrom,
    current: str,
    is_package: bool,
    modules: dict[str, str],
) -> set[str]:
    targets: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            if target := _nearest_local_module(alias.name, modules):
                targets.add(target)
        return targets

    base = _from_import_base(node, current, is_package)
    for alias in node.names:
        specific = (
            f"{base}.{alias.name}"
            if base and alias.name != "*"
            else base
        )
        target = _nearest_local_module(specific, modules)
        if target is None:
            target = _nearest_local_module(base, modules)
        if target is not None:
            targets.add(target)
    return targets


def _from_import_base(
    node: ast.ImportFrom,
    current: str,
    is_package: bool,
) -> str:
    if node.level == 0:
        return node.module or ""

    package_parts = (
        current.split(".")
        if is_package
        else current.split(".")[:-1]
    )
    parents_to_remove = node.level - 1
    if parents_to_remove:
        package_parts = package_parts[:-parents_to_remove]
    if node.module:
        package_parts.extend(node.module.split("."))
    return ".".join(package_parts)


def _nearest_local_module(name: str, modules: dict[str, str]) -> str | None:
    candidate = name
    while candidate:
        if candidate in modules:
            return candidate
        candidate = candidate.rpartition(".")[0]
    return None


def _strongly_connected_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    """Return cyclic components using iterative Kosaraju traversal."""
    visited: set[str] = set()
    finish_order: list[str] = []

    for start in sorted(graph):
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            module, expanded = stack.pop()
            if expanded:
                finish_order.append(module)
                continue
            if module in visited:
                continue
            visited.add(module)
            stack.append((module, True))
            for target in sorted(graph.get(module, ()), reverse=True):
                if target not in visited:
                    stack.append((target, False))

    reverse_graph = {module: set() for module in graph}
    for source, targets in graph.items():
        for target in targets:
            reverse_graph.setdefault(target, set()).add(source)

    assigned: set[str] = set()
    components: list[list[str]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component = []
        stack = [start]
        assigned.add(start)
        while stack:
            module = stack.pop()
            component.append(module)
            for source in sorted(reverse_graph.get(module, ()), reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    stack.append(source)
        if len(component) > 1 or start in graph.get(start, set()):
            components.append(sorted(component))

    return sorted(components)


def _cycle_findings(
    cycles: list[list[str]],
    locations: dict[tuple[str, str], Location],
) -> list[Finding]:
    findings = []
    for cycle in cycles:
        members = set(cycle)
        location = next(
            (
                value
                for (source, target), value in sorted(locations.items())
                if source in members and target in members
            ),
            Location(path=".", line=1, column=1),
        )
        findings.append(Finding(
            rule_id="PY-PKG-001",
            category="package-health",
            severity="warning",
            confidence="high",
            message=f"Circular import group detected: {', '.join(cycle)}.",
            location=location,
            remediation=(
                "Move shared contracts to a lower-level module or invert the "
                "dependency between these modules."
            ),
        ))
    return findings


def _entry_point_findings(
    metadata: dict,
    module_paths: dict[str, str],
) -> list[Finding]:
    project = _table(metadata.get("project"))
    scripts = _table(project.get("scripts"))
    findings = []
    for name, target in sorted(scripts.items()):
        if not isinstance(target, str):
            continue
        module = target.partition(":")[0].strip()
        if module and module not in module_paths:
            findings.append(Finding(
                rule_id="PY-PKG-002",
                category="package-health",
                severity="error",
                confidence="high",
                message=(
                    f"Console script '{name}' targets missing local module "
                    f"'{module}'."
                ),
                location=Location("pyproject.toml", 1, 1),
                remediation=(
                    "Correct the entry-point module or include it "
                    "in the package."
                ),
            ))
    return findings


def _finding_key(finding: Finding) -> tuple:
    return (
        finding.location.path,
        finding.location.line,
        finding.location.column,
        finding.rule_id,
    )
