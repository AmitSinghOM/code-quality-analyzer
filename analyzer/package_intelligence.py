"""Passive Python package metadata and import-graph analysis."""

from __future__ import annotations

import ast
import re
import stat
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
        suppressions_by_path: (
            dict[str, frozenset[tuple[int, str]]] | None
        ) = None,
    ) -> None:
        self.root = root
        self.parsed_files = parsed_files
        self.redact_paths = redact_paths
        self.suppressions_by_path = suppressions_by_path or {}
        self.result = PackageIntelligence()
        self.findings: list[Finding] = []
        self.errors = 0

    def analyze(self) -> PackageIntelligence:
        metadata = self._read_metadata()
        namespace_discovery = _namespace_discovery(metadata)
        module_paths = _module_paths(
            self.parsed_files,
            namespace_discovery,
        )
        self.result.layout = _layout(module_paths)
        if self.result.layout == "src":
            self.result.source_roots = ["src"]
        elif self.result.layout == "flat":
            self.result.source_roots = _flat_source_roots(
                module_paths,
                namespace_discovery,
            )
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
        for path in sorted(module_paths.values()):
            self.findings.extend(_public_api_findings(
                path,
                self.parsed_files[path],
                self.suppressions_by_path.get(path, frozenset()),
                redact_paths=self.redact_paths,
            ))
        if metadata is not None:
            self.findings.extend(_entry_point_findings(metadata, module_paths))
            self.findings.extend(_package_data_findings(
                self.root,
                metadata,
                module_paths,
                namespace_discovery,
            ))
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


class _AllSafetyVisitor(ast.NodeVisitor):
    """Reject modules whose public API declaration may be dynamic."""

    def __init__(self, candidate: ast.Assign | ast.AnnAssign) -> None:
        self.candidate = candidate
        self.unsafe = False

    def visit_Assign(self, node: ast.Assign) -> None:
        if node is self.candidate:
            self.visit(node.value)
            return
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node is self.candidate:
            if node.value is not None:
                self.visit(node.value)
            return
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id == "__all__":
            self.unsafe = True

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.partition(".")[0]
            if bound == "__all__":
                self.unsafe = True

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*" or (alias.asname or alias.name) == "__all__":
                self.unsafe = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name in {"__all__", "__getattr__"}:
            self.unsafe = True

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node.name in {"__all__", "__getattr__"}:
            self.unsafe = True

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node.name == "__all__":
            self.unsafe = True

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"exec", "globals", "locals"}
        ):
            self.unsafe = True
        self.generic_visit(node)


class _ModuleBindingVisitor(ast.NodeVisitor):
    """Collect names bound in module scope, including control-flow suites."""

    def __init__(self) -> None:
        self.bindings: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.bindings.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.bindings.add(alias.asname or alias.name.partition(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.bindings.add(alias.asname or alias.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bindings.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bindings.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bindings.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ListComp(self, node: ast.ListComp) -> None:
        return

    def visit_SetComp(self, node: ast.SetComp) -> None:
        return

    def visit_DictComp(self, node: ast.DictComp) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        return

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bindings.add(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bindings.add(node.name)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.bindings.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bindings.add(node.rest)
        self.generic_visit(node)


def _public_api_findings(
    path: str,
    tree: ast.AST,
    suppressions: frozenset[tuple[int, str]],
    redact_paths: bool = False,
) -> list[Finding]:
    exports = _literal_all_exports(tree)
    if exports is None:
        return []

    collector = _ModuleBindingVisitor()
    collector.visit(tree)
    findings = []
    seen: set[str] = set()
    for name, node in exports:
        if name in seen:
            finding = _public_api_finding(
                "PY-PKG-005",
                name,
                node,
                path,
                redact_paths,
            )
        else:
            seen.add(name)
            if name in collector.bindings:
                continue
            finding = _public_api_finding(
                "PY-PKG-004",
                name,
                node,
                path,
                redact_paths,
            )
        if (node.lineno, finding.rule_id) not in suppressions:
            findings.append(finding)
    return findings


def _literal_all_exports(
    tree: ast.AST,
) -> list[tuple[str, ast.Constant]] | None:
    if not isinstance(tree, ast.Module):
        return None
    candidates = [
        statement
        for statement in tree.body
        if _is_direct_all_assignment(statement)
    ]
    if len(candidates) != 1:
        return None

    candidate = candidates[0]
    safety = _AllSafetyVisitor(candidate)
    safety.visit(tree)
    if safety.unsafe:
        return None

    value = candidate.value
    if not isinstance(value, ast.List | ast.Tuple):
        return None
    exports = []
    for element in value.elts:
        if not (
            isinstance(element, ast.Constant)
            and isinstance(element.value, str)
        ):
            return None
        exports.append((element.value, element))
    return exports


def _is_direct_all_assignment(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Assign):
        return (
            len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "__all__"
        )
    return (
        isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and statement.target.id == "__all__"
        and statement.value is not None
        and statement.simple == 1
    )


def _public_api_finding(
    rule_id: str,
    name: str,
    node: ast.Constant,
    path: str,
    redact_paths: bool,
) -> Finding:
    location = Location(
        path=Path(path).name if redact_paths else path,
        line=node.lineno,
        column=node.col_offset + 1,
        end_line=getattr(node, "end_lineno", None),
        end_column=(
            node.end_col_offset + 1
            if getattr(node, "end_col_offset", None) is not None
            else None
        ),
        identity_path=path,
    )
    if rule_id == "PY-PKG-004":
        return Finding(
            rule_id=rule_id,
            category="package-health",
            severity="error",
            confidence="high",
            message=(
                f"Literal __all__ export '{name}' has no module-level "
                "binding."
            ),
            location=location,
            remediation=(
                "Define or import the exported name at module scope, or "
                "remove it from __all__."
            ),
        )
    return Finding(
        rule_id=rule_id,
        category="package-health",
        severity="warning",
        confidence="high",
        message=f"Literal __all__ exports '{name}' more than once.",
        location=location,
        remediation="Remove the repeated name from __all__.",
    )


def _table(value) -> dict:
    return value if isinstance(value, dict) else {}


def _optional_string(value) -> str | None:
    return value if isinstance(value, str) else None


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


_SETUPTOOLS_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
}
_PACKAGE_DATA_MAX_KEYS = 256
_PACKAGE_DATA_MAX_VALUES = 1024
_PACKAGE_DATA_MAX_TEXT = 512
_SETUPTOOLS_REQUIREMENT = re.compile(
    r"setuptools(?:\s*(?:===|==|~=|!=|<=|>=|<|>)[^;]+)?",
    re.IGNORECASE,
)


def _package_data_findings(
    root: Path,
    metadata: dict,
    module_paths: dict[str, str],
    namespace_discovery: _NamespaceDiscovery | None,
) -> list[Finding]:
    declarations = _package_data_declarations(root, metadata)
    if not declarations:
        return []
    package_directories = _package_directories(
        module_paths,
        namespace_discovery,
    )
    findings = []
    for package, targets in sorted(declarations.items()):
        directories = package_directories.get(package, set())
        if len(directories) != 1:
            continue
        package_directory = next(iter(directories))
        for target in targets:
            parts = _literal_package_data_parts(target)
            if parts is None:
                continue
            if _package_data_target_status(
                root,
                package_directory,
                parts,
            ) != "missing":
                continue
            findings.append(Finding(
                rule_id="PY-PKG-006",
                category="package-health",
                severity="warning",
                confidence="high",
                message=(
                    f"Static package-data declaration for '{package}' names "
                    f"missing source file '{target}'."
                ),
                location=Location("pyproject.toml", 1, 1),
                remediation=(
                    "Add the file, correct the literal path, or disable the "
                    "rule when a documented build step generates it."
                ),
            ))
    return findings


def _package_data_declarations(
    root: Path,
    metadata: dict,
) -> dict[str, tuple[str, ...]] | None:
    tool = _table(metadata.get("tool"))
    setuptools = _table(tool.get("setuptools"))
    raw_declarations = setuptools.get("package-data")
    if raw_declarations is None:
        return {}
    if not isinstance(raw_declarations, dict):
        return None

    build_system = _table(metadata.get("build-system"))
    if build_system.get("build-backend") not in _SETUPTOOLS_BACKENDS:
        return None
    if "backend-path" in build_system:
        return None
    requirements = build_system.get("requires")
    if not (
        isinstance(requirements, list)
        and len(requirements) == 1
        and isinstance(requirements[0], str)
        and _SETUPTOOLS_REQUIREMENT.fullmatch(requirements[0].strip())
    ):
        return None
    if any(
        path.exists() or path.is_symlink()
        for path in (root / "setup.py", root / "setup.cfg")
    ):
        return None
    if "cmdclass" in setuptools or "package-dir" in setuptools:
        return None
    if len(raw_declarations) > _PACKAGE_DATA_MAX_KEYS:
        return None

    declarations = {}
    total_values = 0
    for package, values in raw_declarations.items():
        if not _valid_package_data_key(package):
            return None
        if not isinstance(values, list):
            return None
        total_values += len(values)
        if total_values > _PACKAGE_DATA_MAX_VALUES:
            return None
        if any(
            not isinstance(value, str)
            or len(value) > _PACKAGE_DATA_MAX_TEXT
            or _literal_package_data_parts(value) is None
            for value in values
        ):
            return None
        declarations[package] = tuple(sorted(set(values)))
    return declarations


def _valid_package_data_key(value) -> bool:
    if not isinstance(value, str) or len(value) > _PACKAGE_DATA_MAX_TEXT:
        return False
    parts = value.split(".")
    return bool(parts) and all(part.isidentifier() for part in parts)


def _literal_package_data_parts(value: str) -> tuple[str, ...] | None:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(character in value for character in "*?[]")
    ):
        return None
    parts = tuple(value.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        return None
    return parts


def _package_directories(
    module_paths: dict[str, str],
    namespace_discovery: _NamespaceDiscovery | None,
) -> dict[str, set[Path]]:
    directories: dict[str, set[Path]] = {}
    for module, path in sorted(module_paths.items()):
        source = Path(path)
        if source.name == "__init__.py":
            directories.setdefault(module, set()).add(source.parent)
        if namespace_discovery is None:
            continue
        _add_namespace_package_directories(
            directories,
            module,
            source,
            namespace_discovery,
        )
    return directories


def _add_namespace_package_directories(
    directories: dict[str, set[Path]],
    module: str,
    source: Path,
    discovery: _NamespaceDiscovery,
) -> None:
    path_parts = source.parts
    if not any(
        path_parts[:len(root)] == root
        for root in discovery.roots
    ):
        return
    if not any(
        module == prefix or module.startswith(f"{prefix}.")
        for prefix in discovery.prefixes
    ):
        return

    module_parts = module.split(".")
    package_count = (
        len(module_parts)
        if source.name == "__init__.py"
        else len(module_parts) - 1
    )
    if package_count <= 0:
        return
    root_parts = source.parent.parts[:-package_count]
    for count in range(1, package_count + 1):
        package = ".".join(module_parts[:count])
        if not any(
            package == prefix or package.startswith(f"{prefix}.")
            for prefix in discovery.prefixes
        ):
            continue
        directory = Path(*root_parts, *module_parts[:count])
        directories.setdefault(package, set()).add(directory)


def _package_data_target_status(
    root: Path,
    package_directory: Path,
    target_parts: tuple[str, ...],
) -> str | None:
    current = root
    relative_parts = package_directory.parts + target_parts
    for index, part in enumerate(relative_parts):
        current /= part
        try:
            details = current.lstat()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return None
        if stat.S_ISLNK(details.st_mode):
            return None
        is_target = index == len(relative_parts) - 1
        if is_target:
            return "present" if stat.S_ISREG(details.st_mode) else None
        if not stat.S_ISDIR(details.st_mode):
            return None
    return None


@dataclass(frozen=True, slots=True)
class _NamespaceDiscovery:
    """Validated static setuptools namespace discovery configuration."""

    roots: tuple[tuple[str, ...], ...]
    prefixes: tuple[str, ...]


def _namespace_discovery(metadata: dict | None) -> _NamespaceDiscovery | None:
    if metadata is None:
        return None
    build_system = _table(metadata.get("build-system"))
    if build_system.get("build-backend") not in {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
    }:
        return None

    tool = _table(metadata.get("tool"))
    setuptools = _table(tool.get("setuptools"))
    if not setuptools or "package-dir" in setuptools:
        return None
    packages = _table(setuptools.get("packages"))
    find_config = packages.get("find")
    if not isinstance(find_config, dict):
        return None
    if set(find_config) - {"where", "include", "exclude", "namespaces"}:
        return None

    namespaces = find_config.get("namespaces", True)
    if not isinstance(namespaces, bool) or not namespaces:
        return None
    excluded = find_config.get("exclude", [])
    if not isinstance(excluded, list) or excluded:
        return None

    raw_prefixes = find_config.get("include")
    if not isinstance(raw_prefixes, list) or not raw_prefixes:
        return None
    prefixes = []
    for pattern in raw_prefixes:
        prefix = _namespace_prefix(pattern)
        if prefix is None:
            return None
        prefixes.append(prefix)

    raw_roots = find_config.get("where", ["."])
    if not isinstance(raw_roots, list) or not raw_roots:
        return None
    roots = []
    for value in raw_roots:
        root = _namespace_root(value)
        if root is None:
            return None
        roots.append(root)
    roots = sorted(set(roots))
    if _roots_overlap(roots):
        return None
    return _NamespaceDiscovery(
        roots=tuple(roots),
        prefixes=tuple(sorted(set(prefixes))),
    )


def _namespace_prefix(value) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = value[:-2] if value.endswith(".*") else value
    parts = prefix.split(".")
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return prefix


def _namespace_root(value) -> tuple[str, ...] | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    return tuple(part for part in candidate.parts if part != ".")


def _roots_overlap(roots: list[tuple[str, ...]]) -> bool:
    for index, root in enumerate(roots):
        for other in roots[index + 1:]:
            shorter, longer = sorted((root, other), key=len)
            if longer[:len(shorter)] == shorter:
                return True
    return False


def _module_paths(
    parsed_files: dict[str, ast.AST],
    namespace_discovery: _NamespaceDiscovery | None = None,
) -> dict[str, str]:
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

        module = _module_name(parts)
        if module is not None:
            modules[module] = path

    if not uses_src and namespace_discovery is not None:
        modules.update(_namespace_module_paths(paths, namespace_discovery))
    return modules


def _namespace_module_paths(
    paths: list[str],
    discovery: _NamespaceDiscovery,
) -> dict[str, str]:
    modules = {}
    for path in paths:
        path_parts = Path(path).parts
        for root in discovery.roots:
            if path_parts[:len(root)] != root:
                continue
            module = _module_name(list(path_parts[len(root):]))
            if module is None:
                continue
            if any(
                module == prefix or module.startswith(f"{prefix}.")
                for prefix in discovery.prefixes
            ):
                modules[module] = path
            break
    return modules


def _module_name(parts: list[str]) -> str | None:
    if not parts or not parts[-1].endswith(".py"):
        return None
    parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _flat_source_roots(
    module_paths: dict[str, str],
    discovery: _NamespaceDiscovery | None,
) -> list[str]:
    if discovery is None:
        return ["."]
    roots = set()
    unmatched = False
    for path in module_paths.values():
        path_parts = Path(path).parts
        matches = [
            root
            for root in discovery.roots
            if path_parts[:len(root)] == root
        ]
        if matches:
            roots.update("/".join(root) or "." for root in matches)
        else:
            unmatched = True
    if unmatched or not roots:
        roots.add(".")
    return sorted(roots, key=lambda value: (value != ".", value))


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
                        identity_path=path,
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
