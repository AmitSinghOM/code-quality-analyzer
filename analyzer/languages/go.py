"""Bounded Go adapter and high-confidence pilot rule pack."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding, Location
from ..protocols import (
    DEFAULT_CAPABILITY_VERSION,
    PLUGIN_API_VERSION,
    ParsedFile,
    ProjectContext,
    ProviderResult,
    SourceFile,
)
from ..registry import PluginRegistry

GO_ADAPTER_VERSION = "1.0.0"
GO_RULE_PACK_ID = "go-core"

_PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_]\w*)\s*$")
_SINGLE_IMPORT = re.compile(
    r'(?m)^\s*import\s+(?:(?P<alias>[A-Za-z_]\w*|[._])\s+)?'
    r'"(?P<path>[^"]+)"'
)
_IMPORT_BLOCK = re.compile(r"(?s)\bimport\s*\((.*?)\)")
_IMPORT_SPEC = re.compile(
    r'(?m)^\s*(?:(?P<alias>[A-Za-z_]\w*|[._])\s+)?'
    r'"(?P<path>[^"]+)"'
)
_MODULE = re.compile(r"(?m)^\s*module\s+([^\s]+)\s*$")

_KNOWN_ERROR_CALLS = (
    "encoding/json.Marshal",
    "encoding/json.MarshalIndent",
    "encoding/json.Unmarshal",
    "io.ReadAll",
    "net/http.NewRequest",
    "net/http.NewRequestWithContext",
    "net/url.Parse",
    "os.Create",
    "os.Open",
    "os.ReadFile",
    "os.WriteFile",
    "strconv.Atoi",
    "strconv.ParseBool",
    "strconv.ParseFloat",
    "strconv.ParseInt",
    "strconv.ParseUint",
)
_CALL_PATTERN = "|".join(
    re.escape(call.rpartition(".")[2])
    for call in _KNOWN_ERROR_CALLS
)
_IGNORED_ERROR = re.compile(
    rf"(?P<first>[A-Za-z_]\w*|_)\s*,\s*(?P<ignored>_)\s*:?=\s*"
    rf"(?P<qualifier>[A-Za-z_]\w*)\.(?P<call>{_CALL_PATTERN})\s*\("
)


@dataclass(frozen=True, slots=True, order=True)
class GoImport:
    """One Go import with its effective local qualifier."""

    path: str
    local_name: str | None
    kind: str


@dataclass(frozen=True, slots=True)
class GoFacts:
    """Small adapter-owned Go fact model."""

    package_name: str
    imports: tuple[GoImport, ...]
    code_text: str


@dataclass(frozen=True, slots=True)
class GoPackage:
    """Aggregated passive facts for one project-relative package directory."""

    directory: str
    package_names: tuple[str, ...]
    files: tuple[str, ...]
    imports: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "directory": self.directory,
            "package_names": list(self.package_names),
            "files": list(self.files),
            "imports": list(self.imports),
        }


@dataclass(frozen=True, slots=True)
class GoPackageGraph:
    """Passive Go package inventory and local import edges."""

    module_path: str | None = None
    packages: tuple[GoPackage, ...] = ()
    local_edges: tuple[tuple[str, str], ...] = ()
    conflicts: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "module_path": self.module_path,
            "packages": [package.as_dict() for package in self.packages],
            "local_edges": [list(edge) for edge in self.local_edges],
            "conflicts": list(self.conflicts),
        }


class GoLanguageAdapter:
    """Extract bounded Go package/import facts without executing Go tools."""

    language_id = "go"
    adapter_version = GO_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".go",)

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_comments_and_strings(
            source.content
        )
        metadata_text, metadata_complete = _strip_comments_and_strings(
            source.content,
            blank_strings=False,
        )
        package = _PACKAGE.search(code_text)
        facts = (
            GoFacts(
                package_name=package.group(1),
                imports=_imports(metadata_text),
                code_text=code_text,
            )
            if package is not None
            else None
        )
        return ParsedFile(
            source=source,
            artifact=facts,
            facts=facts,
            line_count=len(source.content.splitlines()),
            complete=(
                lexical_complete
                and metadata_complete
                and facts is not None
            ),
        )


class GoIgnoredErrorRule:
    """Detect ignored errors from a narrow set of standard-library calls."""

    rule_id = "GO-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, GoFacts):
            return
        allowed_calls = _allowed_calls(parsed.facts.imports)
        for match in _IGNORED_ERROR.finditer(parsed.facts.code_text):
            call = match.group("call")
            qualifier = match.group("qualifier")
            if (qualifier, call) not in allowed_calls:
                continue
            offset = match.start("ignored")
            line, column = _line_column(parsed.facts.code_text, offset)
            yield Finding(
                rule_id=self.rule_id,
                category="correctness",
                severity="warning",
                confidence="high",
                message=(
                    f"Error returned by {qualifier}.{call} "
                    "is discarded."
                ),
                location=Location(
                    path=parsed.source.display_path,
                    line=line,
                    column=column,
                    identity_path=parsed.source.identity_path,
                ),
                remediation=(
                    "Bind the error result and handle or explicitly return it."
                ),
            )


class GoPackageGraphProvider:
    """Build a passive multi-file Go package graph from shared facts."""

    provider_id = "go-package-graph"
    language_id = "go"
    capability = "package-graph"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True

    def analyze(self, project: ProjectContext) -> ProviderResult:
        module_path, module_error = _read_module_path(
            project.root,
            project.max_file_size,
        )
        grouped: dict[str, list[ParsedFile]] = {}
        for identity_path, parsed in sorted(project.parsed_files.items()):
            if isinstance(parsed.facts, GoFacts):
                graph_path = (
                    parsed.source.display_path
                    if project.redact_paths
                    else identity_path
                )
                directory = Path(graph_path).parent.as_posix()
                grouped.setdefault(directory, []).append(parsed)

        packages = []
        conflicts = []
        directories = set(grouped)
        for directory, parsed_files in sorted(grouped.items()):
            names = tuple(sorted({
                parsed.facts.package_name
                for parsed in parsed_files
                if isinstance(parsed.facts, GoFacts)
            }))
            if not _compatible_package_names(names):
                conflicts.append(directory)
            files = tuple(sorted(
                parsed.source.display_path for parsed in parsed_files
            ))
            imports = tuple(sorted({
                imported.path
                for parsed in parsed_files
                if isinstance(parsed.facts, GoFacts)
                for imported in parsed.facts.imports
            }))
            packages.append(GoPackage(directory, names, files, imports))

        edges = set()
        if module_path:
            for package in packages:
                for imported in package.imports:
                    target = _local_import_directory(module_path, imported)
                    if target in directories:
                        edges.add((package.directory, target))

        graph = GoPackageGraph(
            module_path=module_path,
            packages=tuple(packages),
            local_edges=tuple(sorted(edges)),
            conflicts=tuple(conflicts),
        )
        errors = int(module_error) + len(conflicts)
        return ProviderResult(
            payload=graph,
            health={
                "errors": errors,
                "complete": errors == 0,
                "package_count": len(packages),
                "local_edge_count": len(edges),
            },
        )


class GoRulePack:
    """Run the bounded built-in Go pilot rules."""

    rule_pack_id = GO_RULE_PACK_ID
    language_id = "go"
    ruleset_version = "2.5.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (GoIgnoredErrorRule(),)

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not parsed.complete:
            return ()
        findings = [
            finding
            for rule in self.rules
            for finding in rule.evaluate(parsed)
        ]
        return tuple(sorted(
            findings,
            key=lambda finding: (
                finding.location.path,
                finding.location.line,
                finding.location.column,
                finding.rule_id,
            ),
        ))


def register_go_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Go pilot adapter and rules."""
    registry.register_language(GoLanguageAdapter())
    registry.register_rule_pack(GoRulePack())
    registry.register_project_provider(GoPackageGraphProvider())
    return registry


def _allowed_calls(imports: tuple[GoImport, ...]) -> set[tuple[str, str]]:
    allowed = set()
    qualifiers = {
        imported.path: imported.local_name
        for imported in imports
        if imported.kind in {"default", "alias"}
    }
    for qualified_call in _KNOWN_ERROR_CALLS:
        module, _, call = qualified_call.rpartition(".")
        qualifier = qualifiers.get(module)
        if qualifier:
            allowed.add((qualifier, call))
    return allowed


def _imports(source: str) -> tuple[GoImport, ...]:
    imports = {
        _go_import(match.group("path"), match.group("alias"))
        for match in _SINGLE_IMPORT.finditer(source)
    }
    for block in _IMPORT_BLOCK.findall(source):
        imports.update(
            _go_import(match.group("path"), match.group("alias"))
            for match in _IMPORT_SPEC.finditer(block)
        )
    return tuple(sorted(imports))


def _go_import(path: str, alias: str | None) -> GoImport:
    if alias == "_":
        return GoImport(path, None, "blank")
    if alias == ".":
        return GoImport(path, None, "dot")
    if alias:
        return GoImport(path, alias, "alias")
    return GoImport(path, path.rpartition("/")[2], "default")


def _read_module_path(
    root: Path,
    max_file_size: int,
) -> tuple[str | None, bool]:
    module_file = root / "go.mod"
    try:
        resolved = module_file.resolve(strict=True)
        resolved.relative_to(root.resolve())
        if not resolved.is_file() or resolved.stat().st_size > max_file_size:
            return None, True
        content = resolved.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, False
    except (OSError, UnicodeError, ValueError):
        return None, True
    match = _MODULE.search(content)
    return (match.group(1), False) if match else (None, True)


def _compatible_package_names(names: tuple[str, ...]) -> bool:
    if len(names) <= 1:
        return True
    return len(names) == 2 and any(
        other == f"{name}_test"
        for name in names
        for other in names
        if name != other
    )


def _local_import_directory(module_path: str, imported: str) -> str | None:
    if imported == module_path:
        return "."
    prefix = f"{module_path}/"
    return imported[len(prefix):] if imported.startswith(prefix) else None


def _line_column(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _strip_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank Go comments and optional string contents, preserving layout."""
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    complete = True

    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if current == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if current in {'"', "'", "`"}:
                quote = current
                if blank_strings:
                    output[index] = " "
                state = "raw_string" if current == "`" else "string"
                index += 1
                continue
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        elif state == "block_comment":
            if current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if current != "\n":
                output[index] = " "
            index += 1
            continue
        elif state == "raw_string":
            if current == "`":
                if blank_strings:
                    output[index] = " "
                state = "code"
            elif blank_strings and current != "\n":
                output[index] = " "
            index += 1
            continue
        elif state == "string":
            if current == "\\" and following:
                if blank_strings:
                    output[index] = " "
                    if following != "\n":
                        output[index + 1] = " "
                index += 2
                continue
            if current == quote:
                if blank_strings:
                    output[index] = " "
                state = "code"
            elif blank_strings and current != "\n":
                output[index] = " "
            index += 1
            continue

        index += 1

    if state in {"block_comment", "raw_string", "string"}:
        complete = False
    return "".join(output), complete
