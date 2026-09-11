"""Bounded C#/.NET pilot adapter, rule pack, signal provider, and package provider.

Facts are extracted by regex from blanked source. The adapter never
executes ``dotnet``, MSBuild, or NuGet.

String forms handled by the blanker: regular ``"..."``, verbatim
``@"..."`` (doubled-quote escapes), interpolated ``$"..."`` with nested
``{...}`` holes (``{{`` escapes), verbatim-interpolated ``$@""``/``@$""``,
raw ``\"\"\"...\"\"\"``, and ``'c'`` char literals. Interpolation holes are
lexed as code (they may contain strings and braces) but blanked, so
string content is never evidence.

Known pilot bounds, accepted deliberately:

- Raw interpolated strings (``$\"\"\"``) are blanked whole without
  tracking holes — conservative, never leaks.
- Dependency drift compares ``using`` namespaces to ``PackageReference``
  names by prefix in either direction; namespaces that do not follow the
  package name (rare) are not detected as drift.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from ..csharp_patterns import CSHARP_DESIGN_PATTERNS, CSHARP_DSA_PATTERNS
from ..findings import Finding, Location
from ..manifests import (
    MAX_MANIFEST_BYTES,
    MAX_MANIFESTS,
    discover_manifests,
    local_name,
    locate_glob,
    manifest_chain,
    manifest_report_path,
    nearest_manifest_dir,
    parse_xml_hardened,
)
from ..protocols import (
    DEFAULT_CAPABILITY_VERSION,
    PLUGIN_API_VERSION,
    ParsedFile,
    ProjectContext,
    ProviderResult,
    SignalObservation,
    SourceFile,
)
from ..registry import PluginRegistry
from ..safe_io import SafeReadError, read_bounded_text
from ..signals import FileSignals, pattern_is_present
from ._shared import RegexRulePackBase, empty_catch_finding
from ._parity import blocking_in_async_findings, broad_catch_findings
from ._sql import CSHARP_SQL, dynamic_sql_findings

CSHARP_ADAPTER_VERSION = "1.0.0"
CSHARP_CACHE_CODEC_VERSION = "1.0.0"
CSHARP_RULE_PACK_ID = "csharp-core"
_MAX_CACHED_STRING = 4 * 1024 * 1024
_MAX_IDENTIFIERS = 20_000
_MAX_USINGS = 20_000

_USING = re.compile(
    r"(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?"
    r"(?:[A-Za-z_]\w*\s*=\s*)?([A-Za-z_][\w.]*)\s*;"
)
_NAMESPACE = re.compile(r"\bnamespace\s+([A-Za-z_][\w.]*)")
_TYPE_DECLARATION = re.compile(
    r"\b(?:class|interface|enum|struct|record)\s+([A-Za-z_@][\w]*)"
)
_ATTRIBUTE = re.compile(r"(?m)(?:^\s*\[|\[)\s*([A-Z]\w*)")
_GENERIC_USE = re.compile(r"\b([A-Z]\w*)\s*<")
_NEW_TARGET = re.compile(r"\bnew\s+([A-Za-z_][\w.]*)\s*[(<\[{]")
_SELECTOR_CALL = re.compile(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(")
_BARE_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# ``Type name`` where a terminator follows: fields, locals, parameters.
_VARIABLE_DECLARATION = re.compile(
    # Possessive runs: `a.a.a.…` chains must not backtrack (test_lexer_fuzz).
    # `(?<![\w.])`: attempt only at a chain start (see java.py).
    r"(?<![\w.])[A-Za-z_][\w.]*+(?:<[^<>;{}]*+>)?(?:\[\])*+\??\s++([a-z_@]\w*+)\s*+(?=[;=,)])"
)
_EMPTY_CATCH = re.compile(
    r"\bcatch\b(?:\s*\([^)]*\))?(?:\s*when\s*\([^)]*\))?\s*\{\s*\}"
)
_KEYWORDS = frozenset({
    "abstract", "as", "async", "await", "base", "bool", "break", "byte",
    "case", "catch", "char", "checked", "class", "const", "continue",
    "decimal", "default", "delegate", "do", "double", "else", "enum",
    "event", "explicit", "extern", "false", "finally", "fixed", "float",
    "for", "foreach", "get", "goto", "if", "implicit", "in", "init", "int",
    "interface", "internal", "is", "lock", "long", "namespace", "new",
    "null", "object", "operator", "out", "override", "params", "private",
    "protected", "public", "readonly", "record", "ref", "return", "sbyte",
    "sealed", "set", "short", "sizeof", "stackalloc", "static", "string",
    "struct", "switch", "this", "throw", "true", "try", "typeof", "uint",
    "ulong", "unchecked", "unsafe", "ushort", "using", "var", "virtual",
    "void", "volatile", "when", "where", "while", "yield", "nameof",
})
# Namespaces provided by the runtime or shared frameworks rather than by
# a PackageReference; never drift.
_FRAMEWORK_PREFIXES = (
    "System", "Microsoft.AspNetCore", "Microsoft.Extensions", "Microsoft.NET",
    "Microsoft.CSharp", "Microsoft.VisualBasic", "Microsoft.Win32", "Windows",
    "Internal",
)


def _strip_csharp_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank comments and optional string contents, preserving layout."""
    output = list(source)
    index = 0
    state = "code"
    complete = True
    # Each open interpolation hole: (unmatched brace depth, string state
    # to resume when the hole closes).
    holes: list[tuple[int, str]] = []

    def blank(position: int) -> None:
        if blank_strings and source[position] != "\n":
            output[position] = " "

    def blank_run(start: int, count: int) -> None:
        for offset in range(count):
            blank(start + offset)

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
            if source.startswith(('$@"', '@$"'), index):
                blank_run(index, 3)
                state = "verbatim_interp"
                index += 3
                continue
            if source.startswith(('$"""', '"""'), index):
                width = 4 if current == "$" else 3
                blank_run(index, width)
                state = "raw"
                index += width
                continue
            if source.startswith('$"', index):
                blank_run(index, 2)
                state = "interp"
                index += 2
                continue
            if source.startswith('@"', index):
                blank_run(index, 2)
                state = "verbatim"
                index += 2
                continue
            if current == '"':
                blank(index)
                state = "string"
                index += 1
                continue
            if current == "'":
                blank(index)
                state = "char"
                index += 1
                continue
            if holes:
                depth, resume = holes[-1]
                if current == "{":
                    holes[-1] = (depth + 1, resume)
                elif current == "}":
                    if depth == 0:
                        holes.pop()
                        state = resume
                    else:
                        holes[-1] = (depth - 1, resume)
                blank(index)
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
        elif state == "raw":
            if source.startswith('"""', index):
                blank_run(index, 3)
                state = "code"
                index += 3
                continue
            blank(index)
            index += 1
            continue
        elif state in {"string", "char", "interp"}:
            quote = "'" if state == "char" else '"'
            if current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
                continue
            if state == "interp" and current == "{":
                if following == "{":
                    blank_run(index, 2)
                    index += 2
                    continue
                blank(index)
                holes.append((0, "interp"))
                state = "code"
                index += 1
                continue
            if current == quote:
                blank(index)
                state = "code"
            elif current == "\n":
                state = "code"
                complete = False
            else:
                blank(index)
            index += 1
            continue
        elif state in {"verbatim", "verbatim_interp"}:
            if current == '"':
                if following == '"':
                    blank_run(index, 2)
                    index += 2
                    continue
                blank(index)
                state = "code"
                index += 1
                continue
            if state == "verbatim_interp" and current == "{":
                if following == "{":
                    blank_run(index, 2)
                    index += 2
                    continue
                blank(index)
                holes.append((0, "verbatim_interp"))
                state = "code"
                index += 1
                continue
            blank(index)
            index += 1
            continue
        index += 1

    if state != "code" or holes:
        complete = state in {"line_comment"} and not holes
    return "".join(output), complete


def _usings(metadata_text: str) -> tuple[str, ...]:
    found = {match.group(1) for match in _USING.finditer(metadata_text)}
    return tuple(sorted(found)[:_MAX_USINGS])


def _namespaces(code_text: str) -> tuple[str, ...]:
    return tuple(sorted({m.group(1) for m in _NAMESPACE.finditer(code_text)}))


def _identifiers(code_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in (
        _TYPE_DECLARATION, _ATTRIBUTE, _GENERIC_USE, _BARE_CALL,
        _VARIABLE_DECLARATION,
    ):
        for match in pattern.finditer(code_text):
            names.add(match.group(1).lstrip("@"))
            if len(names) >= _MAX_IDENTIFIERS:
                break
    for match in _NEW_TARGET.finditer(code_text):
        target = match.group(1)
        names.add(target)
        names.add(target.rpartition(".")[2])
    for match in _SELECTOR_CALL.finditer(code_text):
        qualifier, member = match.group(1), match.group(2)
        names.update((qualifier, member, f"{qualifier}.{member}"))
        if len(names) >= _MAX_IDENTIFIERS:
            break
    return tuple(sorted(names - _KEYWORDS)[:_MAX_IDENTIFIERS])


class CSharpFacts:
    """Small adapter-owned C# fact model."""

    __slots__ = ("namespaces", "usings", "identifiers", "code_text")

    def __init__(
        self,
        namespaces: tuple[str, ...],
        usings: tuple[str, ...],
        identifiers: tuple[str, ...],
        code_text: str,
    ) -> None:
        self.namespaces = namespaces
        self.usings = usings
        self.identifiers = identifiers
        self.code_text = code_text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CSharpFacts) and (
            self.namespaces, self.usings, self.identifiers, self.code_text,
        ) == (
            other.namespaces, other.usings, other.identifiers, other.code_text,
        )


class CSharpLanguageAdapter:
    """Extract bounded C# facts without executing any toolchain."""

    language_id = "csharp"
    adapter_version = CSHARP_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".cs",)
    cache_codec_version = CSHARP_CACHE_CODEC_VERSION
    cache_runtime_version = "portable"

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_csharp_comments_and_strings(
            source.content
        )
        metadata_text, metadata_complete = _strip_csharp_comments_and_strings(
            source.content,
            blank_strings=False,
        )
        facts = CSharpFacts(
            namespaces=_namespaces(code_text),
            usings=_usings(metadata_text),
            identifiers=_identifiers(code_text),
            code_text=code_text,
        )
        return ParsedFile(
            source=source,
            artifact=facts,
            facts=facts,
            line_count=len(source.content.splitlines()),
            complete=lexical_complete and metadata_complete,
        )

    def serialize_parsed(self, parsed: ParsedFile) -> Mapping[str, object]:
        facts = parsed.facts
        if not isinstance(facts, CSharpFacts):
            raise TypeError("C# cache codec requires CSharpFacts")
        return {
            "line_count": parsed.line_count,
            "complete": parsed.complete,
            "facts": {
                "namespaces": list(facts.namespaces),
                "usings": list(facts.usings),
                "identifiers": list(facts.identifiers),
                "code_text": facts.code_text,
            },
        }

    def deserialize_parsed(
        self,
        source: SourceFile,
        payload: Mapping[str, object],
    ) -> ParsedFile:
        data = _exact_mapping(payload, {"line_count", "complete", "facts"})
        line_count = _nonnegative_int(data["line_count"])
        complete = _boolean(data["complete"])
        fact_data = _exact_mapping(
            data["facts"],
            {"namespaces", "usings", "identifiers", "code_text"},
        )
        facts = CSharpFacts(
            namespaces=_string_tuple(fact_data["namespaces"], _MAX_USINGS),
            usings=_string_tuple(fact_data["usings"], _MAX_USINGS),
            identifiers=_string_tuple(fact_data["identifiers"], _MAX_IDENTIFIERS),
            code_text=_string(fact_data["code_text"]),
        )
        return ParsedFile(source, facts, facts, line_count, complete)


class CSharpEmptyCatchRule:
    """Detect catch blocks whose blanked body is empty."""

    rule_id = "CS-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, CSharpFacts):
            return
        for match in _EMPTY_CATCH.finditer(parsed.facts.code_text):
            yield empty_catch_finding(self.rule_id, parsed, match, rethrow_word="exception")


class CSharpDynamicSqlRule:
    """Detect SQL text built with ``$""`` interpolation, ``+`` or ``Format``."""

    rule_id = "CS-COR-002"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, CSharpFacts):
            return
        yield from dynamic_sql_findings(self.rule_id, parsed, CSHARP_SQL)


# ``catch (Exception e)``, ``catch (System.Exception)`` and the bare ``catch``.
# An exception filter (``when (...)``) narrows the clause and is not reported.
_CS_BROAD_CATCH = re.compile(
    r"\bcatch\s*(?:\(\s*(?P<type>(?:System\.)?Exception)(?:\s+\w+)?\s*\))?\s*(?!when\b)\{"
)
# ``async`` modifier through the parameter list; lambdas (``async (x) =>``)
# and local functions match as well.
_CS_ASYNC_HEADER = re.compile(r"\basync\b[^;{]*?\([^()]*\)")
# ``.Result`` only on a call-shaped receiver (``GetAsync(x).Result``,
# ``task.Result`` where the name says Task): a bare ``msg.Result`` is a
# property on a plain object (found on StackExchange.Redis during
# calibration). ``.Wait()`` / ``GetResult()`` are Task-specific already.
_CS_BLOCKING = re.compile(
    r"(?:(?<=\))|(?<=[Tt]ask))\.Result\b(?!\s*=[^=])|\.Wait\s*\(|"
    r"\.GetAwaiter\s*\(\s*\)\s*\.GetResult\s*\(|\bThread\.Sleep\s*\("
)
# Nested lambdas own their own async-ness; blank their bodies.
_CS_NESTED = re.compile(r"=>\s*\{")


class CSharpBroadCatchRule:
    """Detect handlers that catch Exception or everything."""

    rule_id = "CS-COR-003"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, CSharpFacts):
            return
        yield from broad_catch_findings(self.rule_id, parsed, _CS_BROAD_CATCH)


class CSharpBlockingInAsyncRule:
    """Detect ``.Result`` / ``.Wait()`` / ``GetResult()`` inside ``async`` bodies."""

    rule_id = "CS-COR-004"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, CSharpFacts):
            return
        yield from blocking_in_async_findings(
            self.rule_id,
            parsed,
            async_header=_CS_ASYNC_HEADER,
            blocking_call=_CS_BLOCKING,
            nested_opener=_CS_NESTED,
            what="A synchronous wait on a Task",
        )


class CSharpRulePack(RegexRulePackBase):
    """Run the bounded built-in C# pilot rules."""

    rule_pack_id = CSHARP_RULE_PACK_ID
    language_id = "csharp"
    ruleset_version = "1.1.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (
            CSharpEmptyCatchRule(),
            CSharpDynamicSqlRule(),
            CSharpBroadCatchRule(),
            CSharpBlockingInAsyncRule(),
        )


class CSharpArchitectureSignalProvider:
    """Extract C# DSA and design signals from blanked adapter facts."""

    provider_id = "csharp-architecture-signals"
    language_id = "csharp"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        facts = parsed.facts
        if not isinstance(facts, CSharpFacts):
            raise TypeError("C# signal provider requires CSharpFacts")
        signals = FileSignals(
            path=parsed.source.path,
            line_count=parsed.line_count,
            code_text=facts.code_text.lower(),
            identifiers={name.lower() for name in facts.identifiers},
            imports={using.lower() for using in facts.usings},
        )
        for category, definitions in (
            ("architecture.dsa", CSHARP_DSA_PATTERNS),
            ("architecture.design", CSHARP_DESIGN_PATTERNS),
        ):
            for signal_id, definition in definitions.items():
                present, matched = pattern_is_present(signals, definition)
                if present:
                    yield SignalObservation(
                        category=category,
                        signal_id=signal_id,
                        description=definition["description"],
                        path=parsed.source.display_path,
                        evidence=tuple(matched),
                    )


class CSharpPackageProvider:
    """Passive .csproj discovery and using-vs-PackageReference drift."""

    provider_id = "csharp-package"
    language_id = "csharp"
    capability = "package"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True

    def analyze(self, project: ProjectContext) -> ProviderResult:
        located, truncated = discover_manifests(
            project.root,
            project.parsed_files,
            locate_glob("*.csproj"),
        )
        manifests = {
            directory: _load_csproj(project.root, directory, filename)
            for directory, filename in located
        }
        own_roots = _own_namespace_roots(project.parsed_files, manifests)
        findings: list[Finding] = []
        errors = 0
        for directory, info in manifests.items():
            if info["invalid"]:
                errors += 1
                report_path, identity = manifest_report_path(
                    directory, info["filename"], project.redact_paths,
                )
                findings.append(Finding(
                    rule_id="CS-PKG-002",
                    category="package-health",
                    severity="error",
                    confidence="high",
                    message=f"{identity} cannot be read as a valid project file.",
                    location=Location(report_path, 1, 1, identity_path=identity),
                    remediation=(
                        "Correct the project file syntax and run analysis again."
                    ),
                ))

        undeclared = _undeclared_by_manifest(
            project.parsed_files, manifests, own_roots, project.root,
        )
        for directory in sorted(undeclared):
            info = manifests[directory]
            report_path, identity = manifest_report_path(
                directory, info["filename"], project.redact_paths,
            )
            for namespace, example in undeclared[directory]:
                findings.append(Finding(
                    rule_id="CS-PKG-001",
                    category="package-health",
                    severity="warning",
                    confidence="medium",
                    message=(
                        f"Namespace '{namespace}' is used (for example in "
                        f"{example}) but no matching PackageReference is "
                        f"declared in {identity}."
                    ),
                    location=Location(report_path, 1, 1, identity_path=identity),
                    remediation=(
                        "Add the PackageReference to the project file or "
                        "remove the using directive."
                    ),
                ))

        payload = {
            "projects": [
                {
                    "path": manifest_report_path(d, info["filename"], False)[1],
                    "assembly": info["assembly"],
                    "invalid": info["invalid"],
                    "package_references": sorted(info["packages"]),
                    "undeclared_namespaces": [
                        namespace for namespace, _ in undeclared.get(d, [])
                    ],
                }
                for d, info in manifests.items()
            ],
            "projects_truncated": truncated,
        }
        return ProviderResult(
            payload=payload,
            health={"complete": not truncated, "errors": errors},
            findings=tuple(findings),
        )


def _load_csproj(root, directory: str, filename: str) -> dict:
    info = {
        "filename": filename,
        "assembly": filename[: -len(".csproj")],
        "packages": set(),
        "project_references": set(),
        "root_namespaces": set(),
        "invalid": False,
    }
    try:
        text = read_bounded_text(
            root / directory / filename, max_bytes=MAX_MANIFEST_BYTES, root=root,
        )
        element = parse_xml_hardened(text)
    except (SafeReadError, ValueError):
        info["invalid"] = True
        return info
    for node in element.iter():
        name = local_name(node.tag)
        if name == "PackageReference":
            package = node.get("Include") or node.get("Update")
            if package:
                info["packages"].add(package.strip())
        elif name == "ProjectReference":
            target = node.get("Include")
            if target:
                normalized = target.strip().replace("\\", "/")
                info["project_references"].add((
                    _resolve_project_reference(directory, normalized),
                    normalized.rsplit("/", 1)[-1],
                ))
        elif name in {"RootNamespace", "AssemblyName"} and node.text:
            info["root_namespaces"].add(node.text.strip())
            if name == "AssemblyName":
                info["assembly"] = node.text.strip()
    return info


def _resolve_project_reference(directory: str, target: str) -> str:
    """Return the project-relative directory a ProjectReference points to."""
    parts = directory.split("/") if directory else []
    for segment in target.replace("\\", "/").split("/")[:-1]:
        if segment in {"", "."}:
            continue
        if segment == "..":
            if parts:
                parts.pop()
        else:
            parts.append(segment)
    return "/".join(parts)


def _transitive_packages(directory: str, manifests: dict, root) -> set[str]:
    """Union PackageReferences across the ProjectReference graph.

    Referenced projects that were not discovered (no analyzed source
    beneath them) are loaded on demand, bounded by ``MAX_MANIFESTS``.
    """
    packages: set[str] = set()
    seen: set[str] = set()
    pending = [directory]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        info = manifests.get(current)
        if info is None:
            continue
        packages.update(info["packages"])
        for target_dir, filename in info["project_references"]:
            if target_dir not in manifests and len(manifests) < MAX_MANIFESTS:
                if (root / target_dir / filename).is_file():
                    manifests[target_dir] = _load_csproj(root, target_dir, filename)
            pending.append(target_dir)
    return packages


def _props_packages(directory: str, root) -> set[str]:
    """Return PackageReferences declared by ancestor Directory.*.props files."""
    packages: set[str] = set()
    parts = directory.split("/") if directory else []
    for depth in range(len(parts), -1, -1):
        for filename in ("Directory.Build.props", "Directory.Packages.props"):
            path = root / "/".join(parts[:depth]) / filename
            if not path.is_file():
                continue
            try:
                element = parse_xml_hardened(
                    read_bounded_text(path, max_bytes=MAX_MANIFEST_BYTES, root=root)
                )
            except (SafeReadError, ValueError):
                continue
            for node in element.iter():
                if local_name(node.tag) in {"PackageReference", "GlobalPackageReference"}:
                    package = node.get("Include") or node.get("Update")
                    if package:
                        packages.add(package.strip())
    return packages


def _own_namespace_roots(parsed_files, manifests: dict) -> set[str]:
    roots: set[str] = set()
    for parsed in parsed_files.values():
        if isinstance(parsed.facts, CSharpFacts):
            roots.update(ns.split(".")[0].lower() for ns in parsed.facts.namespaces)
    for info in manifests.values():
        roots.add(info["assembly"].split(".")[0].lower())
        roots.update(ns.split(".")[0].lower() for ns in info["root_namespaces"])
    return roots


def _is_framework(namespace: str) -> bool:
    return any(
        namespace == prefix or namespace.startswith(prefix + ".")
        for prefix in _FRAMEWORK_PREFIXES
    )


def _declared_covers(namespace: str, packages: set[str]) -> bool:
    """Return whether any declared package plausibly provides ``namespace``.

    NuGet vendors split one root namespace across many packages
    (``OpenTelemetry.Metrics`` ships in ``OpenTelemetry.Extensions.Hosting``),
    so a shared root segment counts as coverage in addition to prefix
    matches in either direction.
    """
    lowered = namespace.lower()
    root = lowered.split(".")[0]
    for package in packages:
        candidate = package.lower()
        if (
            lowered == candidate
            or lowered.startswith(candidate + ".")
            or candidate.startswith(lowered + ".")
            or candidate.split(".")[0] == root
        ):
            return True
    return False


def _undeclared_by_manifest(
    parsed_files,
    manifests: dict,
    own_roots: set[str],
    root,
) -> dict[str, list[tuple[str, str]]]:
    first_seen: dict[str, dict[str, str]] = {}
    manifest_dirs = list(manifests)
    for identity_path in sorted(parsed_files):
        parsed = parsed_files[identity_path]
        if not isinstance(parsed.facts, CSharpFacts):
            continue
        directory = nearest_manifest_dir(identity_path, manifest_dirs)
        if directory is None:
            continue
        chain = manifest_chain(directory, manifest_dirs)
        if any(manifests[entry]["invalid"] for entry in chain):
            continue
        packages: set[str] = set()
        for entry in chain:
            packages.update(_transitive_packages(entry, manifests, root))
        packages.update(_props_packages(directory, root))
        for namespace in parsed.facts.usings:
            if _is_framework(namespace):
                continue
            if namespace.split(".")[0].lower() in own_roots:
                continue
            if _declared_covers(namespace, packages):
                continue
            first_seen.setdefault(directory, {}).setdefault(
                namespace, parsed.source.display_path,
            )
    return {
        directory: sorted(entries.items())
        for directory, entries in first_seen.items()
    }


def _exact_mapping(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Cached C# object has unexpected fields")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str) or len(value) > _MAX_CACHED_STRING:
        raise ValueError("Cached C# string is invalid")
    return value


def _string_tuple(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Cached C# string list is invalid")
    return tuple(_string(item) for item in value)


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Cached C# integer is invalid")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("Cached C# boolean is invalid")
    return value


def register_csharp_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in C#/.NET pilot plugins."""
    registry.register_language(CSharpLanguageAdapter())
    registry.register_rule_pack(CSharpRulePack())
    registry.register_signal_provider(CSharpArchitectureSignalProvider())
    registry.register_project_provider(CSharpPackageProvider())
    return registry
