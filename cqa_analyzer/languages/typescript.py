"""Bounded TypeScript/JavaScript pilot adapter, rule pack, and provider.

One adapter covers the ECMAScript family: TypeScript (``.ts``/``.tsx``)
and JavaScript (``.js``/``.jsx``/``.mjs``/``.cjs``). It extracts facts
by regex from blanked source and never executes ``node``, ``tsc``, or
any package manager.

Known pilot bounds, accepted deliberately:

- Template literal contents are blanked whole, including ``${...}``
  interpolations — conservative: interpolated code is never evidence.
- Regular-expression literals are not lexed; a regex containing quote
  or comment delimiters can over-blank the remainder of its line.
- Minified bundles under the size limit are scanned; identifier
  extraction is capped so they cannot exhaust memory.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping

from ..findings import Finding, Location
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
from ..ts_patterns import TS_DESIGN_PATTERNS, TS_DSA_PATTERNS

TS_ADAPTER_VERSION = "1.0.0"
TS_CACHE_CODEC_VERSION = "1.0.0"
TS_RULE_PACK_ID = "typescript-core"
_MAX_CACHED_TS_STRING = 4 * 1024 * 1024
_MAX_TS_IDENTIFIERS = 20_000
_MAX_TS_IMPORTS = 20_000
_MAX_PACKAGE_JSON_BYTES = 1024 * 1024

_FROM_IMPORT = re.compile(r"""\bfrom\s+['"]([^'"\n]+)['"]""")
_SIDE_EFFECT_IMPORT = re.compile(r"""(?m)^\s*import\s+['"]([^'"\n]+)['"]""")
_CALL_IMPORT = re.compile(
    r"""\b(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)"""
)

_TS_DECLARATION = re.compile(
    r"\b(?:function|class|interface|enum|namespace|type)\s+"
    r"([A-Za-z_$][\w$]*)"
)
_TS_VALUE_DECLARATION = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)"
)
_TS_SELECTOR_CALL = re.compile(
    r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\("
)
_TS_KEYWORDS = frozenset({
    "abstract", "any", "as", "async", "await", "boolean", "break", "case",
    "catch", "class", "const", "continue", "debugger", "declare", "default",
    "delete", "do", "else", "enum", "export", "extends", "false", "finally",
    "for", "from", "function", "if", "implements", "import", "in",
    "instanceof", "interface", "let", "namespace", "new", "null", "number",
    "of", "private", "protected", "public", "readonly", "return", "static",
    "string", "super", "switch", "this", "throw", "true", "try", "type",
    "typeof", "undefined", "unknown", "var", "void", "while", "with",
    "yield",
})

_EMPTY_CATCH = re.compile(r"\bcatch\b\s*(?:\([^)]*\))?\s*\{\s*\}")

_NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster",
    "console", "constants", "crypto", "dgram", "dns", "domain", "events",
    "fs", "http", "http2", "https", "inspector", "module", "net", "os",
    "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "worker_threads", "zlib",
})


def _line_column(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _strip_ts_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank comments and optional string contents, preserving layout."""
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
                state = "template" if current == "`" else "string"
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
        elif state == "template":
            # Interpolations are blanked with the rest of the literal:
            # conservative, so interpolated code is never evidence.
            if current == "\\" and following:
                if blank_strings:
                    output[index] = " "
                    if following != "\n":
                        output[index + 1] = " "
                index += 2
                continue
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
            elif current == "\n":
                # Unterminated single-line string: recover at newline.
                state = "code"
                complete = False
            elif blank_strings:
                output[index] = " "
            index += 1
            continue
        index += 1

    if state in {"block_comment", "template", "string"}:
        complete = False
    return "".join(output), complete


def _ts_imports(metadata_text: str) -> tuple[str, ...]:
    specifiers: set[str] = set()
    for pattern in (_FROM_IMPORT, _SIDE_EFFECT_IMPORT, _CALL_IMPORT):
        for match in pattern.finditer(metadata_text):
            specifiers.add(match.group(1))
            if len(specifiers) >= _MAX_TS_IMPORTS:
                break
    return tuple(sorted(specifiers)[:_MAX_TS_IMPORTS])


def _ts_identifiers(code_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in (_TS_DECLARATION, _TS_VALUE_DECLARATION):
        for match in pattern.finditer(code_text):
            names.add(match.group(1))
            if len(names) >= _MAX_TS_IDENTIFIERS:
                break
    for match in _TS_SELECTOR_CALL.finditer(code_text):
        qualifier, member = match.group(1), match.group(2)
        names.update((qualifier, member, f"{qualifier}.{member}"))
        if len(names) >= _MAX_TS_IDENTIFIERS:
            break
    return tuple(sorted(names - _TS_KEYWORDS)[:_MAX_TS_IDENTIFIERS])


class TsFacts:
    """Small adapter-owned TypeScript/JavaScript fact model."""

    __slots__ = ("imports", "identifiers", "code_text")

    def __init__(
        self,
        imports: tuple[str, ...],
        identifiers: tuple[str, ...],
        code_text: str,
    ) -> None:
        self.imports = imports
        self.identifiers = identifiers
        self.code_text = code_text

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, TsFacts)
            and self.imports == other.imports
            and self.identifiers == other.identifiers
            and self.code_text == other.code_text
        )


class TypeScriptLanguageAdapter:
    """Extract bounded TS/JS facts without executing any toolchain."""

    language_id = "typescript"
    adapter_version = TS_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
    cache_codec_version = TS_CACHE_CODEC_VERSION
    cache_runtime_version = "portable"

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_ts_comments_and_strings(
            source.content
        )
        metadata_text, metadata_complete = _strip_ts_comments_and_strings(
            source.content,
            blank_strings=False,
        )
        facts = TsFacts(
            imports=_ts_imports(metadata_text),
            identifiers=_ts_identifiers(code_text),
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
        if not isinstance(facts, TsFacts):
            raise TypeError("TypeScript cache codec requires TsFacts")
        return {
            "line_count": parsed.line_count,
            "complete": parsed.complete,
            "facts": {
                "imports": list(facts.imports),
                "identifiers": list(facts.identifiers),
                "code_text": facts.code_text,
            },
        }

    def deserialize_parsed(
        self,
        source: SourceFile,
        payload: Mapping[str, object],
    ) -> ParsedFile:
        data = _ts_exact_mapping(
            payload,
            {"line_count", "complete", "facts"},
        )
        line_count = _ts_nonnegative_int(data["line_count"])
        complete = _ts_boolean(data["complete"])
        fact_data = _ts_exact_mapping(
            data["facts"],
            {"imports", "identifiers", "code_text"},
        )
        facts = TsFacts(
            imports=_ts_string_tuple(fact_data["imports"], _MAX_TS_IMPORTS),
            identifiers=_ts_string_tuple(
                fact_data["identifiers"],
                _MAX_TS_IDENTIFIERS,
            ),
            code_text=_ts_string(fact_data["code_text"]),
        )
        return ParsedFile(source, facts, facts, line_count, complete)


class TsEmptyCatchRule:
    """Detect catch blocks whose blanked body is empty."""

    rule_id = "TS-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, TsFacts):
            return
        for match in _EMPTY_CATCH.finditer(parsed.facts.code_text):
            line, column = _line_column(
                parsed.facts.code_text,
                match.start(),
            )
            yield Finding(
                rule_id=self.rule_id,
                category="correctness",
                severity="warning",
                confidence="high",
                message=(
                    "An empty catch block silently discards the failure."
                ),
                location=Location(
                    path=parsed.source.display_path,
                    line=line,
                    column=column,
                    identity_path=parsed.source.identity_path,
                ),
                remediation=(
                    "Handle the failure, log actionable context, or "
                    "rethrow the error."
                ),
            )


class TypeScriptRulePack:
    """Run the bounded built-in TypeScript/JavaScript pilot rules."""

    rule_pack_id = TS_RULE_PACK_ID
    language_id = "typescript"
    ruleset_version = "1.0.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (TsEmptyCatchRule(),)

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not parsed.complete:
            return ()
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(parsed))
        return findings


class TsArchitectureSignalProvider:
    """Extract TS/JS DSA and design signals from blanked adapter facts.

    Reuses the language-neutral pattern matcher over a signal view built
    from blanked code text, bounded identifiers, and import specifiers,
    so literals are never evidence and generic patterns keep the same
    corroboration discipline as Python and Go.
    """

    provider_id = "typescript-architecture-signals"
    language_id = "typescript"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        facts = parsed.facts
        if not isinstance(facts, TsFacts):
            raise TypeError("TypeScript signal provider requires TsFacts")
        signals = FileSignals(
            path=parsed.source.path,
            line_count=parsed.line_count,
            code_text=facts.code_text.lower(),
            identifiers={name.lower() for name in facts.identifiers},
            imports={specifier.lower() for specifier in facts.imports},
        )
        for category, definitions in (
            ("architecture.dsa", TS_DSA_PATTERNS),
            ("architecture.design", TS_DESIGN_PATTERNS),
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


class TsPackageProvider:
    """Passive package.json metadata and dependency-drift analysis."""

    provider_id = "typescript-package"
    language_id = "typescript"
    capability = "package"
    capability_version = "1.0.0"
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True

    def analyze(self, project: ProjectContext) -> ProviderResult:
        manifest_path = project.root / "package.json"
        payload: dict = {
            "manifest_present": manifest_path.is_file(),
            "name": None,
            "declared_dependencies": [],
            "workspaces": False,
            "undeclared_imports": [],
        }
        findings: list[Finding] = []
        errors = 0

        manifest = None
        if payload["manifest_present"]:
            try:
                raw = read_bounded_text(
                    manifest_path,
                    max_bytes=_MAX_PACKAGE_JSON_BYTES,
                )
                manifest = json.loads(raw)
                if not isinstance(manifest, dict):
                    raise ValueError("package.json is not an object")
            except (SafeReadError, ValueError) as error:
                errors = 1
                findings.append(_manifest_finding(str(error)))
                manifest = None

        if manifest is not None:
            payload["name"] = (
                manifest.get("name")
                if isinstance(manifest.get("name"), str)
                else None
            )
            declared = _declared_dependencies(manifest)
            payload["declared_dependencies"] = sorted(declared)
            payload["workspaces"] = "workspaces" in manifest
            if not payload["workspaces"]:
                undeclared = _undeclared_imports(
                    project.parsed_files,
                    declared,
                )
                payload["undeclared_imports"] = [
                    module for module, _ in undeclared
                ]
                findings.extend(
                    _undeclared_finding(module, example)
                    for module, example in undeclared
                )

        return ProviderResult(
            payload=payload,
            health={"complete": True, "errors": errors},
            findings=tuple(findings),
        )


def _declared_dependencies(manifest: dict) -> set[str]:
    declared: set[str] = set()
    for key in (
        "dependencies", "devDependencies",
        "peerDependencies", "optionalDependencies",
    ):
        section = manifest.get(key)
        if isinstance(section, dict):
            declared.update(
                name for name in section if isinstance(name, str)
            )
    return declared


_NPM_PACKAGE_NAME = re.compile(
    r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$"
)


def _bare_module(specifier: str) -> str | None:
    """Return the package name for an external bare specifier, or None."""
    if specifier.startswith((".", "/", "#", "~", "@/")):
        return None
    if specifier.startswith("node:"):
        return None
    segments = specifier.split("/")
    if specifier.startswith("@"):
        if len(segments) < 2:
            return None
        base = "/".join(segments[:2])
    else:
        base = segments[0]
        if base in _NODE_BUILTINS:
            return None
    # Directive strings and minifier artifacts are not package names.
    if not _NPM_PACKAGE_NAME.match(base):
        return None
    return base


def _undeclared_imports(
    parsed_files,
    declared: set[str],
) -> list[tuple[str, str]]:
    first_seen: dict[str, str] = {}
    for identity_path in sorted(parsed_files):
        parsed = parsed_files[identity_path]
        if not isinstance(parsed.facts, TsFacts):
            continue
        for specifier in parsed.facts.imports:
            module = _bare_module(specifier)
            if module is not None and module not in declared:
                first_seen.setdefault(module, parsed.source.display_path)
    return sorted(first_seen.items())


def _manifest_finding(detail: str) -> Finding:
    return Finding(
        rule_id="TS-PKG-002",
        category="package-health",
        severity="error",
        confidence="high",
        message="package.json cannot be read as a valid JSON object.",
        location=Location("package.json", 1, 1),
        remediation="Correct the package.json syntax and run analysis again.",
    )


def _undeclared_finding(module: str, example_path: str) -> Finding:
    return Finding(
        rule_id="TS-PKG-001",
        category="package-health",
        severity="warning",
        confidence="high",
        message=(
            f"Module '{module}' is imported (for example in "
            f"{example_path}) but not declared in package.json."
        ),
        location=Location("package.json", 1, 1),
        remediation=(
            "Declare the dependency in package.json or remove the import."
        ),
    )


def _ts_exact_mapping(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Cached TypeScript object has unexpected fields")
    return value


def _ts_string(value: object) -> str:
    if not isinstance(value, str) or len(value) > _MAX_CACHED_TS_STRING:
        raise ValueError("Cached TypeScript string is invalid")
    return value


def _ts_string_tuple(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Cached TypeScript string list is invalid")
    return tuple(_ts_string(item) for item in value)


def _ts_nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Cached TypeScript integer is invalid")
    return value


def _ts_boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("Cached TypeScript boolean is invalid")
    return value


def register_typescript_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in TypeScript/JavaScript pilot plugins."""
    registry.register_language(TypeScriptLanguageAdapter())
    registry.register_rule_pack(TypeScriptRulePack())
    registry.register_signal_provider(TsArchitectureSignalProvider())
    registry.register_project_provider(TsPackageProvider())
    return registry
