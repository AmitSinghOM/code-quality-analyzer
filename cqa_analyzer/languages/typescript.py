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
from ._shared import RegexRulePackBase, empty_catch_finding

TS_ADAPTER_VERSION = "1.0.0"
TS_CACHE_CODEC_VERSION = "1.0.0"
TS_RULE_PACK_ID = "typescript-core"
_MAX_CACHED_TS_STRING = 4 * 1024 * 1024
_MAX_TS_IDENTIFIERS = 20_000
_MAX_TS_IMPORTS = 20_000
_MAX_PACKAGE_JSON_BYTES = 1024 * 1024
_MAX_MANIFESTS = 100

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


_REGEX_PRECEDING_KEYWORDS = frozenset({
    "return", "typeof", "case", "do", "else", "in", "of", "instanceof",
    "new", "delete", "void", "throw", "yield", "await",
})
# `<` and `>` are deliberately absent: in TSX `</p>` is a closing tag and
# `<T>/x/` is vanishingly rare, so `<` before `/` is treated as JSX.
_REGEX_PRECEDING_CHARS = frozenset("(,=:[!&|?{;+-*%~^")


def _regex_allowed(last_sig: str, last_word: str, prev_sig: str = "") -> bool:
    """A ``/`` starts a regex literal unless it follows a value."""
    if last_sig == ">" and prev_sig == "=":
        return True  # arrow function body: `x => /re/.test(x)`
    if last_sig == "" or last_sig in _REGEX_PRECEDING_CHARS:
        return True
    return last_word in _REGEX_PRECEDING_KEYWORDS


def _regex_end(source: str, start: int) -> int | None:
    """Return the index of the closing ``/`` of a regex literal, or None."""
    index = start + 1
    in_class = False
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "\n":
            return None
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "/":
            return index
        index += 1
    return None


def _strip_ts_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank comments and optional string contents, preserving layout.

    Template literals are tracked through ``${...}`` interpolations with
    nesting: an interpolation may contain strings, comments, braces, and
    further template literals. When blanking, everything from a template's
    opening backtick to its closing backtick — interpolated code included —
    is blanked, so template content is never evidence.

    Regular-expression literals are recognised by the previous significant
    token (a ``/`` after a value is division; after an operator, opening
    bracket, or keyword such as ``return`` it starts a regex) and blanked
    like strings, so quotes inside ``/"/`` no longer open a string.
    """
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    complete = True
    last_sig = ""  # last significant (non-space) code character
    prev_sig = ""  # the significant character before last_sig
    word_closed = False  # whitespace seen since last_word ended
    last_word = ""  # identifier/keyword token ending at last_sig
    # One entry per open template interpolation: the entry is the current
    # unmatched `{` depth inside that interpolation. Non-empty means we are
    # lexing code that ultimately lives inside a template literal.
    interpolations: list[int] = []

    def blank(position: int) -> None:
        if blank_strings and source[position] != "\n":
            output[position] = " "

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
            if current == "/" and _regex_allowed(last_sig, last_word, prev_sig):
                end = _regex_end(source, index)
                if end is not None:
                    for position in range(index, end + 1):
                        blank(position)
                    index = end + 1
                    prev_sig, last_sig, last_word = last_sig, ")", ""
                    continue
                # No closing `/` on this line: not a regex after all
                # (JSX `</p>`, a stray operator). Treat as ordinary code.
            if current in {'"', "'"}:
                # An apostrophe glued to an identifier character cannot open a
                # string in JS/TS (`x'a'` is invalid); it is JSX text
                # (`<p>Don't have an account?</p>`). Leave it as code.
                glued = index and (source[index - 1].isalnum() or source[index - 1] == "_")
                if current == "'" and glued:
                    prev_sig, last_sig, last_word = last_sig, current, ""
                    index += 1
                    continue
                quote = current
                blank(index)
                state = "string"
                index += 1
                continue
            if current == "`":
                blank(index)
                state = "template"
                index += 1
                continue
            if current.isspace():
                # A keyword ends at whitespace: `b in /re/` must see `in`,
                # not `bin`.
                if last_word:
                    word_closed = True
            else:
                if word_closed:
                    last_word = ""
                    word_closed = False
                prev_sig, last_sig = last_sig, current
                last_word = last_word + current if (current.isalnum() or current in "_$") else ""
            if interpolations:
                if current == "{":
                    interpolations[-1] += 1
                elif current == "}":
                    if interpolations[-1] == 0:
                        interpolations.pop()
                        state = "template"
                    else:
                        interpolations[-1] -= 1
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
        elif state == "template":
            if current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
                continue
            if current == "$" and following == "{":
                blank(index)
                blank(index + 1)
                interpolations.append(0)
                state = "code"
                index += 2
                continue
            if current == "`":
                blank(index)
                state = "code"
                prev_sig, last_sig, last_word = last_sig, ")", ""
            else:
                blank(index)
            index += 1
            continue
        elif state == "string":
            if current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
                continue
            if current == quote:
                blank(index)
                state = "code"
                prev_sig, last_sig, last_word = last_sig, ")", ""
            elif current == "\n":
                # Unterminated single-line string: recover at newline.
                state = "code"
                complete = False
            else:
                blank(index)
            index += 1
            continue
        index += 1

    if state in {"block_comment", "template", "string"} or interpolations:
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
            yield empty_catch_finding(self.rule_id, parsed, match, rethrow_word="error")


class TypeScriptRulePack(RegexRulePackBase):
    """Run the bounded built-in TypeScript/JavaScript pilot rules."""

    rule_pack_id = TS_RULE_PACK_ID
    language_id = "typescript"
    ruleset_version = "1.0.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (TsEmptyCatchRule(),)


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
    """Passive package.json metadata and dependency-drift analysis.

    Manifests are discovered at the scan root and in every non-excluded
    directory that encloses an analyzed TS/JS file (bounded). Each file
    is associated with its nearest enclosing manifest; declared
    dependencies are the union of that manifest and its ancestors,
    because Node module resolution walks up the directory tree. Files
    under a manifest chain that declares ``workspaces`` — or contains an
    unreadable manifest — skip drift analysis rather than guess.
    """

    provider_id = "typescript-package"
    language_id = "typescript"
    capability = "package"
    capability_version = "1.1.0"
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True

    def analyze(self, project: ProjectContext) -> ProviderResult:
        manifest_dirs, truncated = _manifest_directories(
            project.root,
            project.parsed_files,
        )
        manifests = {
            directory: _load_manifest(project.root, directory)
            for directory in manifest_dirs
        }
        findings: list[Finding] = []
        errors = 0
        for directory in manifest_dirs:
            if manifests[directory]["invalid"]:
                errors += 1
                findings.append(_manifest_finding(
                    _manifest_report_path(directory, project.redact_paths),
                    _manifest_identity_path(directory),
                ))

        undeclared = _undeclared_by_manifest(
            project.parsed_files,
            manifests,
        )
        for directory in sorted(undeclared):
            report_path = _manifest_report_path(
                directory,
                project.redact_paths,
            )
            identity = _manifest_identity_path(directory)
            for module, example in undeclared[directory]:
                findings.append(_undeclared_finding(
                    module,
                    example,
                    report_path,
                    identity,
                ))

        root_manifest = manifests.get("")
        payload = {
            "manifest_present": root_manifest is not None,
            "name": root_manifest["name"] if root_manifest else None,
            "declared_dependencies": (
                sorted(root_manifest["declared"]) if root_manifest else []
            ),
            "workspaces": (
                root_manifest["workspaces"] if root_manifest else False
            ),
            "undeclared_imports": sorted({
                module
                for entries in undeclared.values()
                for module, _ in entries
            }),
            "manifests": [
                {
                    "path": _manifest_identity_path(directory),
                    "name": manifests[directory]["name"],
                    "workspaces": manifests[directory]["workspaces"],
                    "invalid": manifests[directory]["invalid"],
                    "undeclared_imports": [
                        module
                        for module, _ in undeclared.get(directory, [])
                    ],
                }
                for directory in manifest_dirs
            ],
            "manifests_truncated": truncated,
        }
        return ProviderResult(
            payload=payload,
            health={"complete": not truncated, "errors": errors},
            findings=tuple(findings),
        )


def _manifest_directories(
    root,
    parsed_files,
) -> tuple[list[str], bool]:
    """Return sorted project-relative directories holding a package.json."""
    candidates = {""}
    for identity_path in parsed_files:
        parts = identity_path.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            candidates.add("/".join(parts[:depth]))
    present = sorted(
        directory
        for directory in candidates
        if (root / directory / "package.json").is_file()
        if directory == "" or ".." not in directory.split("/")
    )
    return present[:_MAX_MANIFESTS], len(present) > _MAX_MANIFESTS


def _load_manifest(root, directory: str) -> dict:
    info = {
        "name": None,
        "declared": set(),
        "workspaces": False,
        "invalid": False,
    }
    try:
        raw = read_bounded_text(
            root / directory / "package.json",
            max_bytes=_MAX_PACKAGE_JSON_BYTES,
            root=root,
        )
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise ValueError("package.json is not an object")
    except (SafeReadError, ValueError):
        info["invalid"] = True
        return info
    if isinstance(manifest.get("name"), str):
        info["name"] = manifest["name"]
    info["declared"] = _declared_dependencies(manifest)
    info["workspaces"] = "workspaces" in manifest
    return info


def _manifest_chain(directory: str, manifests: dict) -> list[dict]:
    """Return manifests from ``directory`` up to the root, nearest first."""
    chain = []
    parts = directory.split("/") if directory else []
    for depth in range(len(parts), -1, -1):
        prefix = "/".join(parts[:depth])
        if prefix in manifests:
            chain.append(manifests[prefix])
    return chain


def _nearest_manifest_dir(
    identity_path: str,
    manifests: dict,
) -> str | None:
    parts = identity_path.split("/")[:-1]
    for depth in range(len(parts), -1, -1):
        prefix = "/".join(parts[:depth])
        if prefix in manifests:
            return prefix
    return None


def _manifest_identity_path(directory: str) -> str:
    return f"{directory}/package.json" if directory else "package.json"


def _manifest_report_path(directory: str, redact_paths: bool) -> str:
    return (
        "package.json"
        if redact_paths
        else _manifest_identity_path(directory)
    )


def _undeclared_by_manifest(
    parsed_files,
    manifests: dict,
) -> dict[str, list[tuple[str, str]]]:
    """Map manifest directory to sorted (module, example path) drift."""
    first_seen: dict[str, dict[str, str]] = {}
    for identity_path in sorted(parsed_files):
        parsed = parsed_files[identity_path]
        if not isinstance(parsed.facts, TsFacts):
            continue
        directory = _nearest_manifest_dir(identity_path, manifests)
        if directory is None:
            continue
        chain = _manifest_chain(directory, manifests)
        if any(info["workspaces"] or info["invalid"] for info in chain):
            continue
        declared: set[str] = set()
        for info in chain:
            declared.update(info["declared"])
        for specifier in parsed.facts.imports:
            module = _bare_module(specifier)
            if module is not None and module not in declared:
                first_seen.setdefault(directory, {}).setdefault(
                    module,
                    parsed.source.display_path,
                )
    return {
        directory: sorted(modules.items())
        for directory, modules in first_seen.items()
    }


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


def _manifest_finding(report_path: str, identity_path: str) -> Finding:
    return Finding(
        rule_id="TS-PKG-002",
        category="package-health",
        severity="error",
        confidence="high",
        message=(
            f"{identity_path} cannot be read as a valid JSON object."
        ),
        location=Location(
            report_path,
            1,
            1,
            identity_path=identity_path,
        ),
        remediation="Correct the package.json syntax and run analysis again.",
    )


def _undeclared_finding(
    module: str,
    example_path: str,
    report_path: str,
    identity_path: str,
) -> Finding:
    return Finding(
        rule_id="TS-PKG-001",
        category="package-health",
        severity="warning",
        confidence="high",
        message=(
            f"Module '{module}' is imported (for example in "
            f"{example_path}) but not declared in {identity_path}."
        ),
        location=Location(
            report_path,
            1,
            1,
            identity_path=identity_path,
        ),
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
