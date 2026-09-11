"""Rust pilot (experimental, registered only with the ``[deep]`` extra).

Bounded, no-toolchain discipline like the other pilots: comments (nested
block comments included), strings (``"…"``, ``r#"…"#``, ``b"…"``) and char
literals are blanked with offsets preserved; ``use`` paths and bounded
identifiers are extracted by regex. Lifetimes (``'a``) are told apart from
char literals so they never open a string state.

Rules:

* ``RS-COR-001`` — ``.unwrap()`` density outside test code (the Rust
  analogue of the Kotlin/TypeScript non-null rules; ``.expect("why")`` is
  documented intent and is not counted).
* ``RS-PKG-001`` — a crate used via ``use``/``extern crate`` that no
  governing ``Cargo.toml`` declares; ``RS-PKG-002`` — unreadable manifest.

Duplication and complexity (``RS-DUP-001``, ``RS-MAINT-001/002``) come from
the tree-sitter deep providers, which is why the whole pilot is gated on
``tree-sitter-rust``: a Rust project scored without them would be capped
below the other languages.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Mapping
from pathlib import Path

from ..findings import Finding, Location
from ..manifests import (
    MAX_MANIFEST_BYTES,
    discover_manifest_dirs,
    manifest_chain,
    manifest_report_path,
    nearest_manifest_dir,
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
from ..rust_patterns import RUST_DESIGN_PATTERNS, RUST_DSA_PATTERNS
from ..safe_io import SafeReadError, read_bounded_text
from ._parity import NON_NULL_LIMIT, block_end, downgrade_in_tests, is_test_path
from ._shared import RegexRulePackBase, line_column, signal_observations

RUST_ADAPTER_VERSION = "0.1.0"
RUST_CACHE_CODEC_VERSION = "0.1.0"
RUST_RULE_PACK_ID = "rust-core"
_MAX_CACHED_STRING = 4 * 1024 * 1024
_MAX_IDENTIFIERS = 20_000
_MAX_IMPORTS = 5_000
_MANIFEST_FILENAMES = ("Cargo.toml",)

# ``use foo::bar::{Baz, qux}`` — captured whole; roots and full paths are
# derived. ``extern crate foo;`` and ``foo::bar()`` paths count as well.
# ``r#type`` is a raw identifier (a keyword used as a name): the ``r#`` prefix is
# stripped so ``mod r#type;`` / ``use r#type::x`` resolve to ``type``.
_USE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:r#)?([A-Za-z_][\w:]*)", re.MULTILINE)
_EXTERN_CRATE = re.compile(r"^\s*extern\s+crate\s+([A-Za-z_]\w*)", re.MULTILINE)
_QUALIFIED_PATH = re.compile(r"\b([a-z_][a-z0-9_]*)::[A-Za-z_]")
_MOD_DECL = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?:r#)?([A-Za-z_]\w*)\s*[;{]", re.MULTILINE
)
_DECLARATION = re.compile(
    r"\b(?:fn|struct|enum|trait|type|const|static|mod|macro_rules!)\s+([A-Za-z_]\w*)"
)
_LET_BINDING = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*[!(]")
_METHOD_CALL = re.compile(r"\.([a-z_][a-z0-9_]*)\s*\(")
_TYPE_USE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\s*[<:({]")
_ATTRIBUTE = re.compile(r"#!?\[([A-Za-z_][\w:]*)")
_KEYWORDS = frozenset(
    {
        "as",
        "async",
        "await",
        "break",
        "const",
        "continue",
        "crate",
        "dyn",
        "else",
        "enum",
        "extern",
        "false",
        "fn",
        "for",
        "if",
        "impl",
        "in",
        "let",
        "loop",
        "match",
        "mod",
        "move",
        "mut",
        "pub",
        "ref",
        "return",
        "self",
        "Self",
        "static",
        "struct",
        "super",
        "trait",
        "true",
        "type",
        "unsafe",
        "use",
        "where",
        "while",
    }
)
_STD_ROOTS = frozenset({"std", "core", "alloc", "crate", "self", "super", "proc_macro", "test"})

_UNWRAP = re.compile(r"\.unwrap\s*\(\s*\)")
_CFG_TEST_MOD = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{")
_TEST_FN = re.compile(
    r"#\[(?:test|tokio::test|async_std::test|rstest)\]\s*(?:async\s+)?fn\s+\w+[^{;]*\{"
)


def _strip_rust_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank comments (nested ``/* */`` honoured) and literal contents."""
    output = list(source)
    index = 0
    length = len(source)
    complete = True

    def blank(position: int) -> None:
        if blank_strings and source[position] != "\n":
            output[position] = " "

    def blank_comment(position: int) -> None:
        if source[position] != "\n":
            output[position] = " "

    while index < length:
        current = source[index]
        following = source[index + 1] if index + 1 < length else ""
        if current == "/" and following == "/":
            while index < length and source[index] != "\n":
                blank_comment(index)
                index += 1
            continue
        if current == "/" and following == "*":
            depth = 0
            while index < length:
                if source.startswith("/*", index):
                    depth += 1
                    blank_comment(index)
                    blank_comment(index + 1)
                    index += 2
                    continue
                if source.startswith("*/", index):
                    depth -= 1
                    blank_comment(index)
                    blank_comment(index + 1)
                    index += 2
                    if depth == 0:
                        break
                    continue
                blank_comment(index)
                index += 1
            if depth != 0:
                complete = False
            continue
        # Raw strings: r"…", r#"…"#, br"…", br##"…"##
        raw = re.match(r'b?r(#*)"', source[index : index + 260])
        if raw and (index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")):
            hashes = raw.group(1)
            terminator = '"' + hashes
            start = index
            index += raw.end()
            end = source.find(terminator, index)
            if end < 0:
                complete = False
                end = length
            else:
                end += len(terminator)
            for position in range(start, end):
                blank(position)
            index = end
            continue
        if current == '"' or (current == "b" and following == '"'):
            if current == "b":
                blank(index)
                index += 1
            blank(index)
            index += 1
            while index < length:
                char = source[index]
                if char == "\\" and index + 1 < length:
                    blank(index)
                    blank(index + 1)
                    index += 2
                    continue
                blank(index)
                index += 1
                if char == '"':
                    break
            else:
                complete = False
            continue
        if current == "'":
            # Char literal ('a', '\n', '\u{1F600}') vs lifetime ('a, 'static).
            if following == "\\":
                close = source.find("'", index + 2)
                end = length if close < 0 else close + 1
                for position in range(index, end):
                    blank(position)
                index = end
                continue
            if index + 2 < length and source[index + 2] == "'":
                for position in range(index, index + 3):
                    blank(position)
                index += 3
                continue
            index += 1  # lifetime: leave as code
            continue
        index += 1
    return "".join(output), complete


def _rust_imports(metadata_text: str) -> tuple[str, ...]:
    """Return lower-cased crate roots and full ``use`` paths (bounded)."""
    found: set[str] = set()
    for pattern in (_USE, _EXTERN_CRATE):
        for match in pattern.finditer(metadata_text):
            path = match.group(1).lower()
            found.add(path)
            found.add(path.split("::", 1)[0])
            if len(found) >= _MAX_IMPORTS:
                break
    for match in _QUALIFIED_PATH.finditer(metadata_text):
        found.add(match.group(1).lower())
    return tuple(sorted(found)[:_MAX_IMPORTS])


def _rust_identifiers(code_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in (_DECLARATION, _LET_BINDING, _CALL, _METHOD_CALL, _TYPE_USE, _ATTRIBUTE):
        for match in pattern.finditer(code_text):
            names.add(match.group(1))
            if len(names) >= _MAX_IDENTIFIERS:
                break
    return tuple(sorted(names - _KEYWORDS)[:_MAX_IDENTIFIERS])


def _external_crates(metadata_text: str) -> frozenset[str]:
    """Crate roots named by ``use``/``extern crate`` that are not std/local."""
    roots: set[str] = set()
    for pattern in (_USE, _EXTERN_CRATE):
        for match in pattern.finditer(metadata_text):
            root = match.group(1).split("::", 1)[0]
            if root not in _STD_ROOTS and not root[0].isupper():
                roots.add(root)
    return frozenset(roots)


class RustFacts:
    """Small adapter-owned Rust fact model."""

    __slots__ = ("imports", "identifiers", "code_text", "external_crates", "local_modules")

    def __init__(
        self,
        imports: tuple[str, ...],
        identifiers: tuple[str, ...],
        code_text: str,
        external_crates: tuple[str, ...] = (),
        local_modules: tuple[str, ...] = (),
    ) -> None:
        self.imports = imports
        self.identifiers = identifiers
        self.code_text = code_text
        self.external_crates = external_crates
        self.local_modules = local_modules

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RustFacts) and (
            self.imports,
            self.identifiers,
            self.code_text,
            self.external_crates,
            self.local_modules,
        ) == (
            other.imports,
            other.identifiers,
            other.code_text,
            other.external_crates,
            other.local_modules,
        )

    __hash__ = None


class RustLanguageAdapter:
    """Extract bounded Rust facts without running cargo or rustc."""

    language_id = "rust"
    adapter_version = RUST_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".rs",)
    cache_codec_version = RUST_CACHE_CODEC_VERSION
    cache_runtime_version = "portable"

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_rust_comments_and_strings(source.content)
        # ``use`` paths are code, so they are read from the *blanked* text:
        # ripgrep embeds "extern crate snap;" and "use the ... flag" inside
        # string literals, which must never become imports.
        facts = RustFacts(
            imports=_rust_imports(code_text),
            identifiers=_rust_identifiers(code_text),
            code_text=code_text,
            external_crates=tuple(sorted(_external_crates(code_text))),
            local_modules=tuple(sorted({m.group(1) for m in _MOD_DECL.finditer(code_text)})),
        )
        return ParsedFile(
            source=source,
            artifact=facts,
            facts=facts,
            line_count=len(source.content.splitlines()),
            complete=lexical_complete,
        )

    def serialize_parsed(self, parsed: ParsedFile) -> Mapping[str, object]:
        facts = parsed.facts
        if not isinstance(facts, RustFacts):
            raise TypeError("Rust cache codec requires RustFacts")
        return {
            "line_count": parsed.line_count,
            "complete": parsed.complete,
            "facts": {
                "imports": list(facts.imports),
                "identifiers": list(facts.identifiers),
                "code_text": facts.code_text,
                "external_crates": list(facts.external_crates),
                "local_modules": list(facts.local_modules),
            },
        }

    def deserialize_parsed(self, source: SourceFile, payload: Mapping[str, object]) -> ParsedFile:
        if not isinstance(payload, dict) or set(payload) != {"line_count", "complete", "facts"}:
            raise ValueError("Cached Rust object has unexpected fields")
        line_count = payload["line_count"]
        complete = payload["complete"]
        if isinstance(line_count, bool) or not isinstance(line_count, int) or line_count < 0:
            raise ValueError("Cached Rust integer is invalid")
        if not isinstance(complete, bool):
            raise ValueError("Cached Rust boolean is invalid")
        data = payload["facts"]
        expected = {"imports", "identifiers", "code_text", "external_crates", "local_modules"}
        if not isinstance(data, dict) or set(data) != expected:
            raise ValueError("Cached Rust facts have unexpected fields")
        code_text = data["code_text"]
        if not isinstance(code_text, str) or len(code_text) > _MAX_CACHED_STRING:
            raise ValueError("Cached Rust string is invalid")
        facts = RustFacts(
            imports=_string_tuple(data["imports"], _MAX_IMPORTS),
            identifiers=_string_tuple(data["identifiers"], _MAX_IDENTIFIERS),
            code_text=code_text,
            external_crates=_string_tuple(data["external_crates"], _MAX_IMPORTS),
            local_modules=_string_tuple(data["local_modules"], _MAX_IMPORTS),
        )
        return ParsedFile(source, facts, facts, line_count, complete)


def _string_tuple(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Cached Rust list is invalid")
    if not all(isinstance(item, str) and len(item) <= 4096 for item in value):
        raise ValueError("Cached Rust list item is invalid")
    return tuple(value)


def _blank_test_code(code_text: str) -> str:
    """Blank ``#[cfg(test)] mod … { }`` blocks and ``#[test] fn … { }`` bodies."""
    output = list(code_text)
    for pattern in (_CFG_TEST_MOD, _TEST_FN):
        for match in pattern.finditer(code_text):
            end = block_end(code_text, match.end() - 1)
            for index in range(match.start(), end):
                if output[index] != "\n":
                    output[index] = " "
    return "".join(output)


class RustUnwrapDensityRule:
    """Report files that lean on ``.unwrap()`` outside test code."""

    rule_id = "RS-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, RustFacts):
            return
        path = parsed.source.identity_path or parsed.source.display_path
        if is_test_path(path) or re.search(r"(?:^|/)(?:benches|examples)/", path):
            return
        code_text = _blank_test_code(parsed.facts.code_text)
        matches = list(_UNWRAP.finditer(code_text))
        if len(matches) <= NON_NULL_LIMIT:
            return
        line, column = line_column(code_text, matches[0].start())
        yield downgrade_in_tests(
            parsed,
            Finding(
                rule_id=self.rule_id,
                category="correctness",
                severity="warning",
                confidence="medium",
                message=(
                    f"File uses {len(matches)} .unwrap() calls outside test code "
                    f"(limit {NON_NULL_LIMIT})."
                ),
                location=Location(
                    path=parsed.source.display_path,
                    line=line,
                    column=column,
                    identity_path=parsed.source.identity_path,
                ),
                remediation=(
                    "Propagate with `?`, match on the Option/Result, or use "
                    '`.expect("why this cannot fail")` to document the invariant.'
                ),
            ),
        )


class RustRulePack(RegexRulePackBase):
    """Run the bounded built-in Rust pilot rules."""

    rule_pack_id = RUST_RULE_PACK_ID
    language_id = "rust"
    ruleset_version = "0.1.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (RustUnwrapDensityRule(),)


class RustArchitectureSignalProvider:
    """Extract Rust DSA and design signals from blanked adapter facts."""

    provider_id = "rust-architecture-signals"
    language_id = "rust"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        facts = parsed.facts
        if not isinstance(facts, RustFacts):
            raise TypeError("Rust signal provider requires RustFacts")
        return signal_observations(
            parsed,
            facts.identifiers,
            facts.imports,
            facts.code_text,
            (
                ("architecture.dsa", RUST_DSA_PATTERNS),
                ("architecture.design", RUST_DESIGN_PATTERNS),
            ),
        )


class RustCargoPackageProvider:
    """Passive ``Cargo.toml`` discovery and crate drift.

    Governing manifest = nearest enclosing ``Cargo.toml``; a workspace root's
    ``[workspace.dependencies]`` counts for every member. A crate root named
    by ``use``/``extern crate`` is undeclared when it is not a std root, not a
    module declared anywhere in the project, and not in any dependency table
    of the manifest chain (``-`` and ``_`` are equivalent in crate names).
    """

    provider_id = "rust-cargo-package"
    language_id = "rust"
    capability = "package"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True
    drift_rule_id = "RS-PKG-001"
    invalid_rule_id = "RS-PKG-002"

    def analyze(self, project: ProjectContext) -> ProviderResult:
        manifest_dirs, truncated = discover_manifest_dirs(
            project.root, project.parsed_files, _MANIFEST_FILENAMES
        )
        manifests = {d: _load_cargo_manifest(project.root, d) for d in manifest_dirs}
        local_modules: set[str] = set()
        for parsed in project.parsed_files.values():
            if isinstance(parsed.facts, RustFacts):
                local_modules.update(parsed.facts.local_modules)
                # ``src/foo.rs`` / ``src/foo/mod.rs`` are modules too.
                stem = Path(parsed.source.identity_path or parsed.source.display_path).stem
                local_modules.add(stem)
        findings: list[Finding] = []
        for directory in sorted(manifest_dirs):
            info = manifests[directory]
            report_path, identity = manifest_report_path(
                directory, "Cargo.toml", project.redact_paths
            )
            if info["unreadable"]:
                findings.append(
                    Finding(
                        rule_id=self.invalid_rule_id,
                        category="package-health",
                        severity="error",
                        confidence="high",
                        message=f"{identity} cannot be read as TOML.",
                        location=Location(report_path, 1, 1, identity_path=identity),
                        remediation="Correct the Cargo.toml syntax and run analysis again.",
                    )
                )
        undeclared = _undeclared_crates(project.parsed_files, manifests, local_modules)
        for directory in sorted(undeclared):
            report_path, identity = manifest_report_path(
                directory, "Cargo.toml", project.redact_paths
            )
            for crate, example in undeclared[directory]:
                findings.append(
                    Finding(
                        rule_id=self.drift_rule_id,
                        category="package-health",
                        severity="warning",
                        confidence="medium",
                        message=(
                            f"Crate '{crate}' is used (for example in {example}) but "
                            f"not declared in {identity}."
                        ),
                        location=Location(report_path, 1, 1, identity_path=identity),
                        remediation=(
                            "Add the crate to [dependencies] (or [dev-dependencies]) "
                            "or remove the use."
                        ),
                    )
                )
        payload = {
            "manifests": [
                {
                    "path": manifest_report_path(d, "Cargo.toml", False)[1],
                    "kind": "cargo",
                    "package": manifests[d]["package"],
                    "workspace": manifests[d]["workspace"],
                    "unreadable": manifests[d]["unreadable"],
                    "dependency_count": len(manifests[d]["dependencies"]),
                    "undeclared_crates": [c for c, _ in undeclared.get(d, [])],
                }
                for d in manifest_dirs
            ],
            "manifests_truncated": truncated,
        }
        errors = sum(1 for info in manifests.values() if info["unreadable"])
        return ProviderResult(
            payload=payload,
            health={"complete": not truncated, "errors": errors},
            findings=tuple(findings),
        )


_DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _normalise_crate(name: str) -> str:
    """``-`` and ``_`` are interchangeable in crate names, and a few packages
    drop the separator in their lib name (``md-5`` -> ``md5``), so compare
    with separators removed."""
    return name.lower().replace("-", "").replace("_", "")


def _load_cargo_manifest(root: Path, directory: str) -> dict:
    info = {"package": None, "workspace": False, "dependencies": frozenset(), "unreadable": False}
    try:
        text = read_bounded_text(
            root / directory / "Cargo.toml", max_bytes=MAX_MANIFEST_BYTES, root=root
        )
        data = tomllib.loads(text)
    except (SafeReadError, OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        info["unreadable"] = True
        return info
    if not isinstance(data, dict):
        info["unreadable"] = True
        return info
    package = data.get("package")
    if isinstance(package, dict) and isinstance(package.get("name"), str):
        info["package"] = package["name"]
    declared: set[str] = set()
    for table in _DEPENDENCY_TABLES:
        declared.update(_dependency_names(data.get(table)))
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        info["workspace"] = True
        declared.update(_dependency_names(workspace.get("dependencies")))
    target = data.get("target")
    if isinstance(target, dict):
        for cfg in target.values():
            if isinstance(cfg, dict):
                for table in _DEPENDENCY_TABLES:
                    declared.update(_dependency_names(cfg.get(table)))
    info["dependencies"] = frozenset(declared)
    return info


def _dependency_names(table: object) -> set[str]:
    if not isinstance(table, dict):
        return set()
    names: set[str] = set()
    for key, spec in table.items():
        names.add(_normalise_crate(key))
        # ``foo = { package = "real-name", version = "1" }`` renames a crate.
        if isinstance(spec, dict) and isinstance(spec.get("package"), str):
            names.add(_normalise_crate(spec["package"]))
    return names


def _undeclared_crates(
    parsed_files, manifests: dict, local_modules: set[str]
) -> dict[str, list[tuple[str, str]]]:
    first_seen: dict[str, dict[str, str]] = {}
    manifest_dirs = list(manifests)
    for identity_path in sorted(parsed_files):
        parsed = parsed_files[identity_path]
        if not isinstance(parsed.facts, RustFacts):
            continue
        directory = nearest_manifest_dir(identity_path, manifest_dirs)
        if directory is None:
            continue
        chain = manifest_chain(directory, manifest_dirs)
        if any(manifests[entry]["unreadable"] for entry in chain):
            continue
        declared: set[str] = set()
        for entry in chain:
            declared.update(manifests[entry]["dependencies"])
            package = manifests[entry]["package"]
            if package:
                declared.add(_normalise_crate(package))  # the crate's own name
        for crate in parsed.facts.external_crates:
            if crate in local_modules or _normalise_crate(crate) in declared:
                continue
            if _normalise_crate(crate) in {_normalise_crate(m) for m in local_modules}:
                continue
            first_seen.setdefault(directory, {}).setdefault(crate, parsed.source.display_path)
    return {directory: sorted(crates.items()) for directory, crates in first_seen.items()}


def register_rust_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the Rust pilot (called by the deep module when its grammar is present)."""
    registry.register_language(RustLanguageAdapter())
    registry.register_rule_pack(RustRulePack())
    registry.register_signal_provider(RustArchitectureSignalProvider())
    registry.register_project_provider(RustCargoPackageProvider())
    return registry
