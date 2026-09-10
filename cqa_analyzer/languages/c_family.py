"""Bounded C/C++ ("C-family lite") pilot — roadmap item 8, path (a).

Why this pilot is deliberately narrower than the others:

- **The preprocessor is not modelled.** Every ``#`` directive line
  (including ``\\``-continued lines) is blanked from ``code_text``, so
  macro bodies are never evidence and macro-generated syntax is never
  matched. Conditional compilation is not evaluated: code under
  ``#if 0`` is still visible, which can only over-report signals, never
  hide a finding. ``#include`` paths are captured as the file's imports.
- **CMake only.** ``CMakeLists.txt`` is the sole manifest understood;
  Conan, vcpkg, Bazel, Meson, and Makefiles are not.
- **Rules are lexical.** ``C-COR-001`` (empty catch) is the only rule;
  nothing here claims to understand types, ownership, or lifetimes.

Lexer specifics: ``//`` comments honour ``\\``-newline continuation,
block comments do not nest, string literals accept encoding prefixes and
C++11 raw strings ``R"delim(...)delim"``, and a ``'`` between two
hexadecimal digits is a C++14 digit separator, not a character literal.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from ..c_patterns import C_DESIGN_PATTERNS, C_DSA_PATTERNS
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
from ..safe_io import SafeReadError, read_bounded_text
from ._shared import RegexRulePackBase, empty_catch_finding, signal_observations

C_ADAPTER_VERSION = "1.0.0"
C_CACHE_CODEC_VERSION = "1.0.0"
C_RULE_PACK_ID = "c-core"
_MAX_CACHED_STRING = 4 * 1024 * 1024
_MAX_IDENTIFIERS = 20_000
_MAX_INCLUDES = 5_000
_MANIFEST_FILENAMES = ("CMakeLists.txt",)

_INCLUDE = re.compile(r'(?m)^[ \t]*#[ \t]*include[ \t]*[<"]([^>"\n]+)[>"]')
_TYPE_DECLARATION = re.compile(
    r"\b(?:class|struct|union|enum(?:\s+class|\s+struct)?|namespace|concept)\s+"
    r"(?:\[\[[^\]]*\]\]\s*)?([A-Za-z_]\w*)"
)
# Possessive quantifiers (Python 3.11+) make every identifier regex
# linear: once a `\w` run or a `::` chain is consumed it is never given
# back, so `a::a::a::…` and `b<b<b<…` cannot trigger quadratic
# backtracking (found by tests/test_lexer_fuzz.py — 42 s on 200 KB).
_TYPEDEF = re.compile(r"\btypedef\b(?:[^;{]|\{[^{}]*+\})*?\b([A-Za-z_]\w*+)\s*+;")
_USING = re.compile(r"\busing\s++(?:namespace\s++)?([A-Za-z_][\w:]*+)")
_QUALIFIED_CALL = re.compile(
    r"\b((?:[A-Za-z_]\w*+::)++[A-Za-z_]\w*+)\s*+(?:<[^<>()]*+>)?\s*+\("
)
_QUALIFIED_TYPE = re.compile(r"\b((?:[A-Za-z_]\w*+::)++[A-Za-z_]\w*+)\b")
_MEMBER_CALL = re.compile(r"(?:\.|->)\s*+([A-Za-z_]\w*+)\s*+(?:<[^<>()]*+>)?\s*+\(")
_BARE_CALL = re.compile(r"\b([A-Za-z_]\w*+)\s*+(?:<[^<>()]*+>)?\s*+\(")
_TEMPLATE_USE = re.compile(r"\b([A-Za-z_]\w*+)\s*+<")
_DECLARED_NAME = re.compile(
    r"(?m)\b(?:[A-Za-z_]\w*+(?:::\w++)*+(?:<[^<>;]*+>)?[\s*&]++)([a-z_]\w*+)\s*+(?:[=;\[({,)]|$)"
)
_EMPTY_CATCH = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}")
_STRING_PREFIX = re.compile(r"(?:u8|u|U|L)?R?$")
_KEYWORDS = frozenset(
    {
        "alignas",
        "alignof",
        "and",
        "asm",
        "auto",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "class",
        "concept",
        "const",
        "consteval",
        "constexpr",
        "constinit",
        "continue",
        "co_await",
        "co_return",
        "co_yield",
        "decltype",
        "default",
        "delete",
        "do",
        "double",
        "else",
        "enum",
        "explicit",
        "export",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "not",
        "nullptr",
        "operator",
        "or",
        "private",
        "protected",
        "public",
        "register",
        "reinterpret_cast",
        "static_cast",
        "dynamic_cast",
        "const_cast",
        "requires",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_assert",
        "struct",
        "switch",
        "template",
        "this",
        "thread_local",
        "throw",
        "true",
        "try",
        "typedef",
        "typeid",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "while",
        "override",
        "final",
        "restrict",
        "_Bool",
        "_Atomic",
        "defined",
        "NULL",
        "size_t",
        "int32_t",
        "int64_t",
        "uint32_t",
        "uint64_t",
        "uint8_t",
        "int8_t",
        "uint16_t",
        "int16_t",
        "main",
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "memcpy",
        "memset",
        "strlen",
        "strcmp",
        "strcpy",
        "malloc",
        "free",
        "realloc",
        "calloc",
        "std",
    }
)
_HEX = frozenset("0123456789abcdefABCDEF")


def _is_digit_separator(source: str, index: int) -> bool:
    """True when the ``'`` at ``index`` sits inside a numeric literal.

    Walk back over hex digits and separators to the token start; it must
    begin with a decimal digit (`1'000`, `0xFF'FF`). `case'a'` and `u8'a'`
    start with a letter and are char literals.
    """
    following = source[index + 1] if index + 1 < len(source) else ""
    if following not in _HEX:
        return False
    start = index
    while start > 0 and (source[start - 1] in _HEX or source[start - 1] in "'xX"):
        start -= 1
    token = source[start:index]
    return (
        bool(token)
        and token[0].isdigit()
        and (start == 0 or not (source[start - 1].isalnum() or source[start - 1] == "_"))
    )


def _strip_c_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
    blank_directives: bool = True,
) -> tuple[str, bool]:
    """Blank comments, optional strings, and optional preprocessor lines.

    Layout (line count and column positions) is preserved so locations
    computed on the blanked text are valid for the original.
    """
    output = list(source)
    index = 0
    state = "code"
    complete = True
    raw_terminator = ""
    at_line_start = True

    def blank(position: int) -> None:
        if source[position] != "\n":
            output[position] = " "

    def blank_string_char(position: int) -> None:
        if blank_strings:
            blank(position)

    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if at_line_start and current == "#":
                state = "directive" if blank_directives else "directive_keep"
                if blank_directives:
                    blank(index)
                index += 1
                continue
            if current not in " \t":
                at_line_start = current == "\n"
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
            if current == '"':
                prefix = _STRING_PREFIX.search(source, max(0, index - 3), index)
                is_raw = (
                    prefix is not None
                    and prefix.group(0).endswith("R")
                    and (
                        prefix.start() == 0
                        or not (
                            source[prefix.start() - 1].isalnum()
                            or source[prefix.start() - 1] == "_"
                        )
                    )
                )
                if is_raw:
                    close = source.find("(", index + 1)
                    if close == -1:
                        complete = False
                        break
                    raw_terminator = ")" + source[index + 1 : close] + '"'
                    for position in range(index, close + 1):
                        blank_string_char(position)
                    state = "raw"
                    index = close + 1
                    continue
                blank_string_char(index)
                state = "string"
                index += 1
                continue
            if current == "'":
                if _is_digit_separator(source, index):
                    index += 1  # C++14 digit separator: 1'000'000, 0xFF'FF
                    continue
                blank_string_char(index)
                state = "char"
                index += 1
                continue
            index += 1
            continue
        if state in {"directive", "directive_keep"}:
            if current == "\\" and following == "\n":
                if state == "directive":
                    blank(index)
                index += 2
                continue
            if current == "/" and following == "*":
                # Block comment inside a directive: blank through its end.
                end = source.find("*/", index + 2)
                stop = len(source) if end == -1 else end + 2
                for position in range(index, stop):
                    blank(position)
                index = stop
                continue
            if current == "\n":
                state = "code"
                at_line_start = True
            elif state == "directive":
                blank(index)
            index += 1
            continue
        if state == "line_comment":
            if current == "\\" and following == "\n":
                blank(index)
                index += 2
                continue
            if current == "\n":
                state = "code"
                at_line_start = True
            else:
                output[index] = " "
            index += 1
            continue
        if state == "block_comment":
            if current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if current != "\n":
                output[index] = " "
            index += 1
            continue
        if state == "raw":
            if source.startswith(raw_terminator, index):
                for position in range(index, index + len(raw_terminator)):
                    blank_string_char(position)
                index += len(raw_terminator)
                state = "code"
                continue
            blank_string_char(index)
            index += 1
            continue
        if state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if current == "\\" and following:
                blank_string_char(index)
                if following != "\n":
                    blank_string_char(index + 1)
                index += 2
                continue
            if current == quote:
                blank_string_char(index)
                state = "code"
                index += 1
                continue
            if current == "\n":
                state = "code"
                complete = False
                at_line_start = True
                index += 1
                continue
            blank_string_char(index)
            index += 1
            continue
        index += 1

    if state not in {"code", "line_comment", "directive", "directive_keep"}:
        complete = False
    return "".join(output), complete


def _c_includes(metadata_text: str) -> tuple[str, ...]:
    found = {match.group(1).strip() for match in _INCLUDE.finditer(metadata_text)}
    return tuple(sorted(found)[:_MAX_INCLUDES])


def _c_identifiers(code_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in (
        _TYPE_DECLARATION,
        _TYPEDEF,
        _USING,
        _QUALIFIED_CALL,
        _QUALIFIED_TYPE,
        _MEMBER_CALL,
        _BARE_CALL,
        _TEMPLATE_USE,
        _DECLARED_NAME,
    ):
        for match in pattern.finditer(code_text):
            name = match.group(1)
            names.add(name)
            if "::" in name:
                names.add(name.rsplit("::", 1)[-1])
            if len(names) >= _MAX_IDENTIFIERS:
                break
    return tuple(sorted(names - _KEYWORDS)[:_MAX_IDENTIFIERS])


class CFacts:
    """Small adapter-owned C/C++ fact model."""

    __slots__ = ("includes", "identifiers", "code_text")

    def __init__(
        self,
        includes: tuple[str, ...],
        identifiers: tuple[str, ...],
        code_text: str,
    ) -> None:
        self.includes = includes
        self.identifiers = identifiers
        self.code_text = code_text

    @property
    def imports(self) -> tuple[str, ...]:
        return self.includes

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CFacts) and (
            self.includes,
            self.identifiers,
            self.code_text,
        ) == (other.includes, other.identifiers, other.code_text)

    __hash__ = None


class CLanguageAdapter:
    """Extract bounded C/C++ facts without running any compiler."""

    language_id = "c_cpp"
    adapter_version = C_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")
    cache_codec_version = C_CACHE_CODEC_VERSION
    cache_runtime_version = "portable"

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_c_comments_and_strings(source.content)
        metadata_text, metadata_complete = _strip_c_comments_and_strings(
            source.content,
            blank_strings=False,
            blank_directives=False,
        )
        facts = CFacts(
            includes=_c_includes(metadata_text),
            identifiers=_c_identifiers(code_text),
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
        if not isinstance(facts, CFacts):
            raise TypeError("C cache codec requires CFacts")
        return {
            "line_count": parsed.line_count,
            "complete": parsed.complete,
            "facts": {
                "includes": list(facts.includes),
                "identifiers": list(facts.identifiers),
                "code_text": facts.code_text,
            },
        }

    def deserialize_parsed(
        self,
        source: SourceFile,
        payload: Mapping[str, object],
    ) -> ParsedFile:
        if not isinstance(payload, dict) or set(payload) != {
            "line_count",
            "complete",
            "facts",
        }:
            raise ValueError("Cached C object has unexpected fields")
        line_count = payload["line_count"]
        complete = payload["complete"]
        if isinstance(line_count, bool) or not isinstance(line_count, int) or line_count < 0:
            raise ValueError("Cached C integer is invalid")
        if not isinstance(complete, bool):
            raise ValueError("Cached C boolean is invalid")
        fact_data = payload["facts"]
        if not isinstance(fact_data, dict) or set(fact_data) != {
            "includes",
            "identifiers",
            "code_text",
        }:
            raise ValueError("Cached C facts have unexpected fields")
        code_text = fact_data["code_text"]
        if not isinstance(code_text, str) or len(code_text) > _MAX_CACHED_STRING:
            raise ValueError("Cached C string is invalid")
        facts = CFacts(
            includes=_string_tuple(fact_data["includes"], _MAX_INCLUDES),
            identifiers=_string_tuple(fact_data["identifiers"], _MAX_IDENTIFIERS),
            code_text=code_text,
        )
        return ParsedFile(source, facts, facts, line_count, complete)


def _string_tuple(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Cached C string list is invalid")
    for item in value:
        if not isinstance(item, str) or len(item) > _MAX_CACHED_STRING:
            raise ValueError("Cached C string is invalid")
    return tuple(value)


class CEmptyCatchRule:
    """Detect C++ catch blocks whose blanked body is empty."""

    rule_id = "C-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, CFacts):
            return
        for match in _EMPTY_CATCH.finditer(parsed.facts.code_text):
            yield empty_catch_finding(self.rule_id, parsed, match, rethrow_word="exception")


class CRulePack(RegexRulePackBase):
    """Run the bounded built-in C/C++ pilot rules."""

    rule_pack_id = C_RULE_PACK_ID
    language_id = "c_cpp"
    ruleset_version = "1.0.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (CEmptyCatchRule(),)


class CArchitectureSignalProvider:
    """Extract C/C++ DSA and design signals from includes and identifiers."""

    provider_id = "c-architecture-signals"
    language_id = "c_cpp"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        facts = parsed.facts
        if not isinstance(facts, CFacts):
            raise TypeError("C signal provider requires CFacts")
        return signal_observations(
            parsed,
            facts.identifiers,
            facts.includes,
            facts.code_text,
            (
                ("architecture.dsa", C_DSA_PATTERNS),
                ("architecture.design", C_DESIGN_PATTERNS),
            ),
        )


# Header path prefix -> CMake tokens any of which counts as a declaration
# (find_package name, imported target, pkg-config module, or FetchContent
# name). Only libraries that are essentially always declared directly.
_DIRECT_LIBRARIES: dict[str, tuple[str, ...]] = {
    "boost/": ("boost",),
    "gtest/": ("gtest", "googletest"),
    "gmock/": ("gtest", "googletest", "gmock"),
    "catch2/": ("catch2",),
    "fmt/": ("fmt",),
    "spdlog/": ("spdlog",),
    "nlohmann/json": ("nlohmann_json", "nlohmann"),
    "openssl/": ("openssl", "libcrypto", "libssl", "crypto", "ssl"),
    "curl/curl.h": ("curl",),
    "sqlite3.h": ("sqlite3", "sqlite"),
    "grpcpp/": ("grpc", "grpc++"),
    "google/protobuf/": ("protobuf",),
    "absl/": ("absl", "abseil"),
    "zmq.h": ("zeromq", "zmq", "libzmq"),
    "zmq.hpp": ("cppzmq", "zmq"),
    "yaml-cpp/": ("yaml-cpp", "yaml_cpp"),
    "rapidjson/": ("rapidjson",),
    "pqxx/": ("libpqxx", "pqxx"),
    "hiredis/": ("hiredis",),
    "librdkafka/": ("rdkafka", "librdkafka"),
    "opentelemetry/": ("opentelemetry",),
    "prometheus/": ("prometheus", "prometheus-cpp"),
    "uv.h": ("libuv", "uv_a", "uv"),
    "event2/": ("libevent", "event_core", "event"),
    "zlib.h": ("zlib", "ZLIB::ZLIB", "libz"),
}


class CCMakePackageProvider:
    """Passive CMake discovery and conservative third-party header drift.

    Governing manifest = nearest enclosing ``CMakeLists.txt``. A header
    from the curated set is "undeclared" only when none of its CMake
    tokens appear anywhere in the manifest chain (whole text, case-
    insensitive), so ``find_package``, ``FetchContent``, imported
    targets, and ``pkg_check_modules`` all count. No manifest, no claim.
    """

    provider_id = "c-cmake-package"
    language_id = "c_cpp"
    capability = "package"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True
    drift_rule_id = "C-PKG-001"

    def analyze(self, project: ProjectContext) -> ProviderResult:
        manifest_dirs, truncated = discover_manifest_dirs(
            project.root,
            project.parsed_files,
            _MANIFEST_FILENAMES,
        )
        manifests = {
            directory: _load_cmake_manifest(project.root, directory) for directory in manifest_dirs
        }
        undeclared = _undeclared_headers(project.parsed_files, manifests)
        findings: list[Finding] = []
        for directory in sorted(undeclared):
            report_path, identity = manifest_report_path(
                directory,
                "CMakeLists.txt",
                project.redact_paths,
            )
            for header, tokens, example in undeclared[directory]:
                findings.append(
                    Finding(
                        rule_id=self.drift_rule_id,
                        category="package-health",
                        severity="warning",
                        confidence="medium",
                        message=(
                            f"Header '{header}' is included (for example in "
                            f"{example}) but none of {tokens} appears in {identity}."
                        ),
                        location=Location(report_path, 1, 1, identity_path=identity),
                        remediation=(
                            "Declare the library with find_package, FetchContent, "
                            "or pkg_check_modules, or remove the include."
                        ),
                    )
                )
        payload = {
            "manifests": [
                {
                    "path": manifest_report_path(directory, "CMakeLists.txt", False)[1],
                    "kind": "cmake",
                    "project": manifests[directory]["project"],
                    "unreadable": manifests[directory]["unreadable"],
                    "find_packages": sorted(manifests[directory]["find_packages"]),
                    "undeclared_headers": [
                        header for header, _, _ in undeclared.get(directory, [])
                    ],
                }
                for directory in manifest_dirs
            ],
            "manifests_truncated": truncated,
        }
        errors = sum(1 for info in manifests.values() if info["unreadable"])
        return ProviderResult(
            payload=payload,
            health={"complete": not truncated, "errors": errors},
            findings=tuple(findings),
        )


_CMAKE_PROJECT = re.compile(r"(?im)^\s*project\s*\(\s*([A-Za-z_][\w.-]*)")
_CMAKE_FIND_PACKAGE = re.compile(r"(?im)^\s*find_package\s*\(\s*([A-Za-z_][\w.+-]*)")


def _load_cmake_manifest(root: Path, directory: str) -> dict:
    info = {"project": None, "find_packages": set(), "tokens": frozenset(), "unreadable": False}
    try:
        text = read_bounded_text(
            root / directory / "CMakeLists.txt",
            max_bytes=MAX_MANIFEST_BYTES,
            root=root,
        )
    except (SafeReadError, OSError):
        info["unreadable"] = True
        return info
    project = _CMAKE_PROJECT.search(text)
    info["project"] = project.group(1) if project else None
    info["find_packages"] = {m.group(1) for m in _CMAKE_FIND_PACKAGE.finditer(text)}
    info["tokens"] = _cmake_tokens(text)
    return info


# Whole-word CMake tokens (identifiers, `Pkg::Target`, quoted names), lower-
# cased and at least 3 characters: `z` inside any word must not "declare"
# zlib, and a URL in a comment must not declare curl (staff review C2).
_CMAKE_WORD = re.compile(r"[A-Za-z_][\w+.-]*(?:::[A-Za-z_][\w+.-]*)*")
_CMAKE_COMMENT = re.compile(r"#[^\n]*")


def _cmake_token(token: str) -> str:
    return token.lower()


def _cmake_tokens(text: str) -> frozenset[str]:
    words = set()
    for match in _CMAKE_WORD.finditer(_CMAKE_COMMENT.sub("", text)):
        word = match.group(0).lower()
        if len(word) >= 3:
            words.add(word)
            if "::" in word:
                words.update(part for part in word.split("::") if len(part) >= 3)
    return frozenset(words)


def _undeclared_headers(
    parsed_files,
    manifests: dict,
) -> dict[str, list[tuple[str, str, str]]]:
    first_seen: dict[str, dict[str, tuple[str, str]]] = {}
    manifest_dirs = list(manifests)
    for identity_path in sorted(parsed_files):
        parsed = parsed_files[identity_path]
        if not isinstance(parsed.facts, CFacts):
            continue
        directory = nearest_manifest_dir(identity_path, manifest_dirs)
        if directory is None:
            continue
        chain = manifest_chain(directory, manifest_dirs)
        if any(manifests[entry]["unreadable"] for entry in chain):
            continue
        declared_tokens = set()
        for entry in chain:
            declared_tokens.update(manifests[entry]["tokens"])
        for include in parsed.facts.includes:
            for header, tokens in _DIRECT_LIBRARIES.items():
                if include == header or include.startswith(header):
                    if not any(_cmake_token(token) in declared_tokens for token in tokens):
                        first_seen.setdefault(directory, {}).setdefault(
                            header,
                            ("/".join(tokens), parsed.source.display_path),
                        )
                    break
    return {
        directory: sorted(
            (header, tokens, example) for header, (tokens, example) in headers.items()
        )
        for directory, headers in first_seen.items()
    }


def register_c_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in C/C++ pilot plugins."""
    registry.register_language(CLanguageAdapter())
    registry.register_rule_pack(CRulePack())
    registry.register_signal_provider(CArchitectureSignalProvider())
    registry.register_project_provider(CCMakePackageProvider())
    return registry
