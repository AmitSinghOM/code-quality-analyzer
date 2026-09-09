"""Bounded Kotlin pilot: adapter, rule pack, signals, and JVM package reuse.

Kotlin shares the JVM ecosystem with Java, so this pilot reuses the Java
package provider (Maven/Gradle manifests, conservative drift) and extends
the Java signal catalog. Only the lexer and identifier extraction are
Kotlin-specific: nested block comments, ``$name``/``${expr}`` string
templates, ``\"\"\"`` raw strings, semicolon-free imports with ``as``
aliases, and ``fun``/``val``/``var``/``object``/``data class`` declarations.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from ..findings import Finding, Location
from ..kotlin_patterns import KOTLIN_DESIGN_PATTERNS, KOTLIN_DSA_PATTERNS
from ..protocols import (
    DEFAULT_CAPABILITY_VERSION,
    PLUGIN_API_VERSION,
    ParsedFile,
    SignalObservation,
    SourceFile,
)
from ..registry import PluginRegistry
from ._shared import RegexRulePackBase, line_column, signal_observations
from .java import JavaFacts, JavaPackageProvider

KOTLIN_ADAPTER_VERSION = "1.0.0"
KOTLIN_CACHE_CODEC_VERSION = "1.0.0"
KOTLIN_RULE_PACK_ID = "kotlin-core"
_MAX_CACHED_STRING = 4 * 1024 * 1024
_MAX_IDENTIFIERS = 20_000
_MAX_IMPORTS = 20_000

_IMPORT = re.compile(
    r"(?m)^\s*import\s+([A-Za-z_][\w.]*?)(?:\.\*)?(?:\s+as\s+[A-Za-z_]\w*)?\s*;?\s*$"
)
_PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_][\w.]*)\s*;?\s*$")
_TYPE_DECLARATION = re.compile(
    r"\b(?:class|interface|object|typealias|enum\s+class|data\s+class|"
    r"sealed\s+class|value\s+class|annotation\s+class)\s+([A-Za-z_][\w]*)"
)
_FUN_DECLARATION = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?([A-Za-z_]\w*)\s*\(")
_VALUE_DECLARATION = re.compile(r"\b(?:val|var)\s+([A-Za-z_]\w*)")
_TYPE_ANNOTATION = re.compile(r":\s*([A-Z]\w*)")
_ANNOTATION = re.compile(r"@([A-Za-z_]\w*)")
_GENERIC_USE = re.compile(r"\b([A-Z]\w*)\s*<")
_SELECTOR_CALL = re.compile(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(")
_BARE_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*(?:<[^<>()]*>)?\s*\(")
_EMPTY_CATCH = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}")
_KEYWORDS = frozenset({
    "as", "break", "class", "continue", "do", "else", "false", "for", "fun",
    "if", "in", "interface", "is", "null", "object", "package", "return",
    "super", "this", "throw", "true", "try", "typealias", "typeof", "val",
    "var", "when", "while", "by", "catch", "constructor", "delegate",
    "dynamic", "field", "file", "finally", "get", "import", "init", "param",
    "property", "receiver", "set", "setparam", "where", "abstract", "actual",
    "annotation", "companion", "const", "crossinline", "data", "enum",
    "expect", "external", "final", "infix", "inline", "inner", "internal",
    "lateinit", "noinline", "open", "operator", "out", "override", "private",
    "protected", "public", "reified", "sealed", "suspend", "tailrec",
    "vararg", "it",
})


def _strip_kotlin_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank comments and optional string contents, preserving layout.

    Block comments nest in Kotlin. String templates ``${...}`` are lexed as
    code holes (they may contain strings and braces) but blanked, so
    template content is never evidence.
    """
    output = list(source)
    index = 0
    state = "code"
    complete = True
    comment_depth = 0
    # Open template holes: (unmatched brace depth, string state to resume).
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
                comment_depth = 1
                index += 2
                continue
            if source.startswith('"""', index):
                blank_run(index, 3)
                state = "raw"
                index += 3
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
            if current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                comment_depth += 1
                index += 2
                continue
            if current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                comment_depth -= 1
                if comment_depth == 0:
                    state = "code"
                index += 2
                continue
            if current != "\n":
                output[index] = " "
            index += 1
            continue
        elif state in {"string", "raw"}:
            if state == "string" and current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
                continue
            if current == "$" and following == "{":
                blank_run(index, 2)
                holes.append((0, state))
                state = "code"
                index += 2
                continue
            if state == "raw" and source.startswith('"""', index):
                # Kotlin: the terminator is the LAST three quotes of a run;
                # any extra leading quotes are string content.
                run = 3
                while index + run < len(source) and source[index + run] == '"':
                    run += 1
                blank_run(index, run)
                state = "code"
                index += run
                continue
            if state == "string" and current == '"':
                blank(index)
                state = "code"
                index += 1
                continue
            if state == "string" and current == "\n":
                state = "code"
                complete = False
                index += 1
                continue
            blank(index)
            index += 1
            continue
        elif state == "char":
            if current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
                continue
            if current == "'":
                blank(index)
                state = "code"
            elif current == "\n":
                state = "code"
                complete = False
            else:
                blank(index)
            index += 1
            continue
        index += 1

    if state != "code" or holes:
        complete = state == "line_comment" and not holes
    return "".join(output), complete


def _kotlin_imports(metadata_text: str) -> tuple[str, ...]:
    found = {match.group(1) for match in _IMPORT.finditer(metadata_text)}
    return tuple(sorted(found)[:_MAX_IMPORTS])


def _kotlin_identifiers(code_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in (
        _TYPE_DECLARATION, _FUN_DECLARATION, _VALUE_DECLARATION,
        _TYPE_ANNOTATION, _ANNOTATION, _GENERIC_USE, _BARE_CALL,
    ):
        for match in pattern.finditer(code_text):
            names.add(match.group(1))
            if len(names) >= _MAX_IDENTIFIERS:
                break
    for match in _SELECTOR_CALL.finditer(code_text):
        qualifier, member = match.group(1), match.group(2)
        names.update((qualifier, member, f"{qualifier}.{member}"))
        if len(names) >= _MAX_IDENTIFIERS:
            break
    return tuple(sorted(names - _KEYWORDS)[:_MAX_IDENTIFIERS])


class KotlinFacts(JavaFacts):
    """Kotlin facts share the Java shape so JVM package intelligence applies."""

    __slots__ = ()


class KotlinLanguageAdapter:
    """Extract bounded Kotlin facts without executing any toolchain."""

    language_id = "kotlin"
    adapter_version = KOTLIN_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".kt", ".kts")
    cache_codec_version = KOTLIN_CACHE_CODEC_VERSION
    cache_runtime_version = "portable"

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_kotlin_comments_and_strings(
            source.content
        )
        metadata_text, metadata_complete = _strip_kotlin_comments_and_strings(
            source.content,
            blank_strings=False,
        )
        package = _PACKAGE.search(code_text)
        facts = KotlinFacts(
            package_name=package.group(1) if package else None,
            imports=_kotlin_imports(metadata_text),
            identifiers=_kotlin_identifiers(code_text),
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
        if not isinstance(facts, KotlinFacts):
            raise TypeError("Kotlin cache codec requires KotlinFacts")
        return {
            "line_count": parsed.line_count,
            "complete": parsed.complete,
            "facts": {
                "package_name": facts.package_name,
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
        if not isinstance(payload, dict) or set(payload) != {
            "line_count", "complete", "facts",
        }:
            raise ValueError("Cached Kotlin object has unexpected fields")
        line_count = payload["line_count"]
        complete = payload["complete"]
        if isinstance(line_count, bool) or not isinstance(line_count, int) or line_count < 0:
            raise ValueError("Cached Kotlin integer is invalid")
        if not isinstance(complete, bool):
            raise ValueError("Cached Kotlin boolean is invalid")
        fact_data = payload["facts"]
        if not isinstance(fact_data, dict) or set(fact_data) != {
            "package_name", "imports", "identifiers", "code_text",
        }:
            raise ValueError("Cached Kotlin facts have unexpected fields")
        package_name = fact_data["package_name"]
        if package_name is not None and not isinstance(package_name, str):
            raise ValueError("Cached Kotlin package name is invalid")
        code_text = fact_data["code_text"]
        if not isinstance(code_text, str) or len(code_text) > _MAX_CACHED_STRING:
            raise ValueError("Cached Kotlin string is invalid")
        facts = KotlinFacts(
            package_name=package_name,
            imports=_string_tuple(fact_data["imports"], _MAX_IMPORTS),
            identifiers=_string_tuple(fact_data["identifiers"], _MAX_IDENTIFIERS),
            code_text=code_text,
        )
        return ParsedFile(source, facts, facts, line_count, complete)


def _string_tuple(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Cached Kotlin string list is invalid")
    for item in value:
        if not isinstance(item, str) or len(item) > _MAX_CACHED_STRING:
            raise ValueError("Cached Kotlin string is invalid")
    return tuple(value)


class KotlinEmptyCatchRule:
    """Detect catch blocks whose blanked body is empty."""

    rule_id = "KT-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, KotlinFacts):
            return
        for match in _EMPTY_CATCH.finditer(parsed.facts.code_text):
            line, column = line_column(parsed.facts.code_text, match.start())
            yield Finding(
                rule_id=self.rule_id,
                category="correctness",
                severity="warning",
                confidence="high",
                message="An empty catch block silently discards the failure.",
                location=Location(
                    path=parsed.source.display_path,
                    line=line,
                    column=column,
                    identity_path=parsed.source.identity_path,
                ),
                remediation=(
                    "Handle the failure, log actionable context, or rethrow "
                    "the exception."
                ),
            )


class KotlinRulePack(RegexRulePackBase):
    """Run the bounded built-in Kotlin pilot rules."""

    rule_pack_id = KOTLIN_RULE_PACK_ID
    language_id = "kotlin"
    ruleset_version = "1.0.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (KotlinEmptyCatchRule(),)


class KotlinArchitectureSignalProvider:
    """Extract Kotlin DSA and design signals via the extended Java catalog."""

    provider_id = "kotlin-architecture-signals"
    language_id = "kotlin"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        facts = parsed.facts
        if not isinstance(facts, KotlinFacts):
            raise TypeError("Kotlin signal provider requires KotlinFacts")
        return signal_observations(
            parsed,
            facts.identifiers,
            facts.imports,
            facts.code_text,
            (
                ("architecture.dsa", KOTLIN_DSA_PATTERNS),
                ("architecture.design", KOTLIN_DESIGN_PATTERNS),
            ),
        )


class KotlinPackageProvider(JavaPackageProvider):
    """Maven/Gradle intelligence for Kotlin sources, via the Java provider."""

    provider_id = "kotlin-package"
    language_id = "kotlin"
    drift_rule_id = "KT-PKG-001"
    invalid_rule_id = "KT-PKG-002"


def register_kotlin_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Kotlin pilot plugins."""
    registry.register_language(KotlinLanguageAdapter())
    registry.register_rule_pack(KotlinRulePack())
    registry.register_signal_provider(KotlinArchitectureSignalProvider())
    registry.register_project_provider(KotlinPackageProvider())
    return registry
