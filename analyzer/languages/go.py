"""Bounded Go adapter and high-confidence pilot rule pack."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..findings import Finding, Location
from ..protocols import ParsedFile, SourceFile
from ..registry import PluginRegistry

GO_ADAPTER_VERSION = "1.0.0"
GO_RULE_PACK_ID = "go-core"

_PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_]\w*)\s*$")
_SINGLE_IMPORT = re.compile(r'(?m)^\s*import\s+"([^"]+)"')
_IMPORT_BLOCK = re.compile(r"(?s)\bimport\s*\((.*?)\)")
_IMPORT_PATH = re.compile(r'"([^"]+)"')

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


@dataclass(frozen=True, slots=True)
class GoFacts:
    """Small adapter-owned Go fact model."""

    package_name: str
    imports: tuple[str, ...]
    code_text: str


class GoLanguageAdapter:
    """Extract bounded Go package/import facts without executing Go tools."""

    language_id = "go"
    adapter_version = GO_ADAPTER_VERSION
    extensions = (".go",)

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_comments_and_strings(
            source.content
        )
        package = _PACKAGE.search(source.content)
        facts = (
            GoFacts(
                package_name=package.group(1),
                imports=_imports(source.content),
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
            complete=lexical_complete and facts is not None,
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


class GoRulePack:
    """Run the bounded built-in Go pilot rules."""

    rule_pack_id = GO_RULE_PACK_ID
    language_id = "go"
    ruleset_version = "2.3.0"

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
    return registry


def _allowed_calls(imports: tuple[str, ...]) -> set[tuple[str, str]]:
    allowed = set()
    imported = set(imports)
    for qualified_call in _KNOWN_ERROR_CALLS:
        module, _, call = qualified_call.rpartition(".")
        if module in imported:
            allowed.add((module.rpartition("/")[2], call))
    return allowed


def _imports(source: str) -> tuple[str, ...]:
    imports = set(_SINGLE_IMPORT.findall(source))
    for block in _IMPORT_BLOCK.findall(source):
        imports.update(_IMPORT_PATH.findall(block))
    return tuple(sorted(imports))


def _line_column(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _strip_comments_and_strings(source: str) -> tuple[str, bool]:
    """Blank Go comments and string contents while preserving layout."""
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
                output[index] = " "
                state = "code"
            elif current != "\n":
                output[index] = " "
            index += 1
            continue
        elif state == "string":
            if current == "\\" and following:
                output[index] = " "
                if following != "\n":
                    output[index + 1] = " "
                index += 2
                continue
            if current == quote:
                output[index] = " "
                state = "code"
            elif current != "\n":
                output[index] = " "
            index += 1
            continue

        index += 1

    if state in {"block_comment", "raw_string", "string"}:
        complete = False
    return "".join(output), complete
