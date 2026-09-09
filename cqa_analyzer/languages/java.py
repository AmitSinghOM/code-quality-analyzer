"""Bounded Java pilot adapter, rule pack, signal provider, and package provider.

Facts are extracted by regex from blanked source. The adapter never
executes ``javac``, Maven, or Gradle.

Known pilot bounds, accepted deliberately:

- Generic-method call sites (``Foo.<T>bar()``) and lambdas are lexed as
  ordinary code; identifiers inside them are still captured.
- Dependency drift is checked only against a curated map of libraries
  that are almost always direct dependencies, because Maven and Gradle
  make transitively provided classes importable (see ``_DIRECT_LIBRARIES``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from ..findings import Finding, Location
from ..java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS
from ..manifests import (
    MAX_MANIFEST_BYTES,
    discover_manifest_dirs,
    local_name,
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
from ._shared import RegexRulePackBase, line_column

JAVA_ADAPTER_VERSION = "1.0.0"
JAVA_CACHE_CODEC_VERSION = "1.0.0"
JAVA_RULE_PACK_ID = "java-core"
_MAX_CACHED_JAVA_STRING = 4 * 1024 * 1024
_MAX_JAVA_IDENTIFIERS = 20_000
_MAX_JAVA_IMPORTS = 20_000
_MANIFEST_FILENAMES = ("pom.xml", "build.gradle", "build.gradle.kts")

_IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*?)(?:\.\*)?\s*;")
_PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_][\w.]*)\s*;")
_TYPE_DECLARATION = re.compile(
    r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)"
)
_ANNOTATION = re.compile(r"@([A-Za-z_$][\w$]*)")
_GENERIC_USE = re.compile(r"\b([A-Z][\w$]*)\s*<")
_NEW_TARGET = re.compile(r"\bnew\s+([A-Za-z_$][\w$.]*)\s*[(<\[]")
_SELECTOR_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(")
_BARE_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
# ``Type name`` where a terminator follows: fields, locals, parameters.
_VARIABLE_DECLARATION = re.compile(
    r"\b[A-Za-z_$][\w$.]*(?:<[^<>;{}]*>)?(?:\[\])*\s+([a-z_$][\w$]*)\s*(?=[;=,)])"
)
_EMPTY_CATCH = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}")
_GRADLE_DEPENDENCY = re.compile(
    r"""\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"""
    r"""testRuntimeOnly|annotationProcessor|compile|testCompile)\s*\(?\s*"""
    r"""['"]([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)(?::[^'"]*)?['"]"""
)
_KEYWORDS = frozenset({
    "abstract", "assert", "boolean", "break", "byte", "case", "catch",
    "char", "class", "const", "continue", "default", "do", "double", "else",
    "enum", "extends", "final", "finally", "float", "for", "goto", "if",
    "implements", "import", "instanceof", "int", "interface", "long",
    "native", "new", "package", "private", "protected", "public", "record",
    "return", "short", "static", "strictfp", "super", "switch",
    "synchronized", "this", "throw", "throws", "transient", "try", "var",
    "void", "volatile", "while", "yield", "true", "false", "null",
})

# Import-prefix -> (groupId prefix, artifactId prefix) for libraries that
# are almost always declared directly. Deliberately excludes libraries
# that Spring Boot starters and similar aggregates provide transitively
# (Jackson, SLF4J, Hibernate, AssertJ, Mockito, Hamcrest via
# spring-boot-starter-test), where a missing declaration is normal.
_DIRECT_LIBRARIES = {
    "com.google.common": ("com.google.guava", "guava"),
    "com.google.gson": ("com.google.code.gson", "gson"),
    "org.apache.commons.lang3": ("org.apache.commons", "commons-lang3"),
    "org.apache.commons.io": ("commons-io", "commons-io"),
    "org.apache.commons.collections4": (
        "org.apache.commons", "commons-collections4",
    ),
    "lombok": ("org.projectlombok", "lombok"),
    "okhttp3": ("com.squareup.okhttp3", "okhttp"),
    "retrofit2": ("com.squareup.retrofit2", "retrofit"),
    "org.mapstruct": ("org.mapstruct", "mapstruct"),
    "io.jsonwebtoken": ("io.jsonwebtoken", "jjwt"),
    "com.github.benmanes.caffeine": ("com.github.ben-manes.caffeine", "caffeine"),
    "org.testcontainers": ("org.testcontainers", ""),
    "com.zaxxer.hikari": ("com.zaxxer", "HikariCP"),
    "org.flywaydb": ("org.flywaydb", "flyway"),
    "org.liquibase": ("org.liquibase", "liquibase"),
}


def _strip_java_comments_and_strings(
    source: str,
    *,
    blank_strings: bool = True,
) -> tuple[str, bool]:
    """Blank comments and optional string/char/text-block contents."""
    output = list(source)
    index = 0
    state = "code"
    complete = True

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
            if source.startswith('"""', index):
                for offset in range(3):
                    blank(index + offset)
                state = "text_block"
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
        elif state == "text_block":
            if current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
                continue
            if source.startswith('"""', index):
                for offset in range(3):
                    blank(index + offset)
                state = "code"
                index += 3
                continue
            blank(index)
            index += 1
            continue
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if current == "\\" and following:
                blank(index)
                if following != "\n":
                    blank(index + 1)
                index += 2
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
        index += 1

    if state in {"block_comment", "text_block", "string", "char"}:
        complete = False
    return "".join(output), complete


def _java_imports(metadata_text: str) -> tuple[str, ...]:
    found = {match.group(1) for match in _IMPORT.finditer(metadata_text)}
    return tuple(sorted(found)[:_MAX_JAVA_IMPORTS])


def _java_identifiers(code_text: str) -> tuple[str, ...]:
    names: set[str] = set()
    for pattern in (
        _TYPE_DECLARATION, _ANNOTATION, _GENERIC_USE, _BARE_CALL,
        _VARIABLE_DECLARATION,
    ):
        for match in pattern.finditer(code_text):
            names.add(match.group(1))
            if len(names) >= _MAX_JAVA_IDENTIFIERS:
                break
    for match in _NEW_TARGET.finditer(code_text):
        target = match.group(1)
        names.add(target)
        names.add(target.rpartition(".")[2])
    for match in _SELECTOR_CALL.finditer(code_text):
        qualifier, member = match.group(1), match.group(2)
        names.update((qualifier, member, f"{qualifier}.{member}"))
        if len(names) >= _MAX_JAVA_IDENTIFIERS:
            break
    return tuple(sorted(names - _KEYWORDS)[:_MAX_JAVA_IDENTIFIERS])


class JavaFacts:
    """Small adapter-owned Java fact model."""

    __slots__ = ("package_name", "imports", "identifiers", "code_text")

    def __init__(
        self,
        package_name: str | None,
        imports: tuple[str, ...],
        identifiers: tuple[str, ...],
        code_text: str,
    ) -> None:
        self.package_name = package_name
        self.imports = imports
        self.identifiers = identifiers
        self.code_text = code_text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, JavaFacts) and (
            self.package_name,
            self.imports,
            self.identifiers,
            self.code_text,
        ) == (
            other.package_name,
            other.imports,
            other.identifiers,
            other.code_text,
        )


class JavaLanguageAdapter:
    """Extract bounded Java facts without executing any toolchain."""

    language_id = "java"
    adapter_version = JAVA_ADAPTER_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    extensions = (".java",)
    cache_codec_version = JAVA_CACHE_CODEC_VERSION
    cache_runtime_version = "portable"

    def parse(self, source: SourceFile) -> ParsedFile:
        code_text, lexical_complete = _strip_java_comments_and_strings(
            source.content
        )
        metadata_text, metadata_complete = _strip_java_comments_and_strings(
            source.content,
            blank_strings=False,
        )
        package = _PACKAGE.search(code_text)
        facts = JavaFacts(
            package_name=package.group(1) if package else None,
            imports=_java_imports(metadata_text),
            identifiers=_java_identifiers(code_text),
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
        if not isinstance(facts, JavaFacts):
            raise TypeError("Java cache codec requires JavaFacts")
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
        data = _exact_mapping(payload, {"line_count", "complete", "facts"})
        line_count = _nonnegative_int(data["line_count"])
        complete = _boolean(data["complete"])
        fact_data = _exact_mapping(
            data["facts"],
            {"package_name", "imports", "identifiers", "code_text"},
        )
        package_name = fact_data["package_name"]
        if package_name is not None:
            package_name = _string(package_name)
        facts = JavaFacts(
            package_name=package_name,
            imports=_string_tuple(fact_data["imports"], _MAX_JAVA_IMPORTS),
            identifiers=_string_tuple(
                fact_data["identifiers"],
                _MAX_JAVA_IDENTIFIERS,
            ),
            code_text=_string(fact_data["code_text"]),
        )
        return ParsedFile(source, facts, facts, line_count, complete)


class JavaEmptyCatchRule:
    """Detect catch blocks whose blanked body is empty."""

    rule_id = "JAVA-COR-001"

    def evaluate(self, parsed: ParsedFile) -> Iterable[Finding]:
        if not isinstance(parsed.facts, JavaFacts):
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


class JavaRulePack(RegexRulePackBase):
    """Run the bounded built-in Java pilot rules."""

    rule_pack_id = JAVA_RULE_PACK_ID
    language_id = "java"
    ruleset_version = "1.0.0"
    plugin_api_version = PLUGIN_API_VERSION

    def __init__(self) -> None:
        self.rules = (JavaEmptyCatchRule(),)


class JavaArchitectureSignalProvider:
    """Extract Java DSA and design signals from blanked adapter facts."""

    provider_id = "java-architecture-signals"
    language_id = "java"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION

    def evaluate(self, parsed: ParsedFile) -> Iterable[SignalObservation]:
        facts = parsed.facts
        if not isinstance(facts, JavaFacts):
            raise TypeError("Java signal provider requires JavaFacts")
        signals = FileSignals(
            path=parsed.source.path,
            line_count=parsed.line_count,
            code_text=facts.code_text.lower(),
            identifiers={name.lower() for name in facts.identifiers},
            imports={imported.lower() for imported in facts.imports},
        )
        for category, definitions in (
            ("architecture.dsa", JAVA_DSA_PATTERNS),
            ("architecture.design", JAVA_DESIGN_PATTERNS),
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


class JavaPackageProvider:
    """Passive Maven/Gradle module discovery and conservative drift.

    Kotlin shares the JVM build manifests, so its package provider is a
    subclass overriding only the plugin identity and rule IDs.
    """

    provider_id = "java-package"
    language_id = "java"
    capability = "package"
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True
    drift_rule_id = "JAVA-PKG-001"
    invalid_rule_id = "JAVA-PKG-002"

    def analyze(self, project: ProjectContext) -> ProviderResult:
        manifest_dirs, truncated = discover_manifest_dirs(
            project.root,
            project.parsed_files,
            _MANIFEST_FILENAMES,
        )
        manifests = {
            directory: _load_java_manifest(project.root, directory)
            for directory in manifest_dirs
        }
        findings: list[Finding] = []
        errors = 0
        for directory in manifest_dirs:
            info = manifests[directory]
            if info["invalid"]:
                errors += 1
                report_path, identity = manifest_report_path(
                    directory,
                    info["filename"],
                    project.redact_paths,
                )
                findings.append(Finding(
                    rule_id=self.invalid_rule_id,
                    category="package-health",
                    severity="error",
                    confidence="high",
                    message=f"{identity} cannot be read as a valid build manifest.",
                    location=Location(report_path, 1, 1, identity_path=identity),
                    remediation=(
                        "Correct the manifest syntax and run analysis again."
                    ),
                ))

        undeclared = _undeclared_by_manifest(project.parsed_files, manifests)
        for directory in sorted(undeclared):
            info = manifests[directory]
            report_path, identity = manifest_report_path(
                directory,
                info["filename"],
                project.redact_paths,
            )
            for prefix, coordinates, example in undeclared[directory]:
                findings.append(Finding(
                    rule_id=self.drift_rule_id,
                    category="package-health",
                    severity="warning",
                    confidence="medium",
                    message=(
                        f"Package '{prefix}' is imported (for example in "
                        f"{example}) but no dependency matching "
                        f"'{coordinates}' is declared in {identity}."
                    ),
                    location=Location(report_path, 1, 1, identity_path=identity),
                    remediation=(
                        "Declare the dependency in the build manifest or "
                        "remove the import."
                    ),
                ))

        payload = {
            "manifests": [
                {
                    "path": manifest_report_path(
                        directory, manifests[directory]["filename"], False,
                    )[1],
                    "kind": manifests[directory]["kind"],
                    "artifact": manifests[directory]["artifact"],
                    "invalid": manifests[directory]["invalid"],
                    "declared_dependencies": sorted(
                        f"{group}:{artifact}"
                        for group, artifact in manifests[directory]["declared"]
                    ),
                    "undeclared_imports": [
                        prefix for prefix, _, _ in undeclared.get(directory, [])
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


def _load_java_manifest(root, directory: str) -> dict:
    info = {
        "filename": None,
        "kind": None,
        "artifact": None,
        "declared": set(),
        "invalid": False,
    }
    for filename in _MANIFEST_FILENAMES:
        if (root / directory / filename).is_file():
            info["filename"] = filename
            break
    try:
        text = read_bounded_text(
            root / directory / info["filename"],
            max_bytes=MAX_MANIFEST_BYTES,
            root=root,
        )
    except SafeReadError:
        info["invalid"] = True
        return info
    if info["filename"] == "pom.xml":
        info["kind"] = "maven"
        try:
            element = parse_xml_hardened(text)
        except ValueError:
            info["invalid"] = True
            return info
        for child in element:
            if local_name(child.tag) == "artifactId" and child.text:
                info["artifact"] = child.text.strip()
        for dependency in element.iter():
            if local_name(dependency.tag) != "dependency":
                continue
            group = artifact = None
            for field in dependency:
                name = local_name(field.tag)
                if name == "groupId" and field.text:
                    group = field.text.strip()
                elif name == "artifactId" and field.text:
                    artifact = field.text.strip()
            if group and artifact:
                info["declared"].add((group, artifact))
    else:
        info["kind"] = "gradle"
        info["declared"] = {
            (match.group(1), match.group(2))
            for match in _GRADLE_DEPENDENCY.finditer(text)
        }
    return info


def _declared_provides(
    declared: set[tuple[str, str]],
    group_prefix: str,
    artifact_prefix: str,
) -> bool:
    return any(
        group.startswith(group_prefix) and artifact.startswith(artifact_prefix)
        for group, artifact in declared
    )


def _undeclared_by_manifest(
    parsed_files,
    manifests: dict,
) -> dict[str, list[tuple[str, str, str]]]:
    first_seen: dict[str, dict[str, tuple[str, str]]] = {}
    manifest_dirs = list(manifests)
    for identity_path in sorted(parsed_files):
        parsed = parsed_files[identity_path]
        if not isinstance(parsed.facts, JavaFacts):
            continue
        directory = nearest_manifest_dir(identity_path, manifest_dirs)
        if directory is None:
            continue
        chain = manifest_chain(directory, manifest_dirs)
        if any(manifests[entry]["invalid"] for entry in chain):
            continue
        declared: set[tuple[str, str]] = set()
        for entry in chain:
            declared.update(manifests[entry]["declared"])
        for imported in parsed.facts.imports:
            for prefix, (group, artifact) in _DIRECT_LIBRARIES.items():
                if imported == prefix or imported.startswith(prefix + "."):
                    if not _declared_provides(declared, group, artifact):
                        first_seen.setdefault(directory, {}).setdefault(
                            prefix,
                            (f"{group}:{artifact}*", parsed.source.display_path),
                        )
                    break
    return {
        directory: sorted(
            (prefix, coordinates, example)
            for prefix, (coordinates, example) in entries.items()
        )
        for directory, entries in first_seen.items()
    }


def _exact_mapping(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Cached Java object has unexpected fields")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str) or len(value) > _MAX_CACHED_JAVA_STRING:
        raise ValueError("Cached Java string is invalid")
    return value


def _string_tuple(value: object, limit: int) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Cached Java string list is invalid")
    return tuple(_string(item) for item in value)


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Cached Java integer is invalid")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("Cached Java boolean is invalid")
    return value


def register_java_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register the built-in Java pilot plugins."""
    registry.register_language(JavaLanguageAdapter())
    registry.register_rule_pack(JavaRulePack())
    registry.register_signal_provider(JavaArchitectureSignalProvider())
    registry.register_project_provider(JavaPackageProvider())
    return registry
