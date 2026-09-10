"""Optional tree-sitter depth for Go and C/C++ (``pip install cqa-analyzer[deep]``).

The default install is pure Python with no native dependencies, and the
regex pilots cannot prove function boundaries. This module adds the two
structural metrics Python already has — cross-file duplicate function
detection and cyclomatic complexity — for Go and C/C++, using tree-sitter
grammars when the ``deep`` extra is installed.

Design constraints:

- **Same thresholds as Python.** Duplication significance
  (``MIN_BODY_STATEMENTS`` / ``MIN_BODY_NODES``), the outermost-only
  nesting rule, the grouping and reporting logic
  (:class:`PythonDuplicationAnalyzer`), and the cyclomatic limit
  (``CYCLOMATIC_COMPLEXITY_LIMIT``) are shared, so a Go duplicate means the
  same thing as a Python duplicate.
- **Honest when absent.** Without the extra the providers still run and
  report ``available: false`` with the install hint; they never affect
  ``authoritative`` and never invent a metric.
- **No network, no execution.** tree-sitter parses bytes in-process; the
  grammars are compiled wheels with no runtime downloads.
- **Error-tolerant parsing is reported.** tree-sitter recovers from syntax
  errors; files whose tree contains ``ERROR`` nodes are counted in
  ``parse_errors`` and excluded from duplication (a partial tree can
  fabricate matches) but kept for complexity.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

from ..duplication import (
    MIN_BODY_NODES,
    MIN_BODY_STATEMENTS,
    PythonDuplicationAnalyzer,
    _Occurrence,
)
from ..findings import Finding, Location
from ..maintainability import CYCLOMATIC_COMPLEXITY_LIMIT
from ..protocols import (
    DEFAULT_CAPABILITY_VERSION,
    PLUGIN_API_VERSION,
    ParsedFile,
    ProjectContext,
    ProviderResult,
)
from ..registry import PluginRegistry

DEEP_EXTRA_HINT = "pip install 'cqa-analyzer[deep]'"
MAX_REPORTED_COMPLEX_FUNCTIONS = 200


@dataclass(frozen=True, slots=True)
class GrammarSpec:
    """How to find functions and decisions in one tree-sitter grammar."""

    module: str
    function_types: frozenset[str]
    body_field: str
    params_field: str | None
    decision_types: frozenset[str]
    name_types: frozenset[str]
    comment_types: frozenset[str]
    default_case_types: frozenset[str]


GO_SPEC = GrammarSpec(
    module="tree_sitter_go",
    function_types=frozenset({"function_declaration", "method_declaration"}),
    body_field="body",
    params_field="parameters",
    # gocyclo's rule: if, for, non-default case, communication case, && and ||.
    decision_types=frozenset(
        {
            "if_statement",
            "for_statement",
            "expression_case",
            "type_case",
            "communication_case",
        }
    ),
    name_types=frozenset({"identifier", "field_identifier"}),
    comment_types=frozenset({"comment"}),
    default_case_types=frozenset({"default_case"}),
)
C_SPEC = GrammarSpec(
    module="tree_sitter_c",
    function_types=frozenset({"function_definition"}),
    body_field="body",
    params_field=None,  # parameters live inside the declarator subtree
    decision_types=frozenset(
        {
            "if_statement",
            "for_statement",
            "while_statement",
            "do_statement",
            "case_statement",
            "conditional_expression",
        }
    ),
    name_types=frozenset({"identifier", "field_identifier"}),
    comment_types=frozenset({"comment"}),
    default_case_types=frozenset(),
)
CPP_SPEC = GrammarSpec(
    module="tree_sitter_cpp",
    function_types=frozenset({"function_definition"}),
    body_field="body",
    params_field=None,
    decision_types=frozenset(
        {
            "if_statement",
            "for_statement",
            "while_statement",
            "do_statement",
            "case_statement",
            "conditional_expression",
            "catch_clause",
            "for_range_loop",
        }
    ),
    name_types=frozenset(
        {
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "operator_name",
            "destructor_name",
        }
    ),
    comment_types=frozenset({"comment"}),
    default_case_types=frozenset(),
)
_BOOLEAN_OPERATORS = frozenset({"&&", "||"})
_CPP_EXTENSIONS = frozenset({".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"})
# A `.h` is C unless it visibly uses C++ syntax. Calibration on hiredis:
# the C++ grammar failed 111/127 functions in a macro-heavy C header that
# the C grammar parsed with 11 localized SIMD-intrinsic errors.
_CPP_HEADER_MARKERS = re.compile(
    r"^\s*(?:template\s*<|namespace\s+\w|class\s+\w+\s*[{:]|using\s+namespace\b)" r"|::\s*\w+\s*\(",
    re.MULTILINE,
)


def availability() -> dict[str, str | None]:
    """Return installed versions of the deep engine and grammars (None = missing)."""
    versions: dict[str, str | None] = {}
    for dist in ("tree-sitter", "tree-sitter-go", "tree-sitter-c", "tree-sitter-cpp"):
        try:
            versions[dist] = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            versions[dist] = None
    return versions


def deep_available(*grammars: str) -> bool:
    versions = availability()
    return versions["tree-sitter"] is not None and all(
        versions[grammar] is not None for grammar in grammars
    )


@lru_cache(maxsize=4)
def _parser(module_name: str):
    from tree_sitter import Language, Parser

    module = importlib.import_module(module_name)
    return Parser(Language(module.language()))


def _parse(spec: GrammarSpec, source: str):
    return _parser(spec.module).parse(source.encode("utf-8"))


def _walk(node) -> Iterable:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _named_count(node) -> int:
    return sum(1 for child in _walk(node) if child.is_named)


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node.text else ""


def _function_name(node, spec: GrammarSpec) -> str:
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named)
    declarator = node.child_by_field_name("declarator")
    # C/C++: descend the declarator chain to the innermost function name.
    while declarator is not None:
        if declarator.type in spec.name_types:
            return _text(declarator)
        inner = declarator.child_by_field_name("declarator")
        if inner is None:
            for child in declarator.children:
                if child.type in spec.name_types:
                    return _text(child)
            break
        declarator = inner
    return "<anonymous>"


def _structure(node, spec: GrammarSpec, skip=None) -> Iterable[str]:
    """Serialize a subtree: node types, leaf text; comments and ``skip`` excluded."""
    for current in _walk(node):
        if current is skip or current.type in spec.comment_types:
            continue
        if current.child_count == 0:
            yield f"{current.type}={_text(current)}"
        else:
            yield current.type


def _structure_key(function, spec: GrammarSpec, body) -> str:
    """Fingerprint = signature (minus the function's own name) + body."""
    parts: list[str] = [function.type]
    if spec.params_field:
        params = function.child_by_field_name(spec.params_field)
        if params is not None:
            parts.extend(_structure(params, spec))
    else:
        declarator = function.child_by_field_name("declarator")
        if declarator is not None:
            parts.extend(
                part
                for part in _structure(declarator, spec)
                if not any(part.startswith(f"{t}=") for t in spec.name_types)
            )
    parts.append("\x00")
    parts.extend(_structure(body, spec))
    return "\x1f".join(parts)


def _statement_count(body) -> int:
    """Direct statements in a body; Go wraps them in one ``statement_list``."""
    statements = [child for child in body.children if child.is_named]
    if len(statements) == 1 and statements[0].type == "statement_list":
        statements = [child for child in statements[0].children if child.is_named]
    return len(statements)


def _cyclomatic(body, spec: GrammarSpec) -> int:
    complexity = 1
    for node in _walk(body):
        if node.type in spec.decision_types:
            if (
                node.type == "case_statement"
                and node.children
                and node.children[0].type == "default"
            ):
                continue
            complexity += 1
        elif node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            if operator is not None and _text(operator) in _BOOLEAN_OPERATORS:
                complexity += 1
    return complexity


def _spec_for(parsed: ParsedFile, language_id: str) -> GrammarSpec:
    if language_id == "go":
        return GO_SPEC
    suffix = parsed.source.path.suffix
    if suffix in _CPP_EXTENSIONS:
        return CPP_SPEC
    if suffix == ".h":
        # Decide on blanked text: hiredis's ffc.h mentions `std::` only in
        # comments and must stay C.
        from ..languages.c_family import _strip_c_comments_and_strings

        code, _ = _strip_c_comments_and_strings(parsed.source.content)
        if _CPP_HEADER_MARKERS.search(code):
            return CPP_SPEC
    return C_SPEC


def _grammars_for(language_id: str) -> tuple[str, ...]:
    return ("tree-sitter-go",) if language_id == "go" else ("tree-sitter-c", "tree-sitter-cpp")


def _unavailable(language_id: str) -> ProviderResult:
    versions = availability()
    return ProviderResult(
        payload={
            "available": False,
            "install": DEEP_EXTRA_HINT,
            "engine": {
                name: versions[name] for name in ("tree-sitter", *_grammars_for(language_id))
            },
        },
        health={"complete": True, "errors": 0, "available": False},
        findings=(),
    )


class _DeepProviderBase:
    language_id: str
    capability: str
    capability_version = DEFAULT_CAPABILITY_VERSION
    plugin_api_version = PLUGIN_API_VERSION
    enabled_by_default = True

    def _trees(self, project: ProjectContext):
        parse_errors = 0
        for identity_path, parsed in sorted(project.parsed_files.items()):
            spec = _spec_for(parsed, self.language_id)
            tree = _parse(spec, parsed.source.content)
            errored = tree.root_node.has_error
            parse_errors += int(errored)
            yield identity_path, parsed, spec, tree, errored
        self._parse_errors = parse_errors

    def _engine(self) -> dict:
        versions = availability()
        return {name: versions[name] for name in ("tree-sitter", *_grammars_for(self.language_id))}


class DeepDuplicationProvider(_DeepProviderBase):
    """Cross-file duplicate function detection via tree-sitter."""

    capability = "duplication"

    def __init__(self, language_id: str, rule_id: str) -> None:
        self.language_id = language_id
        self.rule_id = rule_id
        self.provider_id = f"{language_id}-deep-duplication"
        self._parse_errors = 0

    def analyze(self, project: ProjectContext) -> ProviderResult:
        if not deep_available(*_grammars_for(self.language_id)):
            return _unavailable(self.language_id)
        analyzer = PythonDuplicationAnalyzer(rule_id=self.rule_id)
        excluded_functions = 0
        for identity_path, parsed, spec, tree, _errored in self._trees(project):
            for function in _walk(tree.root_node):
                if function.type not in spec.function_types:
                    continue
                body = function.child_by_field_name(spec.body_field)
                if body is None:
                    continue
                if function.has_error:
                    # A partial tree can fabricate or hide a match; errors are
                    # localized (extern "C" guards, va_arg(ap, type)), so only
                    # the affected function is excluded, not the file.
                    excluded_functions += 1
                    continue
                if (
                    _statement_count(body) < MIN_BODY_STATEMENTS
                    or _named_count(body) < MIN_BODY_NODES
                ):
                    continue
                occurrence = _Occurrence(
                    identity_path=identity_path,
                    display_path=parsed.source.display_path,
                    name=_function_name(function, spec),
                    line=function.start_point[0] + 1,
                    column=function.start_point[1] + 1,
                    end_line=function.end_point[0] + 1,
                    end_column=function.end_point[1] + 1,
                    node_id=function.id,
                    ancestor_ids=(),  # only top-level functions participate
                )
                analyzer.add_occurrence(_structure_key(function, spec, body), occurrence, tree)
        payload, findings = analyzer.analyze()
        payload.update(
            {
                "available": True,
                "engine": self._engine(),
                "files_with_parse_errors": self._parse_errors,
                "functions_excluded_for_parse_errors": excluded_functions,
            }
        )
        health = analyzer.analysis_health()
        health.update(
            {
                "available": True,
                "files_with_parse_errors": self._parse_errors,
                "functions_excluded_for_parse_errors": excluded_functions,
            }
        )
        return ProviderResult(payload=payload, health=health, findings=findings)


class DeepComplexityProvider(_DeepProviderBase):
    """Cyclomatic complexity per function via tree-sitter."""

    capability = "complexity"

    def __init__(self, language_id: str, rule_id: str) -> None:
        self.language_id = language_id
        self.rule_id = rule_id
        self.provider_id = f"{language_id}-deep-complexity"
        self._parse_errors = 0

    def analyze(self, project: ProjectContext) -> ProviderResult:
        if not deep_available(*_grammars_for(self.language_id)):
            return _unavailable(self.language_id)
        findings: list[Finding] = []
        complex_functions: list[dict] = []
        functions = 0
        total = 0
        for _, parsed, spec, tree, _errored in self._trees(project):
            for function in _walk(tree.root_node):
                if function.type not in spec.function_types:
                    continue
                body = function.child_by_field_name(spec.body_field)
                if body is None:
                    continue
                functions += 1
                complexity = _cyclomatic(body, spec)
                total += complexity
                if complexity <= CYCLOMATIC_COMPLEXITY_LIMIT:
                    continue
                name = _function_name(function, spec)
                line = function.start_point[0] + 1
                column = function.start_point[1] + 1
                complex_functions.append(
                    {
                        "path": parsed.source.display_path,
                        "line": line,
                        "function": name,
                        "cyclomatic": complexity,
                    }
                )
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        category="maintainability",
                        severity="warning",
                        confidence="high",
                        message=(
                            f"Function '{name}' has cyclomatic complexity "
                            f"{complexity} (limit {CYCLOMATIC_COMPLEXITY_LIMIT})."
                        ),
                        location=Location(
                            path=parsed.source.display_path,
                            line=line,
                            column=column,
                            end_line=function.end_point[0] + 1,
                            end_column=function.end_point[1] + 1,
                            identity_path=parsed.source.identity_path,
                        ),
                        remediation=(
                            "Split the function into smaller units, each with a "
                            "single decision path."
                        ),
                    )
                )
        complex_functions.sort(key=lambda item: (-item["cyclomatic"], item["path"], item["line"]))
        payload = {
            "available": True,
            "engine": self._engine(),
            "functions_analyzed": functions,
            "average_cyclomatic": round(total / functions, 2) if functions else 0.0,
            "over_limit": len(complex_functions),
            "limit": CYCLOMATIC_COMPLEXITY_LIMIT,
            "functions": complex_functions[:MAX_REPORTED_COMPLEX_FUNCTIONS],
            "functions_truncated": len(complex_functions) > MAX_REPORTED_COMPLEX_FUNCTIONS,
            "files_with_parse_errors": self._parse_errors,
        }
        health = {
            "complete": True,
            "errors": 0,
            "available": True,
            "files_with_parse_errors": self._parse_errors,
        }
        return ProviderResult(payload=payload, health=health, findings=tuple(findings))


def register_deep_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register Go and C/C++ deep providers (they self-report availability)."""
    registry.register_project_provider(DeepDuplicationProvider("go", "GO-DUP-001"))
    registry.register_project_provider(DeepComplexityProvider("go", "GO-MAINT-001"))
    registry.register_project_provider(DeepDuplicationProvider("c_cpp", "C-DUP-001"))
    registry.register_project_provider(DeepComplexityProvider("c_cpp", "C-MAINT-001"))
    return registry
