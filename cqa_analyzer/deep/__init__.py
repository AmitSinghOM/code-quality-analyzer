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

import hashlib
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
from ..maintainability import COGNITIVE_COMPLEXITY_LIMIT, CYCLOMATIC_COMPLEXITY_LIMIT
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
    # Cognitive complexity (mirrors maintainability._ComplexityCounter):
    # branch_types add 1 + nesting and nest the fields in nested_fields;
    # switch_types add 1 + nesting once and nest their case children;
    # nested_function_types are not entered (Python skips nested defs).
    branch_types: frozenset[str] = frozenset()
    nested_fields: frozenset[str] = frozenset({"consequence", "alternative", "body"})
    switch_types: frozenset[str] = frozenset()
    case_types: frozenset[str] = frozenset()
    nested_function_types: frozenset[str] = frozenset()


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
    branch_types=frozenset({"if_statement", "for_statement"}),
    switch_types=frozenset(
        {"expression_switch_statement", "type_switch_statement", "select_statement"}
    ),
    case_types=frozenset({"expression_case", "type_case", "communication_case", "default_case"}),
    nested_function_types=frozenset({"func_literal"}),
)
_C_BRANCHES = frozenset(
    {"if_statement", "for_statement", "while_statement", "do_statement", "conditional_expression"}
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
    branch_types=_C_BRANCHES,
    switch_types=frozenset({"switch_statement"}),
    case_types=frozenset({"case_statement"}),
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
    branch_types=_C_BRANCHES | {"for_range_loop", "catch_clause"},
    switch_types=frozenset({"switch_statement"}),
    case_types=frozenset({"case_statement"}),
    nested_function_types=frozenset({"lambda_expression"}),
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


class DeepEngineError(RuntimeError):
    """The deep engine is installed but cannot load (ABI mismatch, broken wheel)."""


@lru_cache(maxsize=4)
def _parser(module_name: str):
    """Build a parser; a grammar/runtime ABI mismatch is reported, not raised.

    ``Language()`` raises ``ValueError`` when the grammar's ABI is outside
    the runtime's accepted range — a real possibility with independent
    version ranges. That must degrade to ``available: false``, never crash
    the scan.
    """
    try:
        from tree_sitter import Language, Parser

        module = importlib.import_module(module_name)
        return Parser(Language(module.language()))
    except Exception as error:  # noqa: BLE001 - any load failure is "unavailable"
        raise DeepEngineError(f"{module_name}: {type(error).__name__}: {error}") from error


def _parse(spec: GrammarSpec, source: str):
    return _parser(spec.module).parse(source.encode("utf-8"))


# One parse per file per scan, shared by the duplication and complexity
# providers. The scanner hands both providers the same parsed_files mapping
# object for a run, so its identity scopes the cache; a new run (or another
# language) replaces it, bounding memory to one language's trees.
_TREE_CACHE: dict = {"owner": None, "owner_ref": None, "trees": {}}


def _tree_for(parsed: ParsedFile, language_id: str, owner: object):
    if _TREE_CACHE["owner_ref"] is not owner:
        _TREE_CACHE.update(owner=id(owner), owner_ref=owner, trees={})
    entry = _TREE_CACHE["trees"].get(parsed.source.identity_path)
    if entry is None or entry[0] is not parsed:
        spec = _spec_for(parsed, language_id)
        entry = (parsed, spec, _parse(spec, parsed.source.content))
        _TREE_CACHE["trees"][parsed.source.identity_path] = entry
    return entry[1], entry[2]


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


_DECLARATOR_WRAPPERS = frozenset(
    {
        "function_declarator",
        "pointer_declarator",
        "parenthesized_declarator",
        "reference_declarator",
        "array_declarator",
        "attributed_declarator",
    }
)


def _function_name(node, spec: GrammarSpec) -> str:
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named)
    # C/C++: descend the declarator chain to the innermost name, through
    # pointer/parenthesized wrappers (`int (*f(void))(int)`).
    declarator = node.child_by_field_name("declarator")
    seen = 0
    while declarator is not None and seen < 32:
        seen += 1
        if declarator.type in spec.name_types:
            return _text(declarator)
        inner = declarator.child_by_field_name("declarator")
        if inner is None:
            inner = next(
                (
                    c
                    for c in declarator.children
                    if c.type in _DECLARATOR_WRAPPERS or c.type in spec.name_types
                ),
                None,
            )
        declarator = inner
    return "<anonymous>"


# Go's official generated-code marker plus the filename conventions that
# carry it in practice. Generated code is excluded from deep metrics: it
# is not maintained by hand, and identical generated methods on different
# types are not "duplicates" anyone can fix.
_GENERATED_HEADER = re.compile(r"^// Code generated .* DO NOT EDIT\.$", re.MULTILINE)
_GENERATED_NAMES = re.compile(
    r"(?:\.pb(?:\.gw)?\.go|_generated\.go|\.gen\.go|^zz_generated.*\.go|^mock_.*\.go|"
    r"_mock\.go|_string\.go|_easyjson\.go|_ffjson\.go|\.g\.cs|\.designer\.cs)$",
    re.IGNORECASE,
)


def _is_generated(parsed: ParsedFile) -> bool:
    name = parsed.source.path.name
    if _GENERATED_NAMES.search(name):
        return True
    head = parsed.source.content[:2048]
    return bool(_GENERATED_HEADER.search(head))


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
    # Digest, not the serialized body: keys for a large codebase otherwise
    # hold several times the source size in memory (staff review C6).
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "surrogatepass")).hexdigest()


def _statement_count(body) -> int:
    """Direct statements in a body; Go wraps them in one ``statement_list``."""
    statements = [child for child in body.children if child.is_named]
    if len(statements) == 1 and statements[0].type == "statement_list":
        statements = [child for child in statements[0].children if child.is_named]
    return len(statements)


def _cognitive(body, spec: GrammarSpec) -> int:
    """Cognitive complexity with exactly the Python counter's rules.

    - a branch (if/for/while/do/?:/catch) adds ``1 + nesting``; its
      condition is visited at the current nesting, its bodies one deeper —
      so ``else if`` costs one more than the ``if`` it follows;
    - a switch/select adds ``1 + nesting`` once; cases are one deeper;
    - a boolean-operator sequence adds 1 regardless of nesting, counting a
      chain of the same operator (``a && b && c``) once, as Python's
      single ``BoolOp`` node does;
    - nested function literals and lambdas are not entered.
    """
    total = 0

    def visit(node, nesting: int, bool_parent: str | None = None) -> None:
        nonlocal total
        node_type = node.type
        if node_type in spec.nested_function_types or node_type in spec.comment_types:
            return
        if node_type in spec.branch_types:
            total += 1 + nesting
            for index, child in enumerate(node.children):
                deeper = node.field_name_for_child(index) in spec.nested_fields
                visit(child, nesting + 1 if deeper else nesting)
            return
        if node_type in spec.switch_types:
            total += 1 + nesting
            for child in node.children:
                deeper = child.type in spec.case_types or child.type in {
                    "compound_statement",
                    "block",
                }
                visit(child, nesting + 1 if deeper else nesting)
            return
        if node_type == "binary_expression":
            operator = node.child_by_field_name("operator")
            operator_text = _text(operator) if operator is not None else ""
            if operator_text in _BOOLEAN_OPERATORS:
                if bool_parent != operator_text:
                    total += 1
                for child in node.children:
                    visit(child, nesting, operator_text)
                return
        for child in node.children:
            visit(child, nesting)

    for child in body.children:
        visit(child, 0)
    return total


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
        skipped_generated = 0
        for identity_path, parsed in sorted(project.parsed_files.items()):
            if _is_generated(parsed):
                skipped_generated += 1
                continue
            spec, tree = _tree_for(parsed, self.language_id, project.parsed_files)
            errored = tree.root_node.has_error
            parse_errors += int(errored)
            yield identity_path, parsed, spec, tree, errored
        self._parse_errors = parse_errors
        self._skipped_generated = skipped_generated

    def _engine_failed(self, error: DeepEngineError) -> ProviderResult:
        result = _unavailable(self.language_id)
        result.payload["reason"] = str(error)
        result.health["reason"] = "engine_load_failed"
        return result

    def analyze(self, project: ProjectContext) -> ProviderResult:
        if not deep_available(*_grammars_for(self.language_id)):
            return _unavailable(self.language_id)
        try:
            return self._analyze(project)
        except DeepEngineError as error:
            return self._engine_failed(error)

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
        self._skipped_generated = 0

    def _analyze(self, project: ProjectContext) -> ProviderResult:
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
                "files_skipped_generated": self._skipped_generated,
                "functions_excluded_for_parse_errors": excluded_functions,
            }
        )
        health = analyzer.analysis_health()
        health.update(
            {
                "available": True,
                "files_with_parse_errors": self._parse_errors,
                "files_skipped_generated": self._skipped_generated,
                "functions_excluded_for_parse_errors": excluded_functions,
            }
        )
        return ProviderResult(payload=payload, health=health, findings=findings)


class DeepComplexityProvider(_DeepProviderBase):
    """Cyclomatic and cognitive complexity per function via tree-sitter.

    Mirrors ``PY-MAINT-001``/``PY-MAINT-002``: the same two metrics, the
    same limits, computed by the same rules on tree-sitter nodes.
    """

    capability = "complexity"

    def __init__(self, language_id: str, rule_id: str, cognitive_rule_id: str) -> None:
        self.language_id = language_id
        self.rule_id = rule_id
        self.cognitive_rule_id = cognitive_rule_id
        self.provider_id = f"{language_id}-deep-complexity"
        self._parse_errors = 0
        self._skipped_generated = 0

    def _analyze(self, project: ProjectContext) -> ProviderResult:
        findings: list[Finding] = []
        reported: list[dict] = []
        functions = 0
        total_cyclomatic = 0
        total_cognitive = 0
        over_cyclomatic = 0
        over_cognitive = 0
        for _, parsed, spec, tree, _errored in self._trees(project):
            for function in _walk(tree.root_node):
                if function.type not in spec.function_types:
                    continue
                body = function.child_by_field_name(spec.body_field)
                if body is None:
                    continue
                functions += 1
                cyclomatic = _cyclomatic(body, spec)
                cognitive = _cognitive(body, spec)
                total_cyclomatic += cyclomatic
                total_cognitive += cognitive
                cyclomatic_over = cyclomatic > CYCLOMATIC_COMPLEXITY_LIMIT
                cognitive_over = cognitive > COGNITIVE_COMPLEXITY_LIMIT
                if not (cyclomatic_over or cognitive_over):
                    continue
                name = _function_name(function, spec)
                location = Location(
                    path=parsed.source.display_path,
                    line=function.start_point[0] + 1,
                    column=function.start_point[1] + 1,
                    end_line=function.end_point[0] + 1,
                    end_column=function.end_point[1] + 1,
                    identity_path=parsed.source.identity_path,
                )
                reported.append(
                    {
                        "path": parsed.source.display_path,
                        "line": location.line,
                        "function": name,
                        "cyclomatic": cyclomatic,
                        "cognitive": cognitive,
                    }
                )
                if cyclomatic_over:
                    over_cyclomatic += 1
                    findings.append(
                        _complexity_finding(
                            self.rule_id,
                            name,
                            "cyclomatic",
                            cyclomatic,
                            CYCLOMATIC_COMPLEXITY_LIMIT,
                            location,
                            "Split the function into smaller units, each with a "
                            "single decision path.",
                        )
                    )
                if cognitive_over:
                    over_cognitive += 1
                    findings.append(
                        _complexity_finding(
                            self.cognitive_rule_id,
                            name,
                            "cognitive",
                            cognitive,
                            COGNITIVE_COMPLEXITY_LIMIT,
                            location,
                            "Flatten nested branches with early returns or extract "
                            "the inner levels into named helpers.",
                        )
                    )
        reported.sort(
            key=lambda item: (
                -max(item["cyclomatic"], item["cognitive"]),
                item["path"],
                item["line"],
            )
        )
        payload = {
            "available": True,
            "engine": self._engine(),
            "functions_analyzed": functions,
            "average_cyclomatic": round(total_cyclomatic / functions, 2) if functions else 0.0,
            "average_cognitive": round(total_cognitive / functions, 2) if functions else 0.0,
            "over_limit": over_cyclomatic,
            "over_cognitive_limit": over_cognitive,
            "limit": CYCLOMATIC_COMPLEXITY_LIMIT,
            "cognitive_limit": COGNITIVE_COMPLEXITY_LIMIT,
            "functions": reported[:MAX_REPORTED_COMPLEX_FUNCTIONS],
            "functions_truncated": len(reported) > MAX_REPORTED_COMPLEX_FUNCTIONS,
            "files_with_parse_errors": self._parse_errors,
            "files_skipped_generated": self._skipped_generated,
        }
        health = {
            "complete": True,
            "errors": 0,
            "available": True,
            "files_with_parse_errors": self._parse_errors,
            "files_skipped_generated": self._skipped_generated,
        }
        return ProviderResult(payload=payload, health=health, findings=tuple(findings))


def _complexity_finding(
    rule_id: str,
    name: str,
    metric: str,
    value: int,
    limit: int,
    location: Location,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="maintainability",
        severity="warning",
        confidence="high",
        message=f"Function '{name}' has {metric} complexity {value} (limit {limit}).",
        location=location,
        remediation=remediation,
    )


def register_deep_plugins(registry: PluginRegistry) -> PluginRegistry:
    """Register Go and C/C++ deep providers (they self-report availability)."""
    registry.register_project_provider(DeepDuplicationProvider("go", "GO-DUP-001"))
    registry.register_project_provider(DeepComplexityProvider("go", "GO-MAINT-001", "GO-MAINT-002"))
    registry.register_project_provider(DeepDuplicationProvider("c_cpp", "C-DUP-001"))
    registry.register_project_provider(
        DeepComplexityProvider("c_cpp", "C-MAINT-001", "C-MAINT-002")
    )
    return registry
