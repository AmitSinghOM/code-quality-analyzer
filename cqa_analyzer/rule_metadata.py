"""Stable metadata for built-in actionable rules."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Immutable rule information shared by standard report formats."""

    rule_id: str
    name: str
    title: str
    description: str
    category: str
    default_severity: str
    confidence: str
    remediation: str
    language: str


def _rule(
    rule_id: str,
    name: str,
    title: str,
    description: str,
    category: str,
    severity: str,
    remediation: str,
    language: str = "python",
) -> RuleMetadata:
    return RuleMetadata(
        rule_id=rule_id,
        name=name,
        title=title,
        description=description,
        category=category,
        default_severity=severity,
        confidence="high",
        remediation=remediation,
        language=language,
    )


_RULES = (
    _rule(
        "PY-COR-001",
        "mutable-default-argument",
        "Mutable default argument",
        "A mutable function default can retain state between calls.",
        "correctness",
        "warning",
        "Use None as the default and create a new value inside the function.",
    ),
    _rule(
        "PY-COR-002",
        "broad-exception-handler",
        "Broad exception handler",
        "A broad exception handler can hide failures it cannot recover from.",
        "correctness",
        "warning",
        "Catch the narrow exception types the operation can recover from.",
    ),
    _rule(
        "PY-COR-003",
        "silently-swallowed-exception",
        "Silently swallowed exception",
        "An empty exception handler discards a failure without recovery or context.",
        "correctness",
        "warning",
        "Handle the failure, log actionable context, or re-raise the exception.",
    ),
    _rule(
        "PY-COR-004",
        "unreachable-statement",
        "Unreachable statement",
        "A statement after a direct control transfer cannot execute.",
        "correctness",
        "warning",
        "Remove the statement or move it before the control transfer.",
    ),
    _rule(
        "PY-COR-005",
        "blocking-call-in-async-code",
        "Blocking synchronous call in async code",
        "A known synchronous operation can block the async event loop.",
        "correctness",
        "warning",
        "Use an async API or move unavoidable synchronous work to a worker thread.",
    ),
    _rule(
        "PY-COR-006",
        "resource-without-guaranteed-cleanup",
        "Resource without guaranteed cleanup",
        "A locally acquired resource is not protected by structural cleanup.",
        "correctness",
        "warning",
        "Use a context manager or guarantee cleanup with try/finally.",
    ),
    _rule(
        "PY-MAINT-001",
        "high-cyclomatic-complexity",
        "High cyclomatic complexity",
        "A function exceeds the supported cyclomatic complexity limit.",
        "maintainability",
        "warning",
        "Extract independent decisions into focused helper functions.",
    ),
    _rule(
        "PY-MAINT-002",
        "high-cognitive-complexity",
        "High cognitive complexity",
        "A function exceeds the supported cognitive complexity limit.",
        "maintainability",
        "warning",
        "Flatten nested control flow and extract focused helper functions.",
    ),
    _rule(
        "PY-MAINT-003",
        "long-function",
        "Long function",
        "A function exceeds the supported physical source-line limit.",
        "maintainability",
        "warning",
        "Extract cohesive responsibilities into focused helper functions.",
    ),
    _rule(
        "PY-MAINT-004",
        "excessive-parameters",
        "Excessive parameters",
        "A function declares more effective parameters than the supported limit.",
        "maintainability",
        "warning",
        "Group related inputs in a cohesive value object or split the responsibility.",
    ),
    _rule(
        "PY-MAINT-005",
        "boolean-parameter-proliferation",
        "Boolean parameter proliferation",
        "Multiple boolean parameters create hard-to-name behavioral combinations.",
        "maintainability",
        "warning",
        "Replace mode flags with explicit operations or a typed configuration object.",
    ),
    _rule(
        "PY-PKG-001",
        "circular-local-imports",
        "Circular local imports",
        "Local modules form a circular import group with fragile initialization order.",
        "package-health",
        "warning",
        "Move shared contracts to a lower-level module or invert the dependency "
        "between these modules.",
    ),
    _rule(
        "PY-PKG-002",
        "missing-console-script-module",
        "Missing console-script module",
        "A declared console script refers to a module absent from the package.",
        "package-health",
        "error",
        "Correct the entry-point module or include it in the package.",
    ),
    _rule(
        "PY-PKG-003",
        "invalid-pyproject-metadata",
        "Invalid pyproject metadata",
        "The project pyproject.toml cannot be read as valid TOML.",
        "package-health",
        "error",
        "Correct the TOML syntax and run analysis again.",
    ),
    _rule(
        "PY-PKG-004",
        "missing-literal-public-export-binding",
        "Missing literal public export binding",
        "A literal __all__ export has no matching module-scope binding.",
        "package-health",
        "error",
        "Define or import the exported name at module scope, or remove it from __all__.",
    ),
    _rule(
        "PY-PKG-005",
        "duplicate-literal-public-export",
        "Duplicate literal public export",
        "A literal __all__ declaration exports the same name more than once.",
        "package-health",
        "warning",
        "Remove the repeated name from __all__.",
    ),
    _rule(
        "PY-PKG-006",
        "missing-literal-package-data-target",
        "Missing literal package-data target",
        "A literal package-data declaration refers to a missing regular file.",
        "package-health",
        "warning",
        "Add the file, correct the literal path, or disable the rule when a "
        "documented build step generates it.",
    ),
    _rule(
        "GO-COR-001",
        "ignored-standard-library-error",
        "Ignored standard-library error",
        "A known standard-library error result is discarded.",
        "correctness",
        "warning",
        "Bind the error result and handle or explicitly return it.",
        language="go",
    ),
)

_CATALOG = MappingProxyType({rule.rule_id: rule for rule in _RULES})


def rule_metadata(rule_id: str) -> RuleMetadata:
    """Return metadata for a built-in rule or fail closed."""
    try:
        return _CATALOG[rule_id]
    except KeyError as error:
        raise ValueError(f"Missing built-in rule metadata for {rule_id}") from error


def builtin_rule_ids() -> tuple[str, ...]:
    """Return every cataloged built-in rule ID in lexical order."""
    return tuple(sorted(_CATALOG))
