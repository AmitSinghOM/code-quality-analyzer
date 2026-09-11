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
    confidence: str = "high",
) -> RuleMetadata:
    return RuleMetadata(
        rule_id=rule_id,
        name=name,
        title=title,
        description=description,
        category=category,
        default_severity=severity,
        confidence=confidence,
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
        "PY-DUP-001",
        "duplicate-function-implementation",
        "Duplicate function implementation",
        "A significant function body is structurally identical to another "
        "function in the project.",
        "duplication",
        "warning",
        "Extract the shared implementation into one function and call it "
        "from each location.",
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
    _rule(
        "GO-DUP-001",
        "duplicate-function-implementation",
        "Duplicate function implementation",
        "A significant function body is structurally identical to another "
        "function in the project. Requires the optional [deep] extra.",
        "duplication",
        "warning",
        "Extract the shared implementation into one function and call it "
        "from each location.",
        language="go",
    ),
    _rule(
        "GO-MAINT-001",
        "high-cyclomatic-complexity",
        "High cyclomatic complexity",
        "A function exceeds the supported cyclomatic complexity limit. "
        "Requires the optional [deep] extra.",
        "maintainability",
        "warning",
        "Extract independent decisions into focused helper functions.",
        language="go",
    ),
    _rule(
        "GO-MAINT-002",
        "high-cognitive-complexity",
        "High cognitive complexity",
        "A function exceeds the supported cognitive complexity limit "
        "(nesting-weighted branches). Requires the optional [deep] extra.",
        "maintainability",
        "warning",
        "Flatten nested branches with early returns or extract the inner "
        "levels into named helpers.",
        language="go",
    ),
    _rule(
        "JAVA-COR-001",
        "empty-catch-block",
        "Empty catch block",
        "An empty catch block discards a failure without recovery or context.",
        "correctness",
        "warning",
        "Handle the failure, log actionable context, or rethrow the exception.",
        language="java",
    ),
    _rule(
        "JAVA-PKG-001",
        "undeclared-direct-library",
        "Undeclared direct library",
        "A commonly direct third-party library is imported but no matching "
        "dependency is declared in the governing build manifest.",
        "package-health",
        "warning",
        "Declare the dependency in the build manifest or remove the import.",
        language="java",
        confidence="medium",
    ),
    _rule(
        "JAVA-PKG-002",
        "invalid-build-manifest",
        "Invalid build manifest",
        "A pom.xml or Gradle build file cannot be read as a valid manifest.",
        "package-health",
        "error",
        "Correct the manifest syntax and run analysis again.",
        language="java",
    ),
    _rule(
        "KT-COR-001",
        "empty-catch-block",
        "Empty catch block",
        "An empty catch block discards a failure without recovery or context.",
        "correctness",
        "warning",
        "Handle the failure, log actionable context, or rethrow the exception.",
        language="kotlin",
    ),
    _rule(
        "KT-PKG-001",
        "undeclared-direct-library",
        "Undeclared direct library",
        "A commonly direct third-party library is imported but no matching "
        "dependency is declared in the governing build manifest.",
        "package-health",
        "warning",
        "Declare the dependency in the build manifest or remove the import.",
        language="kotlin",
        confidence="medium",
    ),
    _rule(
        "KT-PKG-002",
        "invalid-build-manifest",
        "Invalid build manifest",
        "A pom.xml or Gradle build file cannot be read as a valid manifest.",
        "package-health",
        "error",
        "Correct the manifest syntax and run analysis again.",
        language="kotlin",
    ),
    _rule(
        "C-COR-001",
        "empty-catch-block",
        "Empty catch block",
        "An empty catch block discards a failure without recovery or context.",
        "correctness",
        "warning",
        "Handle the failure, log actionable context, or rethrow the exception.",
        language="c_cpp",
    ),
    _rule(
        "C-DUP-001",
        "duplicate-function-implementation",
        "Duplicate function implementation",
        "A significant function body is structurally identical to another "
        "function in the project. Requires the optional [deep] extra.",
        "duplication",
        "warning",
        "Extract the shared implementation into one function and call it "
        "from each location.",
        language="c_cpp",
    ),
    _rule(
        "C-MAINT-001",
        "high-cyclomatic-complexity",
        "High cyclomatic complexity",
        "A function exceeds the supported cyclomatic complexity limit. "
        "Requires the optional [deep] extra.",
        "maintainability",
        "warning",
        "Extract independent decisions into focused helper functions.",
        language="c_cpp",
    ),
    _rule(
        "C-MAINT-002",
        "high-cognitive-complexity",
        "High cognitive complexity",
        "A function exceeds the supported cognitive complexity limit "
        "(nesting-weighted branches). Requires the optional [deep] extra.",
        "maintainability",
        "warning",
        "Flatten nested branches with early returns or extract the inner "
        "levels into named helpers.",
        language="c_cpp",
    ),
    _rule(
        "C-PKG-001",
        "undeclared-third-party-header",
        "Undeclared third-party header",
        "A well-known third-party header is included but no matching "
        "find_package, FetchContent, target, or pkg-config token appears in "
        "the governing CMakeLists.txt chain.",
        "package-health",
        "warning",
        "Declare the library in CMake or remove the include.",
        language="c_cpp",
        confidence="medium",
    ),
    _rule(
        "CS-COR-001",
        "empty-catch-block",
        "Empty catch block",
        "An empty catch block discards a failure without recovery or context.",
        "correctness",
        "warning",
        "Handle the failure, log actionable context, or rethrow the exception.",
        language="csharp",
    ),
    _rule(
        "CS-PKG-001",
        "undeclared-package-namespace",
        "Undeclared package namespace",
        "A using directive names a third-party namespace with no matching "
        "PackageReference in the governing project file.",
        "package-health",
        "warning",
        "Add the PackageReference to the project file or remove the using.",
        language="csharp",
        confidence="medium",
    ),
    _rule(
        "CS-PKG-002",
        "invalid-project-file",
        "Invalid project file",
        "A .csproj file cannot be read as a valid MSBuild project.",
        "package-health",
        "error",
        "Correct the project file syntax and run analysis again.",
        language="csharp",
    ),
    _rule(
        "TS-COR-001",
        "empty-catch-block",
        "Empty catch block",
        "An empty catch block discards a failure without recovery or context.",
        "correctness",
        "warning",
        "Handle the failure, log actionable context, or rethrow the error.",
        language="typescript",
    ),
    _rule(
        "TS-PKG-001",
        "undeclared-imported-dependency",
        "Undeclared imported dependency",
        "A bare module import is not declared in package.json.",
        "package-health",
        "warning",
        "Declare the dependency in package.json or remove the import.",
        language="typescript",
    ),
    _rule(
        "TS-PKG-002",
        "invalid-package-json",
        "Invalid package.json",
        "The project package.json cannot be read as a valid JSON object.",
        "package-health",
        "error",
        "Correct the package.json syntax and run analysis again.",
        language="typescript",
    ),
    # ---- 2.41.0: dynamic SQL (every language) ------------------------------
    *(
        _rule(
            rule_id,
            "dynamic-sql-statement",
            "SQL statement assembled from runtime values",
            "A SQL statement is built with interpolation, concatenation or "
            "string formatting instead of driver parameters.",
            "correctness",
            "warning",
            "Pass runtime values as driver parameters (bind variables); "
            "allowlist identifiers such as table or column names.",
            language=language,
            confidence="medium",
        )
        for rule_id, language in (
            ("PY-COR-007", "python"),
            ("GO-COR-002", "go"),
            ("JAVA-COR-002", "java"),
            ("KT-COR-002", "kotlin"),
            ("CS-COR-002", "csharp"),
            ("TS-COR-002", "typescript"),
            ("C-COR-002", "c_cpp"),
        )
    ),
    # ---- 2.41.0: parity with the Python catalog -----------------------------
    *(
        _rule(
            rule_id,
            "broad-exception-handler",
            "Broad exception handler",
            "An exception handler catches a root exception type (or everything); "
            "handlers that rethrow are reported as notes.",
            "correctness",
            "warning",
            "Catch the narrow exception types the operation can recover from.",
            language=language,
        )
        for rule_id, language in (
            ("JAVA-COR-003", "java"),
            ("KT-COR-003", "kotlin"),
            ("CS-COR-003", "csharp"),
            ("C-COR-003", "c_cpp"),
        )
    ),
    _rule(
        "KT-COR-004",
        "blocking-call-in-suspend-function",
        "Blocking call in suspend function",
        "runBlocking or Thread.sleep is called inside a suspend function.",
        "correctness",
        "warning",
        "Await the asynchronous form of the call, or move the blocking work "
        "off the async path.",
        language="kotlin",
        confidence="medium",
    ),
    _rule(
        "KT-COR-005",
        "non-null-assertion-density",
        "Non-null assertion density",
        "A file uses more !! operators than the limit, disabling null safety "
        "at each site.",
        "correctness",
        "warning",
        "Narrow the type with a check or early return instead of asserting.",
        language="kotlin",
        confidence="medium",
    ),
    _rule(
        "CS-COR-004",
        "blocking-wait-in-async-method",
        "Blocking wait in async method",
        ".Result, .Wait() or GetAwaiter().GetResult() is used inside an async "
        "body.",
        "correctness",
        "warning",
        "Await the asynchronous form of the call, or move the blocking work "
        "off the async path.",
        language="csharp",
        confidence="medium",
    ),
    _rule(
        "TS-COR-003",
        "synchronous-io-in-async-function",
        "Synchronous I/O in async function",
        "A *Sync call (fs, child_process) is used inside an async function.",
        "correctness",
        "warning",
        "Await the asynchronous form of the call, or move the blocking work "
        "off the async path.",
        language="typescript",
        confidence="medium",
    ),
    _rule(
        "TS-COR-004",
        "unexplained-type-suppression",
        "Unexplained type-check suppression",
        "@ts-ignore, @ts-expect-error or @ts-nocheck is used without a reason.",
        "correctness",
        "warning",
        "Fix the type error, or document why it is suppressed with "
        "`// @ts-expect-error <reason>`.",
        language="typescript",
    ),
    _rule(
        "TS-COR-005",
        "non-null-assertion-density",
        "Non-null assertion density",
        "A file uses more postfix ! operators than the limit, disabling null "
        "safety at each site.",
        "correctness",
        "warning",
        "Narrow the type with a check or early return instead of asserting.",
        language="typescript",
        confidence="medium",
    ),
    _rule(
        "GO-COR-003",
        "unchecked-type-assertion",
        "Unchecked type assertion",
        "A single-value type assertion x.(T) panics when the dynamic type "
        "differs.",
        "correctness",
        "warning",
        "Use the two-value form `v, ok := x.(T)` and handle !ok.",
        language="go",
        confidence="medium",
    ),
    _rule(
        "GO-COR-004",
        "defer-in-loop",
        "defer inside a loop",
        "A defer statement inside a for body runs only when the function "
        "returns, accumulating resources across iterations.",
        "correctness",
        "warning",
        "Move the loop body into a function so each iteration's defer runs, "
        "or release the resource explicitly.",
        language="go",
    ),
    _rule(
        "C-COR-004",
        "using-namespace-in-header",
        "using namespace in header",
        "A file-scope `using namespace` directive in a header leaks into every "
        "translation unit that includes it.",
        "correctness",
        "warning",
        "Qualify names in the header, or move the directive into the "
        "implementation file or a function body.",
        language="c_cpp",
    ),
    # ---- Rust pilot (experimental; registered only with the [deep] extra) ----
    _rule(
        "RS-COR-001",
        "unwrap-density",
        "unwrap() density outside test code",
        "A file calls .unwrap() more than the limit outside #[cfg(test)] / "
        "#[test] code; each call is a latent panic.",
        "correctness",
        "warning",
        "Propagate with `?`, match on the Option/Result, or use "
        "`.expect(\"why this cannot fail\")` to document the invariant.",
        language="rust",
        confidence="medium",
    ),
    _rule(
        "RS-PKG-001",
        "undeclared-crate",
        "Undeclared crate",
        "A crate named by `use` or `extern crate` is not declared in any "
        "governing Cargo.toml dependency table.",
        "package-health",
        "warning",
        "Add the crate to [dependencies] (or [dev-dependencies]) or remove the use.",
        language="rust",
        confidence="medium",
    ),
    _rule(
        "RS-PKG-002",
        "invalid-cargo-manifest",
        "Invalid Cargo.toml",
        "A Cargo.toml cannot be read as TOML.",
        "package-health",
        "error",
        "Correct the Cargo.toml syntax and run analysis again.",
        language="rust",
    ),
    _rule(
        "RS-DUP-001",
        "duplicate-function-implementation",
        "Duplicate function implementation",
        "A significant function body is structurally identical to another "
        "function in the project. Requires the optional [deep] extra.",
        "duplication",
        "warning",
        "Extract the shared implementation into one function and call it "
        "from each location.",
        language="rust",
    ),
    _rule(
        "RS-MAINT-001",
        "high-cyclomatic-complexity",
        "High cyclomatic complexity",
        "A function exceeds the supported cyclomatic complexity limit. "
        "Requires the optional [deep] extra.",
        "maintainability",
        "warning",
        "Extract independent decisions into focused helper functions.",
        language="rust",
    ),
    _rule(
        "RS-MAINT-002",
        "high-cognitive-complexity",
        "High cognitive complexity",
        "A function exceeds the supported cognitive complexity limit "
        "(nesting-weighted branches). Requires the optional [deep] extra.",
        "maintainability",
        "warning",
        "Flatten nested branches with early returns or extract the inner "
        "levels into named helpers.",
        language="rust",
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
