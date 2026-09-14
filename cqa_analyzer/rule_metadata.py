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
    not_when: tuple[str, ...] = ()
    """Conditions under which the rule deliberately stays silent, or a finding
    should not be reported onward. Describes what the detector actually does
    (path downgrades, literal blanking, thresholds), so a consumer can judge a
    finding's precision without reading the detector source."""


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
        "Extract the shared implementation into one function and call it " "from each location.",
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
        "Extract the shared implementation into one function and call it " "from each location.",
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
        "Extract the shared implementation into one function and call it " "from each location.",
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
        "Await the asynchronous form of the call, or move the blocking work " "off the async path.",
        language="kotlin",
        confidence="medium",
    ),
    _rule(
        "KT-COR-005",
        "non-null-assertion-density",
        "Non-null assertion density",
        "A file uses more !! operators than the limit, disabling null safety " "at each site.",
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
        ".Result, .Wait() or GetAwaiter().GetResult() is used inside an async " "body.",
        "correctness",
        "warning",
        "Await the asynchronous form of the call, or move the blocking work " "off the async path.",
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
        "Await the asynchronous form of the call, or move the blocking work " "off the async path.",
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
        "A single-value type assertion x.(T) panics when the dynamic type " "differs.",
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
        '`.expect("why this cannot fail")` to document the invariant.',
        language="rust",
        confidence="medium",
    ),
    _rule(
        "RS-COR-002",
        "dynamic-sql-statement",
        "SQL statement assembled from runtime values",
        "A SQL statement is built with format!/write! or + concatenation "
        "instead of driver parameters.",
        "correctness",
        "warning",
        "Pass runtime values as driver parameters (bind variables); "
        "allowlist identifiers such as table or column names.",
        language="rust",
        confidence="medium",
    ),
    _rule(
        "RS-COR-003",
        "blocking-call-in-async-function",
        "Blocking call in async function",
        "thread::sleep, std::fs, block_on or a blocking connect is called "
        "inside an async fn (closures excluded).",
        "correctness",
        "warning",
        "Await the asynchronous form (tokio::fs, tokio::time::sleep) or move "
        "the work to spawn_blocking.",
        language="rust",
        confidence="medium",
    ),
    _rule(
        "RS-COR-004",
        "unexplained-crate-wide-lint-allow",
        "Crate-wide lint allow without reason",
        "#![allow(dead_code | unused | warnings | clippy::all)] at crate level "
        "silences the compiler with no recorded reason.",
        "correctness",
        "warning",
        "Remove the dead or unused code, scope the allow to the item that "
        'needs it, or record why: `#![allow(dead_code, reason = "…")]`.',
        language="rust",
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
        "Extract the shared implementation into one function and call it " "from each location.",
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

# --- negative conditions ----------------------------------------------------------
#
# Each clause states when the detector deliberately stays silent, or when a
# reported finding should not be forwarded. Clauses describe implemented
# behaviour (see the referenced modules), not aspirations: keep them honest when
# a detector changes.

_TEST_PATH_DOWNGRADE = (
    "The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, "
    "*.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, "
    "not dropped (languages/_parity.py: downgrade_in_tests)."
)
_SQL_NOT_WHEN = (
    "The literal is not the head of a SQL statement: only literals whose leading "
    "text reads as a SQL statement head are considered (sql_text).",
    "The literal is complete and constant: no string interpolation, no `+` "
    "concatenation with a non-literal operand on either side, and not an argument "
    "of a formatting call (languages/_sql.py).",
    "The dynamic part is a bound-parameter placeholder rather than a runtime value; "
    "placeholders are constant text and are not assembly.",
    "The literal sits inside a comment: comments are blanked before literals are "
    "located, so they are never evidence.",
)
_EMPTY_CATCH_NOT_WHEN = (
    "The handler body contains at least one statement; only a body with no "
    "statements after blanking comments and literals is empty.",
    _TEST_PATH_DOWNGRADE,
)
_BROAD_HANDLER_NOT_WHEN = (
    "The handler names a specific exception type rather than the language's root "
    "exception or a bare catch-all.",
    "The broad handler re-raises or logs: this rule flags the breadth of the catch, "
    "not silent discard (see the language's empty-catch rule for that).",
    _TEST_PATH_DOWNGRADE,
)
_DUP_NOT_WHEN = (
    "The optional [deep] extra is not installed: the rule is reported as an "
    "unavailable analyzer in scan health rather than producing findings.",
    "The function body is below the minimum significant size, or the two bodies "
    "differ structurally once identifiers are normalised.",
)
_COMPLEXITY_NOT_WHEN = (
    "The optional [deep] extra is not installed: the rule is reported as an "
    "unavailable analyzer in scan health rather than producing findings.",
    "The function is at or below the configured complexity limit.",
)
_UNDECLARED_DEP_NOT_WHEN = (
    "The import resolves to the standard library, the project's own modules, or "
    "a name declared in the nearest governing manifest or any manifest up the "
    "ancestor chain (nested-manifest discovery: manifests.py).",
    "The chain contains a workspace-style manifest or an unreadable manifest: drift "
    "is skipped for that chain and an invalid-manifest finding is raised instead.",
    "Reported at medium confidence: transitive dependencies provided through starter "
    "bundles or split vendor namespaces can appear undeclared; confirm before acting.",
)
_INVALID_MANIFEST_NOT_WHEN = (
    "The manifest parses: this rule only fires when the file cannot be read as its "
    "declared format, never on semantic content.",
)
_BLOCKING_ASYNC_NOT_WHEN = (
    "The blocking call is not inside a function declared async (or suspend): "
    "synchronous code calling synchronous APIs is not flagged.",
    "The call is one of the language's recognised blocking APIs; the rule uses a "
    "fixed allowlist of call names, not type inference.",
    _TEST_PATH_DOWNGRADE,
)
_DENSITY_NOT_WHEN = (
    "The per-file count is below the density threshold; a single occurrence is "
    "never reported (languages/_parity.py: non_null_density_findings).",
    "Occurrences appear inside string literals or comments: both are blanked before " "counting.",
    _TEST_PATH_DOWNGRADE,
)

_NOT_WHEN: dict[str, tuple[str, ...]] = {
    # Python
    "PY-COR-001": (
        "The default is an immutable literal (None, numbers, strings, tuples) or a "
        "call expression; only list, dict and set displays are treated as mutable "
        "(python_rules._MUTABLE_LITERALS).",
        "The parameter is intentionally a shared, documented cache or sentinel: the "
        "rule cannot see intent, so confirm before rewriting.",
    ),
    "PY-COR-002": (
        "The handler catches a specific exception class rather than Exception or "
        "BaseException, or is a bare `except:` handled by PY-COR-003.",
        "The handler re-raises or logs: breadth is the finding, not silence.",
    ),
    "PY-COR-003": (
        "The handler body contains any statement other than `pass` or `...`; a "
        "logged or re-raised failure is not swallowed.",
        "The suppression is a deliberate `contextlib.suppress` or carries a "
        "recognised inline suppression (python_suppressions.py).",
    ),
    "PY-COR-004": (
        "The statement after return/raise/break/continue is in a different block "
        "(else/finally/except) or the transfer is conditional.",
    ),
    "PY-COR-005": (
        "The call is not inside an `async def` body.",
        "The call is not in the fixed blocking-call allowlist "
        "(python_resources._BLOCKING_CALLS); `await`ed coroutines are never flagged.",
        "The call is dispatched through run_in_executor / to_thread.",
    ),
    "PY-COR-006": (
        "The resource is opened inside a `with` statement or returned to a caller "
        "that manages its lifetime.",
        "The call is not in the fixed resource-call allowlist "
        "(python_resources._RESOURCE_CALLS).",
        "Cleanup is guaranteed by an enclosing try/finally.",
    ),
    "PY-COR-007": _SQL_NOT_WHEN,
    "PY-DUP-001": _DUP_NOT_WHEN,
    "PY-MAINT-001": _COMPLEXITY_NOT_WHEN,
    "PY-MAINT-002": _COMPLEXITY_NOT_WHEN,
    "PY-MAINT-003": ("The function is at or below the configured length limit.",),
    "PY-MAINT-004": (
        "The parameter count is at or below the configured limit; `self`/`cls` " "are not counted.",
    ),
    "PY-MAINT-005": (
        "Fewer than the threshold number of parameters default to a boolean literal.",
    ),
    "PY-PKG-001": (
        "The import cycle is between a package and a third-party module, or the "
        "import is local (inside a function) and therefore deferred.",
    ),
    "PY-PKG-002": (
        "The console-script entry in pyproject resolves to an importable module and "
        "attribute in the project tree.",
    ),
    "PY-PKG-003": _INVALID_MANIFEST_NOT_WHEN,
    "PY-PKG-004": (
        "Every name in the literal `__all__` is bound in the module; dynamic "
        "`__all__` values are not evaluated and are not flagged.",
    ),
    "PY-PKG-005": ("Each name appears once in the literal `__all__`.",),
    "PY-PKG-006": (
        "Each literal package-data glob matches at least one path in the project; "
        "non-literal (computed) entries are not evaluated.",
    ),
    # Go
    "GO-COR-001": (
        "The error value is assigned, returned, or checked; only a standard-library "
        "call whose error result is discarded with `_` or dropped is flagged.",
        _TEST_PATH_DOWNGRADE,
    ),
    "GO-COR-002": _SQL_NOT_WHEN,
    "GO-COR-003": (
        "The assertion uses the two-value form `v, ok := x.(T)` or is inside a type " "switch.",
        _TEST_PATH_DOWNGRADE,
    ),
    "GO-COR-004": (
        "The `defer` is inside a function literal within the loop body (the literal "
        "is stripped before matching: languages/go.py _FUNC_LITERAL), so the defer "
        "runs per iteration.",
        _TEST_PATH_DOWNGRADE,
    ),
    "GO-DUP-001": _DUP_NOT_WHEN,
    "GO-MAINT-001": _COMPLEXITY_NOT_WHEN,
    "GO-MAINT-002": _COMPLEXITY_NOT_WHEN,
    # TypeScript / JavaScript
    "TS-COR-001": _EMPTY_CATCH_NOT_WHEN,
    "TS-COR-002": _SQL_NOT_WHEN,
    "TS-COR-003": (
        "The call is not a recognised `*Sync` file-system API inside an async "
        "function or a function returning a Promise.",
        _TEST_PATH_DOWNGRADE,
    ),
    "TS-COR-004": (
        "The `@ts-ignore` / `@ts-expect-error` / `eslint-disable` directive carries "
        "an explanation on the same line.",
    ),
    "TS-COR-005": _DENSITY_NOT_WHEN,
    "TS-PKG-001": _UNDECLARED_DEP_NOT_WHEN,
    "TS-PKG-002": _INVALID_MANIFEST_NOT_WHEN,
    # Java
    "JAVA-COR-001": _EMPTY_CATCH_NOT_WHEN,
    "JAVA-COR-002": _SQL_NOT_WHEN,
    "JAVA-COR-003": _BROAD_HANDLER_NOT_WHEN,
    "JAVA-PKG-001": _UNDECLARED_DEP_NOT_WHEN,
    "JAVA-PKG-002": _INVALID_MANIFEST_NOT_WHEN,
    # Kotlin
    "KT-COR-001": _EMPTY_CATCH_NOT_WHEN,
    "KT-COR-002": _SQL_NOT_WHEN,
    "KT-COR-003": _BROAD_HANDLER_NOT_WHEN,
    "KT-COR-004": _BLOCKING_ASYNC_NOT_WHEN,
    "KT-COR-005": _DENSITY_NOT_WHEN,
    "KT-PKG-001": _UNDECLARED_DEP_NOT_WHEN,
    "KT-PKG-002": _INVALID_MANIFEST_NOT_WHEN,
    # C#
    "CS-COR-001": _EMPTY_CATCH_NOT_WHEN,
    "CS-COR-002": _SQL_NOT_WHEN,
    "CS-COR-003": _BROAD_HANDLER_NOT_WHEN,
    "CS-COR-004": _BLOCKING_ASYNC_NOT_WHEN,
    "CS-PKG-001": _UNDECLARED_DEP_NOT_WHEN,
    "CS-PKG-002": _INVALID_MANIFEST_NOT_WHEN,
    # C / C++
    "C-COR-001": _EMPTY_CATCH_NOT_WHEN,
    "C-COR-002": _SQL_NOT_WHEN,
    "C-COR-003": _BROAD_HANDLER_NOT_WHEN,
    "C-COR-004": (
        "The `using namespace` directive is in a source file (.c/.cc/.cpp), not a "
        "header; only headers are flagged.",
        "The directive is scoped inside a function or namespace block rather than "
        "at file scope.",
    ),
    "C-DUP-001": _DUP_NOT_WHEN,
    "C-MAINT-001": _COMPLEXITY_NOT_WHEN,
    "C-MAINT-002": _COMPLEXITY_NOT_WHEN,
    "C-PKG-001": (
        "The header is a system or standard header (angle-bracket include of a known "
        "standard name) or resolves inside the project tree.",
        "The build is not CMake: drift is only evaluated against CMake manifests, "
        "so other build systems produce no findings.",
        "Reported at medium confidence; confirm against the actual build graph.",
    ),
    # Rust
    "RS-COR-001": (
        "The `.unwrap()` calls are inside `#[cfg(test)]` modules or `#[test]` "
        "functions: both are blanked before counting (languages/rust.py "
        "_blank_test_code), and test-path files are downgraded.",
        "The per-file count is below the density threshold; a single unwrap is " "never reported.",
    ),
    "RS-COR-002": _SQL_NOT_WHEN,
    "RS-COR-003": _BLOCKING_ASYNC_NOT_WHEN,
    "RS-COR-004": (
        'The `#![allow(...)]` carries a `reason = "..."` argument, or the allow is '
        "item-scoped (`#[allow]`) rather than crate-wide (`#![allow]`).",
        "The lint is not one of dead_code / unused / warnings / clippy::all.",
    ),
    "RS-DUP-001": _DUP_NOT_WHEN,
    "RS-MAINT-001": _COMPLEXITY_NOT_WHEN,
    "RS-MAINT-002": _COMPLEXITY_NOT_WHEN,
    "RS-PKG-001": (
        "The `use` root is std/core/alloc/crate/self/super/proc_macro/test "
        "(languages/rust.py _STD_ROOTS) or a local module.",
        "The crate is declared in [dependencies], [dev-dependencies] or "
        "[build-dependencies] of the nearest governing Cargo.toml or any ancestor.",
        "Reported at medium confidence: renamed dependencies (`package = ...`) and "
        "workspace inheritance can appear undeclared; confirm before acting.",
    ),
    "RS-PKG-002": _INVALID_MANIFEST_NOT_WHEN,
}


def _attach_not_when(rules: tuple[RuleMetadata, ...]) -> tuple[RuleMetadata, ...]:
    attached = []
    for rule in rules:
        clauses = _NOT_WHEN.get(rule.rule_id, ())
        attached.append(
            RuleMetadata(
                rule_id=rule.rule_id,
                name=rule.name,
                title=rule.title,
                description=rule.description,
                category=rule.category,
                default_severity=rule.default_severity,
                confidence=rule.confidence,
                remediation=rule.remediation,
                language=rule.language,
                not_when=clauses,
            )
        )
    return tuple(attached)


_RULES = _attach_not_when(_RULES)
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
