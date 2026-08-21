# Rule reference

The built-in SARIF catalog mirrors the rule IDs, titles, categories, default
severities, confidence, and remediation documented here. Catalog completeness
is tested so a built-in finding cannot be rendered without stable metadata.
Runtime severity policy may override a finding's level without changing the
documented default.

## PY-COR-001: Mutable default argument

**Category:** Correctness  
**Default severity:** Warning  
**Confidence:** High

Python evaluates function defaults once when the function is defined. Mutating a list, dictionary, set, comprehension result, or mutable built-in factory default can therefore leak state between calls.

### Non-compliant

```python
def add_item(item, items=[]):
    items.append(item)
    return items
```

### Compliant

```python
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
```

The rule reports the default expression with a one-based file, line, and column location. It currently recognizes list, dictionary, and set literals; list, dictionary, and set comprehensions; and direct calls to `list()`, `dict()`, `set()`, and `bytearray()`.

A same-line suppression is accepted only when it names the rule and includes a nonempty quoted reason:

```python
def compatibility(cache={}):  # cqa: ignore=PY-COR-001 reason="legacy API"
    return cache
```

Malformed directives, blank or missing reasons, and directive-like strings do not suppress the finding. Reasons are not copied into reports or baselines. See [`CONFIGURATION.md`](CONFIGURATION.md) for the complete contract.

## PY-COR-002: Broad exception handler

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A bare `except` or a handler for `Exception`/`BaseException` can hide unrelated failures and, for the broadest forms, process-control exceptions. Catch only exception types the operation can recover from.

```python
# Non-compliant
try:
    load_order()
except Exception:
    recover()

# Compliant
try:
    load_order()
except OrderNotFoundError:
    recover()
```

Tuples are reported when they contain `Exception` or `BaseException`. Attribute-qualified application exception types are not assumed to be broad.

## PY-COR-003: Silently swallowed exception

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

An exception handler whose only statement is `pass` or `...` discards the failure without recovery, propagation, or actionable context.

```python
# Non-compliant
try:
    refresh()
except RefreshError:
    pass

# Compliant
try:
    refresh()
except RefreshError as error:
    logger.warning("Refresh failed", exc_info=error)
```

If discarding a known failure is intentional, use a reason-required same-line suppression on the `except` line rather than an unrecorded empty handler.

## PY-COR-004: Unreachable statement

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A statement immediately following a direct `return`, `raise`, `break`, or `continue` in the same suite cannot execute. The rule reports the first unreachable statement in each affected suite.

```python
# Non-compliant
def load():
    return cached_value
    refresh_cache()

# Compliant
def load():
    refresh_cache()
    return cached_value
```

The rule is intentionally conservative: it does not infer that a conditional or compound statement always transfers control.

## PY-COR-005: Blocking synchronous call in async code

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A known synchronous standard-library operation is called directly inside an `async def`. The bounded allowlist covers `time.sleep`, synchronous `subprocess` helpers, `os.system`, `urllib.request.urlopen`, built-in/`io.open`, and direct `pathlib.Path` file methods. Imported aliases are resolved conservatively; shadowed or ambiguous names are ignored.

Use the corresponding async API, `asyncio.create_subprocess_*`, or move unavoidable synchronous work to `asyncio.to_thread`. Calls passed as callables to `to_thread` or an executor are not reported. Generic methods and third-party clients are intentionally outside this rule.

## PY-COR-006: Resource without guaranteed cleanup

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A locally acquired file or temporary resource is not protected by `with`, `ExitStack.enter_context`, or `try...finally` cleanup. The bounded rule covers built-in/`io.open`, direct `Path(...).open()`, and standard `tempfile` context-manager factories.

Directly returned, yielded, passed, or attribute-stored resources are treated as escaped ownership and are not judged locally. A plain later `close()` is not considered guaranteed when intervening work can raise. Use a context manager whenever possible.

Both rules report the call location and support reason-required same-line suppressions. A bare `open()` in async code may intentionally emit both rule IDs.

## PY-MAINT-001: High cyclomatic complexity

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function has more than 10 independent control-flow paths. The measured value starts at one and counts conditionals, loops, exception handlers, conditional expressions, boolean branches, comprehensions, and match branches.

The finding reports the function definition and measured value. Extract independent decisions into focused helpers. A value of exactly 10 is accepted; the first reported value is 11.

## PY-MAINT-002: High cognitive complexity

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function has cognitive complexity above 15. Decisions add one point plus their current control-flow nesting depth; boolean sequences and comprehensions also add bounded structural cost. The measurement is deterministic and syntax-derived rather than an estimated Big-O class.

Flatten nested conditionals and loops, use guard clauses, and extract focused helpers. A value of exactly 15 is accepted. Nested functions and methods are measured independently, and a suppression must appear on the reported function-definition line.

## PY-MAINT-003: Long function

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function spans more than 60 physical source lines from its definition through its final statement. A span of exactly 60 lines is accepted. Extract cohesive responsibilities into focused helpers.

## PY-MAINT-004: Excessive parameters

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function declares more than seven effective parameters. The leading `self` or `cls` receiver is excluded; positional-only, positional, keyword-only, variadic positional, and variadic keyword parameters are counted. Group related inputs in a value object or split the responsibility.

## PY-MAINT-005: Boolean parameter proliferation

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function exposes more than two parameters identified as boolean by an explicit `bool` annotation or a `True`/`False` default. Multiple mode flags create combinatorial behavior that is hard to name and test. Prefer explicit operations, an enum, or a typed configuration object.

All three rules report the function definition line, where a reason-required suppression can be placed when a stable external interface cannot yet be changed.

## Python package rules

Package rules analyze conventional `src` and initialized flat packages plus
PEP 420 namespaces identified by bounded static setuptools discovery metadata.
Ambiguous configuration is skipped without executing build hooks or weakening
strict-mode analysis health.

## PY-PKG-001: Circular local imports

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

The package import graph contains two or more modules that directly or indirectly depend on each other. Circular imports make initialization order fragile and can expose partially initialized modules.

Move shared contracts into a lower-level module, invert one dependency, or introduce a narrow interface that removes the cycle.

## PY-PKG-002: Missing console-script module

**Category:** Package health
**Default severity:** Error
**Confidence:** High

A `[project.scripts]` entry in `pyproject.toml` points to a module that is not present in the detected local package modules.

Correct the entry-point target or ensure that the target module is included in the package source layout.

## PY-PKG-003: Invalid pyproject metadata

**Category:** Package health
**Default severity:** Error
**Confidence:** High

The project contains `pyproject.toml`, but it cannot be read as valid TOML. Package metadata and build configuration cannot be trusted until parsing succeeds. This finding also marks strict analysis as incomplete.

Correct the TOML syntax and rerun the analyzer. The report intentionally avoids reproducing source content from the invalid file.

## PY-PKG-004: Missing literal public export binding

**Category:** Package health
**Default severity:** Error
**Confidence:** High

A literal string in an eligible module-level `__all__` list or tuple has no
module-scope binding. Forward definitions and names bound by functions, classes,
assignments, imports, and module-level control-flow suites are recognized.

Define or import the name at module scope, or remove it from `__all__`.
Analysis is skipped when `__all__` is dynamic or ambiguous, including multiple
assignments, mutation, wildcard imports, module `__getattr__`, namespace
manipulation, comprehensions, concatenation, unpacking, or non-string values.

## PY-PKG-005: Duplicate literal public export

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

An eligible literal module-level `__all__` declaration repeats an exported
name. Each occurrence after the first receives a finding at its own string
literal, with case-sensitive comparison.

Remove repeated names from `__all__`. The same conservative eligibility
boundaries as `PY-PKG-004` apply.

## PY-PKG-006: Missing literal package-data target

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

An eligible static `[tool.setuptools.package-data]` declaration names a literal
source-tree path that does not exist as a regular file beneath the uniquely
resolved package directory. The finding is reported at `pyproject.toml:1:1`
because the bounded TOML parser does not expose key locations.

Add the file, correct the literal path, or disable the rule when a documented
build step generates it. The rule does not make strict analysis incomplete.
It runs only for standard setuptools builds with one unambiguous setuptools
build requirement and no custom setup file, backend path, command class, or
package remapping. Wildcard package keys, globs, unsafe paths, malformed or
oversized tables, unknown/ambiguous packages, symlinks, directories, special
files, and stat errors are skipped. The analyzer never reads package-data
contents, walks data directories, executes build hooks, or claims that a file
is present in a built wheel or source distribution.

## GO-COR-001: Ignored standard-library error

**Category:** Correctness

**Default severity:** Warning

**Confidence:** High

A two-result assignment discards the second result from a known imported Go standard-library function whose second result is an `error`. The pilot is intentionally narrow: it covers selected functions from `encoding/json`, `io`, `net/http`, `net/url`, `os`, and `strconv`; it does not assume every second return value is an error.

### Non-compliant

```go
data, _ := os.ReadFile(path)
```

### Compliant

```go
data, err := os.ReadFile(path)
if err != nil {
    return nil, err
}
```

The rule requires the corresponding standard-library import, ignores comments and string literals, follows explicit import aliases, and reports the discarded result's one-based location. Blank and dot imports are recorded but intentionally do not authorize qualified-call matches.
