# Rule reference

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
