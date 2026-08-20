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
