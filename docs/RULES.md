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
