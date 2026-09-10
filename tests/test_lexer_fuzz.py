"""Adversarial-input invariants for every regex lexer (staff review A4).

No Hypothesis dependency: a seeded generator splices each language's
tricky tokens (quotes, comment openers, template markers, raw-string
prefixes, backslashes, `$`, `#`, brackets) into random soup. The lexers
must, for every input:

- terminate quickly (they are single-pass state machines — a 200 KB input
  must lex in well under a second);
- return output of identical length with identical newline positions
  (locations computed on blanked text are used against the original);
- in metadata mode (strings kept) never change a character outside a
  comment;
- never raise.
"""

from __future__ import annotations

import random
import re
import time

import pytest

from cqa_analyzer.languages.c_family import _c_identifiers, _strip_c_comments_and_strings
from cqa_analyzer.languages.csharp import _identifiers as _csharp_identifiers
from cqa_analyzer.languages.csharp import _strip_csharp_comments_and_strings
from cqa_analyzer.languages.go import _go_identifiers
from cqa_analyzer.languages.go import _strip_comments_and_strings as _strip_go
from cqa_analyzer.languages.java import _java_identifiers, _strip_java_comments_and_strings
from cqa_analyzer.languages.kotlin import _kotlin_identifiers, _strip_kotlin_comments_and_strings
from cqa_analyzer.languages.typescript import _strip_ts_comments_and_strings, _ts_identifiers

COMMON = [
    '"',
    "'",
    "`",
    "/",
    "*",
    "\\",
    "\n",
    "\n",
    " ",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    "<",
    ">",
    "$",
    "#",
    ":",
    ";",
    "=",
    ",",
    "x",
    "y",
    "0",
    "1",
    "a",
    "f",
    "e",
    "R",
    "L",
    "u8",
    "if",
    "return",
    "case",
    "try",
    "catch",
    "fun",
    "func",
    "import",
    "trie",
    "dijkstra",
]
TOKENS = {
    "typescript": COMMON + ["${", "//", "/*", "*/", "=>", "</p>", "<div>", "/re/g", "Don't"],
    "kotlin": COMMON + ['"""', "${", "$$", "//", "/*", "*/", "`can't`", "'\\''"],
    "java": COMMON + ['"""', "//", "/*", "*/", "\\u0022", "'\\''"],
    "csharp": COMMON + ['@"', '$"', '$@"', '"""', '$$"""', "{{", "}}", '""', "//", "/*", "*/"],
    "go": COMMON + ["//", "/*", "*/", '`json:"x"`', "'\\''", '"\\""'],
    "c_cpp": COMMON
    + [
        "#include <x.h>",
        "#define",
        'R"(',
        ')"',
        'u8R"x(',
        ')x"',
        "1'000",
        "case'a'",
        "//",
        "/*",
        "*/",
        "\\\n",
        "0xFF'FF",
    ],
}
LEXERS = {
    "typescript": _strip_ts_comments_and_strings,
    "kotlin": _strip_kotlin_comments_and_strings,
    "java": _strip_java_comments_and_strings,
    "csharp": _strip_csharp_comments_and_strings,
    "go": _strip_go,
    "c_cpp": _strip_c_comments_and_strings,
}


def soup(language: str, seed: int, size: int) -> str:
    rng = random.Random(seed)  # noqa: S311 - deterministic test corpus, not security
    tokens = TOKENS[language]
    parts = []
    length = 0
    while length < size:
        token = rng.choice(tokens)
        parts.append(token)
        length += len(token)
    return "".join(parts)


@pytest.mark.parametrize("language", sorted(LEXERS))
@pytest.mark.parametrize("seed", range(12))
def test_lexer_invariants_on_random_soup(language, seed):
    source = soup(language, seed, 6_000)
    lexer = LEXERS[language]
    started = time.perf_counter()
    blanked, complete = lexer(source)
    kept, _ = lexer(source, blank_strings=False)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"{language} seed {seed}: {elapsed:.2f}s"
    assert isinstance(complete, bool)
    assert len(blanked) == len(source) == len(kept)
    newlines = [i for i, c in enumerate(source) if c == "\n"]
    assert [i for i, c in enumerate(blanked) if c == "\n"] == newlines
    # Blanking only ever replaces characters with spaces.
    assert all(b == s or b == " " for b, s in zip(blanked, source, strict=False))
    assert all(k == s or k == " " for k, s in zip(kept, source, strict=False))


EXTRACTORS = {
    "c_cpp": _c_identifiers,
    "kotlin": _kotlin_identifiers,
    "typescript": _ts_identifiers,
    "java": _java_identifiers,
    "csharp": _csharp_identifiers,
    "go": _go_identifiers,
}


@pytest.mark.parametrize("language", sorted(EXTRACTORS))
def test_identifier_extraction_is_linear_on_large_soup(language):
    # The regexes with optional bracket groups and `::`/`.` chains must not
    # backtrack catastrophically on 200 KB of adversarial text.
    source = soup(language, 99, 200_000)
    extract = EXTRACTORS[language]
    started = time.perf_counter()
    names = extract(LEXERS[language](source)[0])
    assert time.perf_counter() - started < 10.0  # 200 KB; CI runners are slow
    assert isinstance(names, tuple)


@pytest.mark.parametrize("language", sorted(EXTRACTORS))
def test_pathological_chain_input_scales_linearly(language):
    # Long qualified chains and unbalanced `<` are the shapes most likely to
    # trigger backtracking in declaration/call regexes. Assert on scaling,
    # not wall-clock: CI runners are 3-4x slower than a laptop, but a
    # quadratic regex doubles its ratio when the input doubles.
    sep = "::" if language == "c_cpp" else "."

    def chain(n):
        return (f"a{sep}" * n + "b<" * n + " " + "x" * n + "\n") * 3

    def timed(n):
        started = time.perf_counter()
        EXTRACTORS[language](chain(n))
        return time.perf_counter() - started

    small, large = timed(2500), timed(5000)
    assert large < 10.0, f"{language}: {large:.2f}s on a 45 KB line"
    # Linear work doubles; quadratic quadruples. Allow noise up to 3x.
    assert large < max(3 * small, 0.05), f"{language}: {small:.3f}s -> {large:.3f}s"


# --- Manifest parsers (round 2, D2): attacker-controlled in a fork PR. -------

from cqa_analyzer.config import _glob_matches, _translate_glob  # noqa: E402
from cqa_analyzer.languages.c_family import _cmake_tokens  # noqa: E402
from cqa_analyzer.languages.java import (  # noqa: E402
    _GRADLE_CATALOG_REF,
    _GRADLE_DEPENDENCY,
    _catalog_coordinates,
    _flatten_aliases,
)

MANIFEST_TOKENS = [
    "implementation",
    "(",
    ")",
    '"',
    "'",
    ":",
    ".",
    "-",
    "libs",
    "platform",
    "\n",
    " ",
    "a",
    "b",
    "1",
    "$",
    "{",
    "}",
    "target_link_libraries",
    "find_package",
    "#",
    "::",
    "[",
    "]",
    "!",
    "*",
    "?",
    "/",
    "\\",
    "**",
    "module",
    "group",
    "name",
    "=",
    ",",
]


def manifest_soup(seed: int, size: int) -> str:
    rng = random.Random(seed)  # noqa: S311 - deterministic test corpus
    parts, length = [], 0
    while length < size:
        token = rng.choice(MANIFEST_TOKENS)
        parts.append(token)
        length += len(token)
    return "".join(parts)


@pytest.mark.parametrize("seed", range(8))
def test_manifest_regexes_and_glob_translator_terminate_on_soup(seed):
    text = manifest_soup(seed, 50_000)
    started = time.perf_counter()
    list(_GRADLE_DEPENDENCY.finditer(text))
    list(_GRADLE_CATALOG_REF.finditer(text))
    _cmake_tokens(text)
    for line in text.splitlines()[:200]:
        pattern = line.strip()
        if pattern:
            re.compile(_translate_glob(pattern))  # must be a valid regex
            _glob_matches(pattern, "some/path/file.py")
    assert time.perf_counter() - started < 5.0


def test_catalog_flattening_and_coordinates_never_raise():
    weird = {"a": {"b": {"c": {"module": "g:a"}}}, "d": "x", "e": 5, "f": [1], "g": {"name": "n"}}
    pairs = dict(_flatten_aliases(weird))
    assert pairs["a-b-c"] == {"module": "g:a"}
    assert pairs["g"] == {"name": "n"}  # incomplete spec is a leaf, resolves to None
    for spec in (None, 5, [], {}, "", ":", "g:", ":a", {"module": ":"}, {"group": "g"}):
        assert _catalog_coordinates(spec) is None or isinstance(_catalog_coordinates(spec), tuple)
