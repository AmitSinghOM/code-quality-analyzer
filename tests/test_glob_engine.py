"""The glob engine does bounded work on any pattern (3.6.0).

``_translate_glob`` turned ``a*a*a*a*a*b`` into ``a[^/]*a[^/]*a[^/]*...``, and
``re`` backtracks exponentially on a path of ``a``s that does not match: six
stars against 200 characters took close to a minute. Patterns that spend more
than two wildcards now run on ``_GlobAutomaton``, a one-pass NFA simulation
whose work is linear in the path, while patterns within the budget keep the
``re`` fast path. Both engines read one token stream, and this module checks
they agree on random input, so ``include`` / ``exclude`` / ``.gitignore`` /
``[overrides]`` semantics are unchanged whichever engine runs.
"""

from __future__ import annotations

import random
import re
import time

import pytest

from cqa_analyzer.config import (
    MAX_PATTERN_LENGTH,
    MAX_PATTERNS,
    ConfigError,
    _compile_glob,
    _glob_matches,
    _glob_tokens,
    _GlobAutomaton,
    _parse_config,
    _RegexGlob,
    _translate_glob,
    _translate_tokens,
)


def _automaton(pattern: str) -> _GlobAutomaton:
    """Build the automaton for any pattern, budget or not."""
    body = pattern.replace("\\", "/").lstrip("/").rstrip("/")
    anchored = pattern.replace("\\", "/").startswith("/") or "/" in body
    return _GlobAutomaton(_glob_tokens(body), anchored)


def _regex(pattern: str) -> re.Pattern[str]:
    body = pattern.replace("\\", "/").lstrip("/").rstrip("/")
    anchored = pattern.replace("\\", "/").startswith("/") or "/" in body
    prefix = "^" if anchored else r"(?:^|.*/)"
    return re.compile(prefix + _translate_tokens(_glob_tokens(body)) + r"(?:/.*)?$")


# --- Engine selection -----------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    ["*.py", "**/*.py", "src/**/*.py", "tests/**", "/root.py", "build/", "a?c", "[ab]x"],
)
def test_patterns_within_the_wildcard_budget_keep_the_regex_fast_path(pattern):
    _compile_glob.cache_clear()
    assert isinstance(_compile_glob(pattern), _RegexGlob)


@pytest.mark.parametrize(
    "pattern",
    ["*a*", "a*a*b", "**/x*y*z", "src/**/*/*.py", "a**b**c", "a*" * 40 + "b"],
)
def test_patterns_beyond_the_wildcard_budget_run_on_the_automaton(pattern):
    """An unanchored pattern's implicit ``(?:^|.*/)`` prefix is itself a wildcard."""
    _compile_glob.cache_clear()
    assert isinstance(_compile_glob(pattern), _GlobAutomaton)


# --- The reported ``a*`` family: deterministic lock -----------------------------


@pytest.mark.parametrize("stars", [6, 12, 24, 40, 255])
def test_a_star_family_is_matched_in_one_linear_pass(monkeypatch, stars):
    """Lock: the automaton consumes each character once. ``_closure`` runs
    once at start and once per consumed character, so its call count bounds
    the work and does not depend on how many wildcards the pattern has. On
    the regex engine the same inputs were exponential in ``stars``."""
    pattern = "a*" * stars + "b"
    assert len(pattern) <= MAX_PATTERN_LENGTH
    calls = []
    original = _GlobAutomaton._closure
    monkeypatch.setattr(
        _GlobAutomaton, "_closure", lambda self, states: calls.append(1) or original(self, states)
    )
    _compile_glob.cache_clear()
    matcher = _compile_glob(pattern)
    assert isinstance(matcher, _GlobAutomaton)

    rejected = "a" * 300 + "c"
    accepted = "a" * 300 + "b"
    calls.clear()
    assert matcher.matches(rejected) is False
    assert len(calls) <= len(rejected) + 1
    calls.clear()
    assert matcher.matches(accepted) is True
    assert len(calls) <= len(accepted) + 1
    # Any slash ends the run every ``*`` may consume; still one pass.
    calls.clear()
    assert matcher.matches("x/" + "a" * 100 + "/" + "a" * 300 + "b") is True
    assert len(calls) <= 410


def test_a_star_family_completes_quickly_even_at_the_pattern_and_path_limits():
    """Sanity, not the lock: 255 stars against 4,000 characters, both ways.
    On the regex engine this never finished; the bound here is a hundred
    times what the automaton needs, so a slow runner cannot trip it."""
    pattern = "a*" * 255 + "b"
    started = time.perf_counter()
    assert _glob_matches(pattern, "a" * 4000 + "c") is False
    assert _glob_matches(pattern, "a" * 4000 + "b") is True
    assert _glob_matches("*a" * 200, "a/" * 100 + "b" * 3000) is False
    assert _glob_matches("*a" * 200, "a/" * 100 + "a" * 3000) is True
    assert time.perf_counter() - started < 5.0


def test_adversarial_overrides_at_the_size_cap_resolve_in_bounded_time():
    """1,000 tables of 511-character wildcard-heavy globs, overlapping at
    equal literal prefix, against long paths: every table is visited for every
    (path, rule) and none may blow up."""
    tables = {
        f"gen/{i:03d}" + "*a" * 250 + "?": {"disabled": ["PY-COR-001"]} for i in range(MAX_PATTERNS)
    }
    assert all(len(glob) <= MAX_PATTERN_LENGTH for glob in tables)
    config = _parse_config({"overrides": tables})
    started = time.perf_counter()
    for n in range(200):
        path = f"gen/{n:03d}" + "a" * 400 + ("x" if n % 2 else "/")
        policy = config.effective_policy("PY-COR-001", path)
        assert policy.enabled is (n % 2 == 1) or policy.enabled is False
    assert time.perf_counter() - started < 5.0


def test_oversized_glob_is_rejected_before_it_is_compiled():
    with pytest.raises(ConfigError, match="invalid pattern"):
        _parse_config({"overrides": {"a*" * 257: {"disabled": ["PY-COR-001"]}}})
    with pytest.raises(ConfigError, match="invalid pattern"):
        _parse_config({"analysis": {"exclude": ["a*" * 257]}})


# --- Both engines agree -----------------------------------------------------------

ALPHABET = ["a", "b", "/", "*", "**", "?", "[ab]", "[!a]", "[a-b]", ".", "[", "]", "[!]", "[]]"]


@pytest.mark.parametrize("seed", range(4))
def test_automaton_and_regex_agree_on_random_patterns_and_paths(seed):
    rng = random.Random(seed)  # noqa: S311 - deterministic test corpus
    pairs = 0
    for _ in range(4000):
        pattern = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 8)))
        body = pattern.lstrip("/").rstrip("/")
        if not body:
            continue
        regex, automaton = _regex(pattern), _automaton(pattern)
        for _ in range(5):
            path = "".join(rng.choice("ab./]") for _ in range(rng.randint(0, 10)))
            assert (regex.match(path) is not None) == automaton.matches(path), (pattern, path)
            pairs += 1
    assert pairs > 10_000


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        # .gitignore semantics the include/exclude docs promise.
        ("*.py", "a.py", True),
        ("*.py", "deep/er/a.py", True),
        ("*.py", "a.pyc", False),
        ("/root.py", "root.py", True),
        ("/root.py", "sub/root.py", False),
        ("build/", "build/x.o", True),
        ("build/", "src/build/x.o", True),
        ("build", "src/build", True),
        ("src/**", "src/a/b/c.py", True),
        ("src/**", "lib/src/a.py", False),
        ("**/tests/*.py", "tests/a.py", True),
        ("**/tests/*.py", "x/y/tests/a.py", True),
        ("**/tests/*.py", "x/tests/sub/a.py", False),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("a**b", "a/x/b", True),  # bare ``**`` crosses directories
        ("a?c", "abc", True),
        ("a?c", "a/c", False),
        ("[ab]x", "ax", True),
        ("[!a]x", "ax", False),
        ("[!a]x", "/x", True),  # a class admits ``/``, as the regex form always did
        ("[!]x]", "yy", False),  # the ``]`` after ``!`` is a member of the class
        ("[!]x]", "ay", False),
        ("[!]x]", "a", True),
        ("[]]", "]", True),
        ("[!]", "[!]", True),  # unterminated class is a literal ``[``
        # Overlap and order: the engine decides matching only; tie-breaking is
        # the override resolver's, so both of these match the same path.
        ("src/**", "src/db/x.py", True),
        ("src/db/**", "src/db/x.py", True),
    ],
)
def test_matching_semantics_are_the_same_on_both_engines(pattern, path, expected):
    assert _glob_matches(pattern, path) is expected
    assert _automaton(pattern).matches(path) is expected
    assert (_regex(pattern).match(path) is not None) is expected


def test_translate_glob_still_renders_a_valid_regex_body_for_fuzz_callers():
    for pattern in ("a*b", "**/x", "[!]x]", "[]]", "[!]", "a**", "[", "]", "[a-"):
        re.compile(_translate_glob(pattern))
