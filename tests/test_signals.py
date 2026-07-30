"""Signal extraction: literals are ignored, bare words match identifiers."""

from pathlib import Path

from analyzer.signals import extract_signals, strip_comments_and_strings


def signals_for(source: str):
    return extract_signals(Path("sample.py"), source)


def test_comments_and_strings_are_blanked_but_layout_preserved():
    source = 'x = 1  # dijkstra\ny = "memo[0]"\n'
    stripped, ok = strip_comments_and_strings(source)

    assert ok
    assert "dijkstra" not in stripped
    assert "memo[" not in stripped
    # Same shape, so text patterns still match at the right offsets.
    assert len(stripped.splitlines()) == len(source.splitlines())
    assert stripped.splitlines()[0].startswith("x = 1")


def test_docstring_mentions_do_not_become_signals():
    source = '''
"""We should use a Trie here, and maybe dp[i] memoization.

Also consider heappush and a bloom_filter.
"""


def add(a, b):
    return a + b
'''
    signals = signals_for(source)

    assert not signals.has_identifier("trie")
    assert not signals.has_text("dp[")
    assert not signals.has_identifier("heappush")


def test_identifier_match_is_exact_not_substring():
    signals = signals_for("population = 5\nprint(population)\n")

    # "pop" must not match inside "population".
    assert not signals.has_identifier("pop")
    assert signals.has_identifier("population")


def test_attribute_and_call_names_are_collected():
    signals = signals_for("import heapq\nheapq.heappush(h, 1)\nitems.pop()\n")

    assert signals.has_identifier("heappush")
    assert signals.has_identifier("pop")
    assert signals.has_import("heapq")


def test_unparseable_file_still_yields_text_signals():
    signals = signals_for("def broken(:\n    dp[0] = 1\n")

    assert signals.parsed is False
    # Tokenizer also fails here, so we fall back to raw text.
    assert signals.has_text("dp[")


def test_fstring_contents_are_not_searched():
    signals = signals_for('name = "x"\nmsg = f"use dijkstra on {name}"\n')

    assert not signals.has_identifier("dijkstra")
    assert signals.has_identifier("name")
