"""Rating behaviour: size is not quality, breadth counts, gaps are penalized."""

from analyzer.rater import QualityRater, coverage_gap_ratio


def rate(dsa=None, design=None, files=5, lines=1000, gap=0.0):
    rater = QualityRater(dsa or {}, design or {}, files, lines, coverage_gap_ratio=gap)
    return rater.calculate_rating()


def test_padding_a_project_does_not_raise_the_rating():
    """Regression: the old size bonus grew with file and line count."""
    patterns = {"dynamic_programming": ["a.py", "b.py"]}
    design = {"api_design": ["api.py"]}

    small, _ = rate(patterns, design, files=5, lines=2_000)
    padded, _ = rate(patterns, design, files=500, lines=200_000)

    assert padded == small


def test_empty_project_is_flagged_not_silently_rated():
    rating, breakdown = rate(files=0, lines=0)

    assert rating == 1.0
    assert breakdown["warnings"]


def test_broad_usage_scores_above_a_single_incidental_use():
    narrow, _ = rate({"dynamic_programming": ["a.py"]})
    broad, _ = rate({"dynamic_programming": ["a.py", "b.py", "c.py", "d.py"]})

    assert broad > narrow


def test_coverage_gap_lowers_rating_and_warns():
    patterns = {"dynamic_programming": ["a.py", "b.py"], "graph_traversal": ["g.py"]}
    design = {"api_design": ["api.py"], "caching": ["c.py"]}

    clean_rating, _ = rate(patterns, design, gap=0.0)
    gapped_rating, gapped = rate(patterns, design, gap=0.5)

    assert gapped_rating < clean_rating
    assert any("lower bound" in w for w in gapped["warnings"])


def test_tiny_project_gets_a_noise_warning():
    _, breakdown = rate({"sorting": ["a.py"]}, lines=50)

    assert any("very small" in w for w in breakdown["warnings"])


def test_rating_stays_in_range():
    everything = {name: ["a.py", "b.py", "c.py", "d.py"] for name in (
        "dynamic_programming", "graph_traversal", "segment_tree",
        "fenwick_tree", "trie", "union_find", "dijkstra",
    )}
    rating, _ = rate(everything, everything, files=100, lines=50_000)

    assert 1.0 <= rating <= 10.0


def test_coverage_gap_ratio_math():
    assert coverage_gap_ratio(files_scanned=8, skipped=2, unparsed=0) == 0.2
    assert coverage_gap_ratio(files_scanned=0, skipped=0, unparsed=0) == 0.0
