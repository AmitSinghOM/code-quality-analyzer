"""Cross-language fairness invariants (roadmap item 5, docs/CALIBRATION.md)."""

from __future__ import annotations

from cqa_analyzer.c_patterns import C_DESIGN_PATTERNS, C_DSA_PATTERNS
from cqa_analyzer.csharp_patterns import CSHARP_DESIGN_PATTERNS, CSHARP_DSA_PATTERNS
from cqa_analyzer.go_patterns import GO_DESIGN_PATTERNS, GO_DSA_PATTERNS
from cqa_analyzer.java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS
from cqa_analyzer.kotlin_patterns import KOTLIN_DESIGN_PATTERNS, KOTLIN_DSA_PATTERNS
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.rater import QualityRater
from cqa_analyzer.rust_patterns import RUST_DESIGN_PATTERNS, RUST_DSA_PATTERNS
from cqa_analyzer.ts_patterns import TS_DESIGN_PATTERNS, TS_DSA_PATTERNS

CATALOGS = {
    "go": (GO_DSA_PATTERNS, GO_DESIGN_PATTERNS),
    "typescript": (TS_DSA_PATTERNS, TS_DESIGN_PATTERNS),
    "java": (JAVA_DSA_PATTERNS, JAVA_DESIGN_PATTERNS),
    "kotlin": (KOTLIN_DSA_PATTERNS, KOTLIN_DESIGN_PATTERNS),
    "csharp": (CSHARP_DSA_PATTERNS, CSHARP_DESIGN_PATTERNS),
    "c_cpp": (C_DSA_PATTERNS, C_DESIGN_PATTERNS),
    "rust": (RUST_DSA_PATTERNS, RUST_DESIGN_PATTERNS),
}


def test_every_language_can_reach_every_catalog_id():
    """No language is capped below another by a missing pattern ID."""
    for language, (dsa, design) in CATALOGS.items():
        assert set(dsa) == set(DSA_PATTERNS), (language, set(DSA_PATTERNS) - set(dsa))
        assert set(design) == set(SYSTEM_DESIGN_PATTERNS), language


def test_curve_ceilings_are_reachable_from_a_fraction_of_any_catalog():
    """Full marks need weight 12 (DSA) / 22.5 (design); every catalog offers ~5x."""
    rater = QualityRater({}, {}, 1, 1)
    assert rater._apply_curve(12, rater._DSA_CURVE) == 8.0
    assert rater._apply_curve(22.5, rater._DESIGN_CURVE) == 8.0
    assert sum(v["weight"] for v in DSA_PATTERNS.values()) > 5 * 12
    assert sum(v["weight"] for v in SYSTEM_DESIGN_PATTERNS.values()) > 2 * 22.5


def test_every_pattern_has_at_least_one_non_import_anchor_or_is_library_defined():
    """Import-only specs are allowed only where a library *is* the pattern."""
    allowed_import_only = {"database_orm", "message_queue", "observability"}
    for language, (dsa, design) in CATALOGS.items():
        for name, spec in {**dsa, **design}.items():
            has_code_anchor = any(
                spec.get(k) for k in ("identifiers", "identifier_contains", "text")
            )
            assert has_code_anchor or name in allowed_import_only, (language, name)
