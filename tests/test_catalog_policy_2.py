"""Scoring policy 2.0.0 catalog: parity, recognition, and precision."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cqa_analyzer import SCORING_POLICY_VERSION
from cqa_analyzer.__main__ import main
from cqa_analyzer.csharp_patterns import CSHARP_DESIGN_PATTERNS, CSHARP_DSA_PATTERNS
from cqa_analyzer.go_patterns import GO_DESIGN_PATTERNS, GO_DSA_PATTERNS
from cqa_analyzer.java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.production_patterns import PRODUCTION_DSA_PATTERNS, _DESIGN_BASE
from cqa_analyzer.rater import MATURITY_PATTERN_TARGET
from cqa_analyzer.signals import extract_signals, pattern_is_present
from cqa_analyzer.ts_patterns import TS_DESIGN_PATTERNS, TS_DSA_PATTERNS

_PILOTS = {
    "go": (GO_DSA_PATTERNS, GO_DESIGN_PATTERNS),
    "typescript": (TS_DSA_PATTERNS, TS_DESIGN_PATTERNS),
    "java": (JAVA_DSA_PATTERNS, JAVA_DESIGN_PATTERNS),
    "csharp": (CSHARP_DSA_PATTERNS, CSHARP_DESIGN_PATTERNS),
}


def test_policy_2_catalog_shape():
    assert SCORING_POLICY_VERSION == "2.0.0"
    assert len(DSA_PATTERNS) == 29
    assert len(SYSTEM_DESIGN_PATTERNS) == 27
    assert MATURITY_PATTERN_TARGET == 28
    for definition in list(DSA_PATTERNS.values()) + list(SYSTEM_DESIGN_PATTERNS.values()):
        assert definition["weight"] > 0
        assert definition["min_signals"] >= 1
        assert definition["description"]


@pytest.mark.parametrize("language", sorted(_PILOTS))
def test_every_pilot_carries_the_production_patterns_and_stays_in_catalog(language):
    dsa, design = _PILOTS[language]
    assert set(PRODUCTION_DSA_PATTERNS) <= set(dsa)
    assert set(_DESIGN_BASE) <= set(design)
    # The rater resolves weights from the Python catalog: no orphan IDs.
    assert set(dsa) <= set(DSA_PATTERNS)
    assert set(design) <= set(SYSTEM_DESIGN_PATTERNS)


def _python_signals(source: str):
    return extract_signals(Path("m.py"), source)


def test_resilience_and_event_sourcing_are_recognised_from_class_names():
    source = (
        "class CircuitBreaker:\n    def __init__(self): self.half_open = False\n\n"
        "class RetryPolicy:\n    def __init__(self): self.max_retries = 3\n\n"
        "class DeadLetteringProjectionStore:\n    pass\n\n"
        "class EventStore:\n    def append_event(self): pass\n\n"
        "class BalanceProjection:\n    def replay(self): pass\n"
    )
    signals = _python_signals(source)
    for name in ("resilience", "dead_letter_outbox", "event_sourcing_cqrs"):
        present, evidence = pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS[name])
        assert present, (name, evidence)


def test_raw_database_drivers_count_as_data_access():
    signals = _python_signals("import sqlite3\nimport psycopg\n")
    assert pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS["database_orm"])[0]


def test_observability_and_rate_limiting_from_imports_and_names():
    signals = _python_signals(
        "from opentelemetry import trace\nclass RateLimitMiddleware: pass\n"
    )
    assert pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS["observability"])[0]
    assert pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS["rate_limiting"])[0]


def test_common_words_need_corroboration():
    # 'projection' alone (SQL sense) and 'cursor' alone (DB sense) must not fire.
    signals = _python_signals(
        "def select_projection(cursor):\n    return cursor.execute('x')\n"
    )
    assert not pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS["event_sourcing_cqrs"])[0]
    assert not pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS["pagination"])[0]


def test_literal_mentions_of_new_patterns_are_not_evidence():
    signals = _python_signals(
        '"""We should add a CircuitBreaker and an outbox with consistent_hashing."""\n'
        "VALUE = 1\n"
    )
    for name in ("resilience", "dead_letter_outbox"):
        assert not pattern_is_present(signals, SYSTEM_DESIGN_PATTERNS[name])[0]
    assert not pattern_is_present(signals, DSA_PATTERNS["consistent_hashing"])[0]


def test_json_report_carries_policy_2(project):
    root = project({"m.py": "class RetryPolicy:\n    max_retries = 3\n"})
    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    assert payload["scoring_policy_version"] == "2.0.0"
    assert "resilience" in payload["design_patterns"]
