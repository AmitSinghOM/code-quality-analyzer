"""Scoring policy 2.1.0 catalog (docs/adr/003): six new IDs and labuladong anchors.

The four design IDs came from patterns the author's own backends implement
(leases/SKIP LOCKED, expected-version writes, HMAC signing and SSRF egress
control, schedulers) that the 2.0.0 catalog could not see; the two DSA IDs and
the anchor extensions close gaps found by mapping labuladong's framework onto
the catalog. Each test pins one recognition and one refusal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cqa_analyzer.c_patterns import C_DESIGN_PATTERNS, C_DSA_PATTERNS
from cqa_analyzer.csharp_patterns import CSHARP_DESIGN_PATTERNS, CSHARP_DSA_PATTERNS
from cqa_analyzer.go_patterns import GO_DESIGN_PATTERNS, GO_DSA_PATTERNS
from cqa_analyzer.java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS
from cqa_analyzer.kotlin_patterns import KOTLIN_DESIGN_PATTERNS, KOTLIN_DSA_PATTERNS
from cqa_analyzer.patterns import DSA_PATTERNS, SYSTEM_DESIGN_PATTERNS
from cqa_analyzer.production_patterns import SHARED_ANCHOR_EXTENSIONS
from cqa_analyzer.rust_patterns import RUST_DESIGN_PATTERNS, RUST_DSA_PATTERNS
from cqa_analyzer.signals import extract_signals, pattern_is_present
from cqa_analyzer.ts_patterns import TS_DESIGN_PATTERNS, TS_DSA_PATTERNS

NEW_DESIGN = ("distributed_locking", "optimistic_concurrency", "security_hardening", "scheduling")
NEW_DSA = ("ring_buffer", "randomized_sampling")
CATALOGS = {
    "go": (GO_DSA_PATTERNS, GO_DESIGN_PATTERNS),
    "typescript": (TS_DSA_PATTERNS, TS_DESIGN_PATTERNS),
    "java": (JAVA_DSA_PATTERNS, JAVA_DESIGN_PATTERNS),
    "kotlin": (KOTLIN_DSA_PATTERNS, KOTLIN_DESIGN_PATTERNS),
    "csharp": (CSHARP_DSA_PATTERNS, CSHARP_DESIGN_PATTERNS),
    "c_cpp": (C_DSA_PATTERNS, C_DESIGN_PATTERNS),
    "rust": (RUST_DSA_PATTERNS, RUST_DESIGN_PATTERNS),
}


def _py(source: str):
    return extract_signals(Path("m.py"), source)


def _present(catalog: dict, name: str, source: str) -> bool:
    return pattern_is_present(_py(source), catalog[name])[0]


def test_new_ids_exist_everywhere_with_weights():
    for name in NEW_DESIGN:
        assert SYSTEM_DESIGN_PATTERNS[name]["weight"] > 0
    for name in NEW_DSA:
        assert DSA_PATTERNS[name]["weight"] > 0
    for language, (dsa, design) in CATALOGS.items():
        assert set(NEW_DSA) <= set(dsa), language
        assert set(NEW_DESIGN) <= set(design), language


@pytest.mark.parametrize("language", sorted(CATALOGS))
def test_labuladong_anchors_reached_every_language(language):
    dsa, _ = CATALOGS[language]
    for name, extra in SHARED_ANCHOR_EXTENSIONS.items():
        for key, values in extra.items():
            assert set(values) <= set(dsa[name][key]), (language, name, key)


# ---- design: recognition and refusal ------------------------------------------


def test_distributed_locking_from_leases_and_skip_locked():
    src = (
        "class ConsumerLease:\n"
        "    def acquire_lease(self, owner, fencing_token): ...\n"
        "    def renew_lease(self): ...\n"
        "SQL = 'SELECT id FROM jobs FOR UPDATE SKIP LOCKED'\n"
    )
    assert _present(SYSTEM_DESIGN_PATTERNS, "distributed_locking", src)
    # The SQL text is a string literal and is blanked; the *names* carry it.
    assert not _present(SYSTEM_DESIGN_PATTERNS, "distributed_locking", "lock = threading.Lock()\n")


def test_optimistic_concurrency_from_expected_version_not_atomic_cas():
    src = "def append(self, stream, events, expected_version):\n    raise VersionConflict()\n"
    assert _present(SYSTEM_DESIGN_PATTERNS, "optimistic_concurrency", src)
    # An atomic compare-and-swap on a flag is memory-level, not record versioning
    # (found on HUMM's circuit breaker during dogfooding).
    assert not _present(
        SYSTEM_DESIGN_PATTERNS, "optimistic_concurrency", "state.compare_and_swap(0, 1)\n"
    )


def test_security_hardening_from_hmac_and_egress_control():
    src = (
        "import hmac, ipaddress\n"
        "def verify_signature(secret, body, sig):\n"
        "    return hmac.compare_digest(sign_payload(secret, body), sig)\n"
        "def egress_allowed(host):\n"
        "    return not ipaddress.ip_address(host).is_private\n"
    )
    assert _present(SYSTEM_DESIGN_PATTERNS, "security_hardening", src)
    # `import secrets` for random IDs in a load script is not hardening
    # (found on wallet-transfer-service/scripts/burst.py during dogfooding).
    assert not _present(
        SYSTEM_DESIGN_PATTERNS, "security_hardening", "import secrets\nx = secrets.token_hex()\n"
    )


def test_scheduling_needs_two_anchors():
    assert _present(
        SYSTEM_DESIGN_PATTERNS,
        "scheduling",
        "from apscheduler.schedulers.background import BackgroundScheduler\n"
        "class ReplayScheduler:\n    def next_run(self): ...\n",
    )
    assert not _present(SYSTEM_DESIGN_PATTERNS, "scheduling", "schedule = build_schedule()\n")


# ---- DSA: recognition and refusal ------------------------------------------------


def test_ring_buffer_needs_a_ring_anchor_beyond_deque():
    assert _present(
        DSA_PATTERNS,
        "ring_buffer",
        "from collections import deque\nclass RingBuffer:\n"
        "    def __init__(self, n): self.buf = deque(maxlen=n)\n",
    )
    assert _present(
        DSA_PATTERNS,
        "ring_buffer",
        "class CircularBuffer:\n"
        "    def push(self): self.head_index = (self.head_index + 1) % self.capacity\n",
    )
    # A plain deque is a queue (queue_stack), not a ring buffer.
    assert not _present(
        DSA_PATTERNS, "ring_buffer", "from collections import deque\nq = deque()\nq.append(1)\n"
    )


def test_randomized_sampling_from_weighted_choice_not_plain_random():
    assert _present(
        DSA_PATTERNS, "randomized_sampling", "def weighted_choice(items, cumulative_weights): ...\n"
    )
    assert _present(DSA_PATTERNS, "randomized_sampling", "def reservoir_sample(stream, k): ...\n")
    assert not _present(DSA_PATTERNS, "randomized_sampling", "import random\nx = random.random()\n")


@pytest.mark.parametrize(
    ("pattern", "source"),
    [
        ("monotonic_stack", "def sliding_max(nums, k):\n    mono_queue = deque()\n"),
        ("prefix_sum", "def range_update(diff_array, lo, hi, v): ...\n"),
        (
            "heap_priority",
            "class MedianFinder:\n    def __init__(self): self.min_heap, self.max_heap = [], []\n",
        ),
        ("tree_structures", "from sortedcontainers import SortedDict\nleaders = SortedDict()\n"),
        ("dijkstra", "def floyd_warshall(dist): ...\n"),
        ("graph_traversal", "def is_bipartite(graph, visited): ...\n"),
        ("interval_operations", "def min_meeting_rooms(intervals):\n    sweep_line = []\n"),
        ("string_matching", "def rabin_karp(text, pat):\n    rolling_hash = 0\n"),
    ],
)
def test_labuladong_anchor_recognition(pattern, source):
    assert _present(DSA_PATTERNS, pattern, source), pattern
