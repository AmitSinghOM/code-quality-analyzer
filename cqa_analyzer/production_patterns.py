"""Scoring policy 2.0.0 pattern specs shared by the pilot languages.

The production-systems and GoF patterns are recognised mostly by naming
conventions (``circuitbreaker``, ``deadletter``, ``eventstore``, …) that
are the same in every language. Each pilot merges these specs into its
own catalog and supplies only its idiomatic library imports and any
language-specific identifiers via :func:`production_design_patterns`.

Every ID here exists in the Python catalog (``patterns.py``), which the
rater uses for weights; the parity is regression-locked in tests.
"""

from __future__ import annotations

PRODUCTION_DSA_PATTERNS = {
    "bit_manipulation": {
        "identifiers": ["bitmask", "popcount", "bitcount", "lowbit", "xor"],
        "text": ["1 <<", "& (1 <<", "^= 1 <<"],
        "min_signals": 1,
        "description": "Bit manipulation and bitmask techniques",
    },
    "prefix_sum": {
        "identifier_contains": [
            "prefixsum",
            "prefix_sum",
            "cumsum",
            "cumulative",
            "runningsum",
            "running_sum",
        ],
        "min_signals": 1,
        "description": "Prefix sums and cumulative arrays",
    },
    "string_matching": {
        "identifiers": [
            "kmp",
            "rabinkarp",
            "rabin_karp",
            "rollinghash",
            "rolling_hash",
            "zfunction",
            "lps",
            "ahocorasick",
            "aho_corasick",
            "suffixarray",
            "suffix_array",
        ],
        "min_signals": 1,
        "description": "String matching algorithms",
    },
    "consistent_hashing": {
        "identifier_contains": [
            "consistenthash",
            "consistent_hash",
            "hashring",
            "hash_ring",
            "virtualnode",
            "virtual_node",
            "vnode",
            "rendezvous",
        ],
        "min_signals": 1,
        "description": "Consistent hashing and hash rings",
    },
    "lfu_cache": {
        # Substring "lfu" alone matched "...SSLFuncs" (found live in hiredis).
        "identifier_contains": ["lfucache", "lfu_cache", "lfu_"],
        "identifiers": ["lfu", "minfreq", "min_freq", "frequencymap", "freq_map"],
        "min_signals": 1,
        "description": "LFU cache with frequency buckets",
    },
    # ---- scoring policy 2.1.0 (labuladong review, docs/adr/003) ------------
    "ring_buffer": {
        # labuladong 环形数组: bounded circular storage — metrics windows,
        # log buffers, SPSC queues. Named by convention in every language.
        "identifier_contains": ["ringbuffer", "ring_buffer", "circularbuffer", "circular_buffer"],
        "identifiers": [
            "ringbuf",
            "ring_buf",
            "circbuf",
            "circ_buf",
            "cyclicbuffer",
            "cyclic_buffer",
            "head_index",
            "tail_index",
            "wrap_around",
            "write_pos",
            "read_pos",
        ],
        "text": [
            "% capacity",
            "% self.capacity",
            "% cap",
            "% len(self.buf",
            "&(cap-1)",
            "& (cap - 1)",
        ],
        "min_signals": 1,
        "description": "Ring / circular buffer for bounded windows and queues",
    },
    "randomized_sampling": {
        # labuladong 带权重的随机选择 / 游戏中的随机算法: weighted choice,
        # reservoir sampling, Fisher-Yates shuffle — load balancing, A/B,
        # telemetry sampling. Plain ``random()`` calls are not evidence.
        "identifier_contains": [
            "weighted_random",
            "weightedrandom",
            "reservoir_sampl",
            "reservoirsampl",
            "fisher_yates",
            "fisheryates",
            "knuth_shuffle",
            "alias_table",
            "aliastable",
        ],
        "identifiers": [
            "weighted_choice",
            "weightedchoice",
            "random_weighted",
            "pick_index",
            "pickindex",
            "sample_rate",
            "sampling_rate",
            "sampler",
            "shuffle_in_place",
            "cumulative_weights",
        ],
        "min_signals": 1,
        "description": "Weighted random selection, reservoir sampling, and shuffles",
    },
}

_DESIGN_BASE = {
    "resilience": {
        "identifier_contains": [
            "circuitbreaker",
            "circuit_breaker",
            "retrypolicy",
            "retry_policy",
            "backoff",
            "bulkhead",
        ],
        "identifiers": ["jitter", "maxretries", "max_retries", "halfopen", "half_open"],
        "min_signals": 1,
        "description": "Resilience: retries with backoff, circuit breakers, bulkheads",
    },
    "rate_limiting": {
        "identifier_contains": ["ratelimit", "rate_limit", "throttl"],
        "identifiers": ["tokenbucket", "token_bucket", "leakybucket", "leaky_bucket"],
        "min_signals": 1,
        "description": "Rate limiting and throttling",
    },
    "idempotency": {
        "identifier_contains": ["idempot"],
        "identifiers": ["dedupe", "deduplicate", "exactlyonce", "exactly_once"],
        "min_signals": 1,
        "description": "Idempotency keys and duplicate suppression",
    },
    "event_sourcing_cqrs": {
        "identifier_contains": [
            "eventstore",
            "event_store",
            "eventsourc",
            "cqrs",
            "commandhandler",
            "queryhandler",
            "projection",
            "aggregateroot",
        ],
        "identifiers": ["replay", "snapshot", "readmodel", "read_model"],
        "min_signals": 2,
        "description": "Event sourcing and CQRS",
    },
    "dead_letter_outbox": {
        "identifier_contains": [
            "deadletter",
            "dead_letter",
            "outbox",
            "redrive",
            "poisonmessage",
        ],
        "identifiers": ["dlq"],
        "min_signals": 1,
        "description": "Dead-letter queues, redrive, and transactional outbox",
    },
    "observability": {
        "identifier_contains": [
            "healthcheck",
            "health_check",
            "tracer",
            "startspan",
            "start_span",
        ],
        "identifiers": [
            "readiness",
            "liveness",
            "histogram",
            "traceid",
            "trace_id",
            "correlationid",
            "correlation_id",
        ],
        "min_signals": 1,
        "description": "Observability: tracing, metrics, health checks",
    },
    "concurrency": {
        "min_signals": 2,
        "description": "Concurrency and parallelism primitives",
    },
    "pagination": {
        "identifier_contains": [
            "paginat",
            "pagesize",
            "page_size",
            "nexttoken",
            "next_token",
            "pagetoken",
            "nextcursor",
            "next_cursor",
        ],
        "identifiers": ["cursor", "hasmore", "has_more"],
        "min_signals": 2,
        "description": "Cursor or page-based pagination",
    },
    "strategy_pattern": {
        "identifier_contains": ["strategy"],
        "min_signals": 1,
        "description": "Strategy pattern",
    },
    "observer_pattern": {
        "identifier_contains": [
            "observer",
            "subscriber",
            "eventemitter",
            "pubsub",
            "eventbus",
            "event_bus",
        ],
        "identifiers": ["subscribe", "unsubscribe", "publish", "notifyobservers", "emit"],
        "min_signals": 2,
        "description": "Observer / publish-subscribe pattern",
    },
    "adapter_pattern": {
        "identifier_contains": ["adapter"],
        "min_signals": 1,
        "description": "Adapter pattern",
    },
    "decorator_pattern": {
        "identifier_contains": ["decorator", "middleware", "interceptor"],
        "min_signals": 1,
        "description": "Decorator / middleware / interceptor layering",
    },
    "builder_pattern": {
        "identifier_contains": ["builder"],
        "min_signals": 1,
        "description": "Builder pattern",
    },
    # ---- scoring policy 2.1.0 (docs/adr/003) --------------------------------
    # Four production patterns the 2.0.0 catalog could not see although they
    # are the headline features of real backends (found on the author's own
    # cloudscale / fastapi-microservices-platform / wallet repositories).
    "distributed_locking": {
        "identifier_contains": [
            "fencing_token",
            "fencingtoken",
            "fenced",
            "lease_expir",
            "leaseexpir",
            "renew_lease",
            "renewlease",
            "acquire_lease",
            "acquirelease",
            "release_lease",
            "advisory_lock",
            "advisorylock",
            "redlock",
            "distributed_lock",
            "distributedlock",
            "lock_token",
            "locktoken",
            "skip_locked",
        ],
        "identifiers": ["lease", "leases", "lease_id", "lease_owner", "lock_owner", "lease_ttl"],
        "text": [
            "skip locked",
            "for update skip locked",
            "pg_try_advisory_lock",
            "pg_advisory_xact_lock",
        ],
        "min_signals": 1,
        "description": "Distributed locking: leases, fencing tokens, SKIP LOCKED, advisory locks",
    },
    "optimistic_concurrency": {
        "identifier_contains": [
            "expected_version",
            "expectedversion",
            "version_conflict",
            "versionconflict",
            "concurrency_conflict",
            "concurrencyconflict",
            "optimistic_lock",
            "optimisticlock",
            "compare_and_swap_version",
            "compareandswapversion",
            "stale_version",
            "staleversion",
        ],
        "identifiers": [
            "row_version",
            "rowversion",
            "expected_etag",
            "version_column",
            "check_version",
        ],
        "text": ["where version =", "and version =", "expected_version", "if-match"],
        "min_signals": 1,
        "description": "Optimistic concurrency: expected-version writes, ETags, compare-and-swap",
    },
    "security_hardening": {
        # Egress control (SSRF), request integrity (HMAC signing) and secret
        # handling — the defences a service adds beyond authentication.
        "identifier_contains": [
            "ssrf",
            "verify_signature",
            "verifysignature",
            "sign_payload",
            "signpayload",
            "hmac",
            "constant_time",
            "constanttime",
            "timing_safe",
            "timingsafe",
            "egress",
            "private_ip",
            "privateip",
            "link_local",
            "csrf",
        ],
        "identifiers": [
            "compare_digest",
            "hkdf",
            "signing_key",
            "signing_secret",
            "webhook_secret",
            "nonce",
            "replay_window",
            "max_body_bytes",
        ],
        "min_signals": 1,
        "description": "Security hardening: SSRF/egress control, request signing, replay guards",
    },
    "scheduling": {
        "identifier_contains": [
            "scheduler",
            "cron_expr",
            "cronexpr",
            "crontab",
            "periodic_task",
            "periodictask",
            "background_job",
            "backgroundjob",
            "job_queue",
            "jobqueue",
            "run_every",
        ],
        "identifiers": [
            "cron",
            "schedule",
            "interval_seconds",
            "next_run",
            "next_run_at",
            "heartbeat_interval",
            "at_time",
            "backfill",
        ],
        "min_signals": 2,
        "description": "Scheduling: cron, periodic and background jobs",
    },
}


# Scoring policy 2.1.0: labuladong's framework (fucking-algorithm) named
# techniques that the catalog recognised only under a narrower vocabulary.
# These anchors extend *existing* IDs and are the same in every language, so
# each catalog applies them once via :func:`extend_shared_anchors`.
SHARED_ANCHOR_EXTENSIONS = {
    "monotonic_stack": {
        "identifiers": [
            "monotonic_queue",
            "monotonicqueue",
            "mono_queue",
            "monoqueue",
            "mono_deque",
        ],
    },
    "prefix_sum": {
        "identifiers": ["diff_array", "difference_array", "differencearray", "range_update"],
    },
    "heap_priority": {
        "identifiers": [
            "min_heap",
            "max_heap",
            "minheap",
            "maxheap",
            "median_finder",
            "running_median",
        ],
    },
    "tree_structures": {
        "identifiers": [
            "treemap",
            "treeset",
            "sorteddict",
            "sortedset",
            "sortedlist",
            "btreemap",
            "btreeset",
            "skiplist",
            "skip_list",
            "red_black",
            "redblack",
            "avl",
            "ordered_map",
            "orderedmap",
        ],
    },
    "dijkstra": {
        "identifiers": ["floyd", "floyd_warshall", "floydwarshall", "spfa", "relax_edge"],
    },
    "graph_traversal": {
        "identifiers": [
            "is_bipartite",
            "isbipartite",
            "bipartite",
            "has_cycle",
            "hascycle",
            "detect_cycle",
            "detectcycle",
            "flood_fill",
            "floodfill",
            "num_islands",
        ],
    },
    "interval_operations": {
        "identifiers": [
            "sweep_line",
            "sweepline",
            "meeting_rooms",
            "min_meeting_rooms",
            "interval_schedule",
        ],
    },
    "string_matching": {
        "identifiers": [
            "rabin_karp",
            "rabinkarp",
            "rolling_hash",
            "rollinghash",
            "kmp",
            "z_function",
        ],
    },
}


def extend_shared_anchors(catalog: dict) -> dict:
    """Append :data:`SHARED_ANCHOR_EXTENSIONS` to a language DSA catalog in place."""
    for name, extra in SHARED_ANCHOR_EXTENSIONS.items():
        spec = catalog.get(name)
        if spec is None:
            continue
        for key, values in extra.items():
            existing = list(spec.get(key, []))
            spec[key] = existing + [value for value in values if value not in existing]
    return catalog


def production_design_patterns(
    imports: dict[str, list[str]] | None = None,
    identifiers: dict[str, list[str]] | None = None,
    text: dict[str, list[str]] | None = None,
    min_signals: dict[str, int] | None = None,
) -> dict:
    """Return the shared design specs merged with one language's idioms."""
    merged = {}
    for name, base in _DESIGN_BASE.items():
        spec = {
            key: list(value) if isinstance(value, list) else value for key, value in base.items()
        }
        for source, key in ((imports, "imports"), (identifiers, "identifiers"), (text, "text")):
            extra = (source or {}).get(name)
            if extra:
                spec[key] = list(spec.get(key, [])) + list(extra)
        if min_signals and name in min_signals:
            spec["min_signals"] = min_signals[name]
        merged[name] = spec
    return merged
