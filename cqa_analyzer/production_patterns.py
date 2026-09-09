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
            "prefixsum", "prefix_sum", "cumsum", "cumulative", "runningsum",
            "running_sum",
        ],
        "min_signals": 1,
        "description": "Prefix sums and cumulative arrays",
    },
    "string_matching": {
        "identifiers": [
            "kmp", "rabinkarp", "rabin_karp", "rollinghash", "rolling_hash",
            "zfunction", "lps", "ahocorasick", "aho_corasick", "suffixarray",
            "suffix_array",
        ],
        "min_signals": 1,
        "description": "String matching algorithms",
    },
    "consistent_hashing": {
        "identifier_contains": [
            "consistenthash", "consistent_hash", "hashring", "hash_ring",
            "virtualnode", "virtual_node", "vnode", "rendezvous",
        ],
        "min_signals": 1,
        "description": "Consistent hashing and hash rings",
    },
    "lfu_cache": {
        "identifier_contains": ["lfu"],
        "identifiers": ["minfreq", "min_freq", "frequencymap", "freq_map"],
        "min_signals": 1,
        "description": "LFU cache with frequency buckets",
    },
}

_DESIGN_BASE = {
    "resilience": {
        "identifier_contains": [
            "circuitbreaker", "circuit_breaker", "retrypolicy", "retry_policy",
            "backoff", "bulkhead",
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
            "eventstore", "event_store", "eventsourc", "cqrs", "commandhandler",
            "queryhandler", "projection", "aggregateroot",
        ],
        "identifiers": ["replay", "snapshot", "readmodel", "read_model"],
        "min_signals": 2,
        "description": "Event sourcing and CQRS",
    },
    "dead_letter_outbox": {
        "identifier_contains": [
            "deadletter", "dead_letter", "outbox", "redrive", "poisonmessage",
        ],
        "identifiers": ["dlq"],
        "min_signals": 1,
        "description": "Dead-letter queues, redrive, and transactional outbox",
    },
    "observability": {
        "identifier_contains": [
            "healthcheck", "health_check", "tracer", "startspan", "start_span",
        ],
        "identifiers": [
            "readiness", "liveness", "histogram", "traceid", "trace_id",
            "correlationid", "correlation_id",
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
            "paginat", "pagesize", "page_size", "nexttoken", "next_token",
            "pagetoken", "nextcursor", "next_cursor",
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
            "observer", "subscriber", "eventemitter", "pubsub", "eventbus",
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
}


def production_design_patterns(
    imports: dict[str, list[str]] | None = None,
    identifiers: dict[str, list[str]] | None = None,
    text: dict[str, list[str]] | None = None,
    min_signals: dict[str, int] | None = None,
) -> dict:
    """Return the shared design specs merged with one language's idioms."""
    merged = {}
    for name, base in _DESIGN_BASE.items():
        spec = {key: list(value) if isinstance(value, list) else value
                for key, value in base.items()}
        for source, key in ((imports, "imports"), (identifiers, "identifiers"),
                            (text, "text")):
            extra = (source or {}).get(name)
            if extra:
                spec[key] = list(spec.get(key, [])) + list(extra)
        if min_signals and name in min_signals:
            spec["min_signals"] = min_signals[name]
        merged[name] = spec
    return merged
