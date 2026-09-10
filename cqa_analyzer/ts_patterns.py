"""TypeScript/JavaScript DSA and System Design pattern definitions.

These mirror the Python pattern semantics with TS/JS idioms. Signal
types are matched case-insensitively against blanked source:

  identifiers          exact extracted identifier: declared function/
                       class/interface/enum/const/let/var names, plus
                       selector call sites recorded as ``qualifier``,
                       ``member``, and ``qualifier.member``
  identifier_contains  substring of an extracted identifier
  text                 substring of the source with comments, strings,
                       and template literals blanked out
  imports              substring of an imported module specifier

Every pattern ID here MUST also exist in the Python pattern catalog:
the rater resolves scoring weights from the Python definitions, so an
ID unique to this file would silently contribute nothing
(regression-locked in tests). Identifier extraction is regex-based and
approximate, so generic terms keep the same ``min_signals``
corroboration discipline as Python and Go.

React/Vue component idioms have no shared catalog ID yet; adding a UI
pattern is a cross-language scoring-policy change tracked in the
roadmap.
"""

from .production_patterns import PRODUCTION_DSA_PATTERNS, production_design_patterns

TS_DSA_PATTERNS = {
    "hash_map": {
        "text": ["new map(", "new map<"],
        "identifiers": ["hashmap", "weakmap"],
        "min_signals": 1,
        "description": "Hash-based data structures for O(1) lookups",
    },
    "set_operations": {
        "text": ["new set(", "new set<"],
        "identifiers": ["intersection", "difference", "issubset"],
        "min_signals": 1,
        "description": "Set operations for unique elements and fast membership",
    },
    "sorting": {
        "identifiers": ["sort", "tosorted", "localecompare"],
        "min_signals": 1,
        "description": "Sorting algorithms and ordered operations",
    },
    "binary_search": {
        "identifiers": ["binarysearch", "bisect"],
        "text": ["mid =", "lo, hi", "low, high"],
        "min_signals": 2,
        "description": "Binary search for O(log n) lookups",
    },
    "graph_traversal": {
        "identifiers": [
            "bfs", "dfs", "visited", "neighbors", "neighbours",
            "adjacency", "graph",
        ],
        "min_signals": 2,
        "description": "Graph traversal algorithms (BFS/DFS)",
    },
    "dynamic_programming": {
        "identifiers": ["memo", "memoize", "memoization", "dp"],
        "text": ["dp["],
        "min_signals": 1,
        "description": "Dynamic programming and memoization",
    },
    "tree_structures": {
        "identifiers": ["treenode", "binarytree", "btree", "avl"],
        "min_signals": 1,
        "description": "Tree data structures",
    },
    "linked_list": {
        "identifiers": ["linkedlist", "listnode"],
        "min_signals": 1,
        "description": "Linked list structures",
    },
    "queue_stack": {
        "identifiers": ["enqueue", "dequeue", "deque"],
        "min_signals": 1,
        "description": "Queue and stack disciplines",
    },
    "heap_priority": {
        "identifiers": [
            "heap", "minheap", "maxheap", "priorityqueue",
            "priority_queue", "heappush", "heappop",
        ],
        "min_signals": 1,
        "description": "Heaps and priority queues",
    },
    "trie": {
        "identifiers": ["trie", "prefixtree"],
        "min_signals": 1,
        "description": "Trie / prefix tree structures",
    },
    "segment_tree": {
        "identifiers": ["segmenttree", "segtree"],
        "min_signals": 1,
        "description": "Segment tree for range queries",
    },
    "fenwick_tree": {
        "identifiers": ["fenwick", "fenwicktree", "binaryindexedtree"],
        "min_signals": 1,
        "description": "Fenwick tree (Binary Indexed Tree)",
    },
    "minimum_spanning_tree": {
        "identifiers": ["kruskal", "prim", "spanningtree", "minimumspanningtree"],
        "min_signals": 1,
        "description": "Minimum spanning tree algorithms",
    },
    "union_find": {
        "identifiers": [
            "unionfind", "union_find", "disjointset", "disjoint_set",
            "findparent", "findroot", "find_parent", "find_root",
            "pathcompression", "unionbyrank", "union_by_rank",
        ],
        "min_signals": 2,
        "description": "Union-Find / Disjoint Set structures",
    },
    "topological_sort": {
        "identifiers": [
            "topologicalsort", "toposort", "topological",
            "indegree", "in_degree",
        ],
        "min_signals": 1,
        "description": "Topological ordering of dependencies",
    },
    "sliding_window": {
        "identifiers": ["slidingwindow", "sliding_window"],
        "min_signals": 1,
        "description": "Sliding window technique",
    },
    "two_pointers": {
        "identifiers": [
            "twopointer", "twopointers", "leftpointer", "rightpointer",
            "slowpointer", "fastpointer", "tortoisehare", "two_pointers",
            "left_pointer", "right_pointer",
        ],
        "min_signals": 2,
        "description": "Two-pointer technique",
    },
    "backtracking": {
        "identifiers": ["backtrack", "backtracking"],
        "min_signals": 1,
        "description": "Backtracking search",
    },
    "lru_cache_manual": {
        "identifiers": ["lru", "lrucache"],
        "imports": ["lru-cache"],
        "min_signals": 1,
        "description": "LRU cache implementation or library",
    },
    "bloom_filter": {
        "identifiers": ["bloomfilter", "bloom_filter"],
        "min_signals": 1,
        "description": "Bloom filter probabilistic membership",
    },
    "dijkstra": {
        "identifiers": [
            "dijkstra", "shortestpath", "shortest_path",
            "bellmanford", "astar",
        ],
        "min_signals": 1,
        "description": "Shortest path algorithms",
    },
    "interval_operations": {
        "identifiers": [
            "interval", "intervals", "mergeintervals", "merge_intervals",
        ],
        "min_signals": 1,
        "description": "Interval merge and overlap operations",
    },
    "monotonic_stack": {
        "identifiers": ["monotonicstack", "monotonic_stack", "monotonic"],
        "min_signals": 1,
        "description": "Monotonic stack technique",
    },
}

TS_DESIGN_PATTERNS = {
    "api_design": {
        "imports": [
            "express", "fastify", "koa", "hono", "@nestjs/common",
            "next/server", "@trpc/server", "apollo-server", "graphql",
        ],
        "identifiers": [
            "app.get", "app.post", "app.use", "router.get", "router.post",
        ],
        "min_signals": 1,
        "description": "HTTP/RPC API design",
    },
    "database_orm": {
        "imports": [
            "@prisma/client", "typeorm", "sequelize", "mongoose",
            "drizzle-orm", "knex", "better-sqlite3", "mysql2", "pg",
        ],
        "min_signals": 1,
        "description": "Database access layers",
    },
    "caching": {
        "imports": [
            "redis", "ioredis", "lru-cache", "node-cache",
            "@tanstack/react-query", "swr",
        ],
        "identifiers": ["memoize", "ttl", "stale", "revalidate"],
        "min_signals": 1,
        "description": "Caching layers",
    },
    "message_queue": {
        "imports": [
            "kafkajs", "amqplib", "bullmq", "bull", "nats",
            "@aws-sdk/client-sqs", "rascal",
        ],
        "identifiers": ["kafka", "rabbitmq", "amqp"],
        "min_signals": 1,
        "description": "Message queue integration",
    },
    "factory_pattern": {
        "identifier_contains": ["factory"],
        "min_signals": 1,
        "description": "Factory construction pattern",
    },
    "singleton_pattern": {
        "identifiers": ["getinstance"],
        "identifier_contains": ["singleton"],
        "min_signals": 1,
        "description": "Singleton pattern",
    },
    "dependency_injection": {
        "imports": ["inversify", "tsyringe", "awilix", "@nestjs/common"],
        "identifiers": ["injectable", "inject"],
        "min_signals": 2,
        "description": "Dependency injection frameworks",
    },
    "error_handling": {
        "text": ["try {", "catch ("],
        "identifiers": ["apierror", "httperror"],
        "min_signals": 2,
        "description": "Structured error handling",
    },
    "logging": {
        "imports": ["winston", "pino", "bunyan", "log4js"],
        "identifiers": ["logger"],
        "min_signals": 2,
        "description": "Structured logging",
    },
    "authentication": {
        "imports": [
            "jsonwebtoken", "next-auth", "passport", "bcrypt",
            "bcryptjs", "jose", "@auth/",
        ],
        "identifiers": ["jwt", "oauth", "authenticate", "authorization"],
        "min_signals": 1,
        "description": "Authentication and authorization",
    },
    "testing": {
        "imports": [
            "vitest", "@testing-library", "@playwright/test",
            "cypress", "jest", "mocha", "chai",
            # Node's built-in runner (google/zx, many CLIs).
            "node:test", "node:assert", "bun:test", "uvu", "ava", "tap",
        ],
        "identifiers": ["describe", "expect", "test", "assert"],
        "min_signals": 2,
        "description": "Testing discipline",
    },
    "microservices": {
        "imports": ["@grpc/grpc-js", "@aws-sdk/"],
        "identifiers": ["client", "service", "endpoint"],
        "min_signals": 2,
        "description": "Service clients and RPC boundaries",
    },
    "repository_pattern": {
        "identifier_contains": ["repository"],
        "identifiers": ["findbyid", "getbyid", "save"],
        "min_signals": 2,
        "description": "Repository data-access pattern",
    },
    "config_management": {
        "imports": ["dotenv", "convict", "envalid"],
        "text": ["process.env"],
        "identifiers": ["config", "configuration"],
        "min_signals": 2,
        "description": "Configuration management",
    },
}

# Scoring policy 2.0.0: production-systems and GoF patterns, merged from the
# shared specs with the JavaScript ecosystem's libraries and primitives.
TS_DSA_PATTERNS.update(PRODUCTION_DSA_PATTERNS)
TS_DESIGN_PATTERNS.update(production_design_patterns(
    imports={
        "resilience": [
            "cockatiel", "opossum", "p-retry", "async-retry",
            "exponential-backoff", "retry-axios",
        ],
        "rate_limiting": [
            "express-rate-limit", "rate-limiter-flexible", "bottleneck",
            "p-throttle", "@upstash/ratelimit",
        ],
        "observability": ["@opentelemetry", "prom-client", "@sentry", "dd-trace"],
        "event_sourcing_cqrs": ["@nestjs/cqrs"],
        "concurrency": ["worker_threads", "p-limit", "p-queue", "p-map", "piscina"],
    },
    identifiers={
        "concurrency": [
            "promise.all", "promise.allsettled", "promise.race", "workerpool",
        ],
        "decorator_pattern": ["app.use"],
    },
))
