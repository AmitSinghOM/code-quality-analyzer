"""Go DSA and System Design pattern definitions.

These mirror the Python pattern semantics with Go idioms. Signal types
are matched case-insensitively against blanked Go source:

  identifiers          exact extracted identifier: declared func/type/var/
                       const or short-declaration names, plus selector call
                       sites recorded as ``qualifier``, ``member``, and
                       ``qualifier.member``
  identifier_contains  substring of an extracted identifier
  text                 substring of the source with comments and string
                       literals blanked out
  imports              substring of an imported Go module path

Every pattern ID here MUST also exist in the Python pattern catalog:
the rater resolves scoring weights from the Python definitions, so a
Go-only ID would silently contribute nothing (regression-locked in
tests). Go identifier extraction is regex-based and approximate, so
generic terms keep the same ``min_signals`` corroboration discipline
as Python — a lone ``visited`` is still not a graph traversal.

Go has no scored equivalent for goroutine/channel worker-pool patterns
yet because the shared scoring catalog has no such ID; adding one is a
cross-language scoring-policy change tracked in the roadmap.
"""

from .production_patterns import PRODUCTION_DSA_PATTERNS, production_design_patterns

GO_DSA_PATTERNS = {
    "set_operations": {
        "text": ["]struct{}{"],
        "identifiers": ["stringset", "intset", "hashset"],
        "min_signals": 1,
        "description": "Set idioms (map[T]struct{}) for membership tests",
    },
    "sorting": {
        "identifiers": [
            "sort.slice", "sort.sort", "sort.slicestable",
            "sort.ints", "sort.strings",
        ],
        "imports": ["sort"],
        "min_signals": 1,
        "description": "Sorting algorithms and ordered operations",
    },
    "binary_search": {
        "identifiers": ["sort.search", "binarysearch", "binary_search"],
        "text": ["mid :=", "lo, hi", "low, high"],
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
        "identifiers": ["memo", "memoization", "dp"],
        "text": ["dp["],
        "min_signals": 1,
        "description": "Dynamic programming and memoization",
    },
    "tree_structures": {
        "identifiers": [
            "treenode", "binarytree", "btree", "avl", "redblack",
        ],
        "min_signals": 1,
        "description": "Tree data structures",
    },
    "linked_list": {
        "imports": ["container/list"],
        "identifiers": ["linkedlist", "listnode"],
        "min_signals": 1,
        "description": "Linked list structures",
    },
    "queue_stack": {
        "identifiers": [
            "enqueue", "dequeue", "pushback", "popfront", "stack",
        ],
        "imports": ["container/list"],
        "min_signals": 2,
        "description": "Queue and stack disciplines",
    },
    "heap_priority": {
        "imports": ["container/heap"],
        "identifiers": [
            "heap.push", "heap.pop", "heap.init", "heap.fix",
            "priorityqueue", "priority_queue",
        ],
        "min_signals": 1,
        "description": "Heaps and priority queues",
    },
    "trie": {
        "identifiers": ["trie", "prefixtree", "prefix_tree"],
        "min_signals": 1,
        "description": "Trie / prefix tree structures",
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
    "segment_tree": {
        "identifiers": ["segmenttree", "segment_tree"],
        "min_signals": 1,
        "description": "Segment tree range structures",
    },
    "fenwick_tree": {
        "identifiers": ["fenwick", "binaryindexedtree"],
        "min_signals": 1,
        "description": "Fenwick / Binary Indexed Tree structures",
    },
    "lru_cache_manual": {
        "identifiers": ["lru", "lrucache"],
        "imports": ["container/list"],
        "min_signals": 2,
        "description": "Manual LRU cache implementation",
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
    "minimum_spanning_tree": {
        "identifiers": ["kruskal", "prim", "mst", "spanningtree"],
        "min_signals": 1,
        "description": "Minimum spanning tree algorithms",
    },
    "monotonic_stack": {
        "identifiers": ["monotonicstack", "monotonic_stack", "monotonic"],
        "min_signals": 1,
        "description": "Monotonic stack technique",
    },
    "interval_operations": {
        "identifiers": [
            "interval", "intervals", "mergeintervals", "merge_intervals",
        ],
        "min_signals": 1,
        "description": "Interval merge and overlap operations",
    },
}

GO_DESIGN_PATTERNS = {
    "api_design": {
        "imports": [
            "net/http", "github.com/gin-gonic", "github.com/go-chi",
            "github.com/labstack/echo", "github.com/gorilla/mux",
            "google.golang.org/grpc",
        ],
        "identifiers": ["handlefunc", "servehttp"],
        "min_signals": 1,
        "description": "HTTP/RPC API design",
    },
    "database_orm": {
        "imports": [
            "database/sql", "gorm.io", "github.com/jmoiron/sqlx",
            "github.com/jackc/pgx", "go.mongodb.org",
        ],
        "min_signals": 1,
        "description": "Database access layers",
    },
    "caching": {
        "imports": [
            "github.com/redis", "github.com/go-redis",
            "github.com/patrickmn/go-cache",
        ],
        "identifiers": ["cache", "ttl"],
        "min_signals": 1,
        "description": "Caching layers",
    },
    "message_queue": {
        "imports": [
            "github.com/segmentio/kafka", "github.com/confluentinc",
            "github.com/rabbitmq", "github.com/nats-io",
            "github.com/streadway/amqp", "cloud.google.com/go/pubsub",
        ],
        "identifiers": ["kafka", "rabbitmq", "amqp", "pubsub"],
        "min_signals": 1,
        "description": "Message queue integration",
    },
    "factory_pattern": {
        "identifier_contains": ["factory"],
        "min_signals": 1,
        "description": "Factory construction pattern",
    },
    "singleton_pattern": {
        "identifiers": ["sync.once", "once.do"],
        "min_signals": 1,
        "description": "Singleton via sync.Once",
    },
    "dependency_injection": {
        "imports": [
            "github.com/google/wire", "go.uber.org/fx", "go.uber.org/dig",
        ],
        "identifiers": ["inject"],
        "identifier_contains": ["injector"],
        "min_signals": 1,
        "description": "Dependency injection frameworks",
    },
    "error_handling": {
        "text": ["if err != nil"],
        "identifiers": ["errors.is", "errors.as", "fmt.errorf"],
        "imports": ["errors"],
        "min_signals": 2,
        "description": "Structured error handling",
    },
    "logging": {
        "imports": [
            "log/slog", "go.uber.org/zap", "github.com/rs/zerolog",
            "github.com/sirupsen/logrus", "log",
        ],
        "identifiers": ["logger", "logging"],
        "min_signals": 2,
        "description": "Structured logging",
    },
    "authentication": {
        "imports": [
            "golang.org/x/crypto", "github.com/golang-jwt",
            "crypto/hmac", "crypto/subtle",
        ],
        "identifiers": [
            "jwt", "oauth", "authenticate", "authorization", "bcrypt",
        ],
        "min_signals": 1,
        "description": "Authentication and authorization",
    },
    "testing": {
        "imports": ["testing", "github.com/stretchr/testify"],
        "identifiers": ["t.run", "assert", "require", "mock"],
        "min_signals": 2,
        "description": "Testing discipline",
    },
    "microservices": {
        "imports": ["google.golang.org/grpc", "net/rpc"],
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
        "imports": [
            "github.com/spf13/viper", "github.com/kelseyhightower/envconfig",
            "github.com/joho/godotenv",
        ],
        "identifiers": ["os.getenv", "config", "configuration"],
        "min_signals": 2,
        "description": "Configuration management",
    },
}

# Scoring policy 2.0.0: production-systems and GoF patterns, merged from the
# shared specs with Go's idiomatic libraries and primitives.
GO_DSA_PATTERNS.update(PRODUCTION_DSA_PATTERNS)
GO_DESIGN_PATTERNS.update(production_design_patterns(
    imports={
        "resilience": [
            "github.com/sony/gobreaker", "github.com/cenkalti/backoff",
            "github.com/avast/retry-go", "github.com/failsafe-go",
            "github.com/eapache/go-resiliency",
        ],
        "rate_limiting": [
            "golang.org/x/time/rate", "github.com/ulule/limiter",
            "github.com/uber-go/ratelimit",
        ],
        "observability": [
            "go.opentelemetry.io", "github.com/prometheus/client_golang",
            "github.com/getsentry/sentry-go", "github.com/datadog/dd-trace-go",
        ],
        "concurrency": [
            "golang.org/x/sync/errgroup", "golang.org/x/sync/semaphore",
        ],
    },
    identifiers={
        "concurrency": [
            "waitgroup", "sync.waitgroup", "errgroup", "sync.mutex",
            "sync.rwmutex", "mutex", "semaphore",
        ],
        "decorator_pattern": ["handlerfunc"],
    },
    text={"concurrency": ["go func", "select {", "<-"]},
    min_signals={"concurrency": 1},
))
