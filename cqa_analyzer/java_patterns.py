"""Java DSA and System Design pattern definitions.

Mirrors the Python pattern semantics with Java idioms. Signal types are
matched case-insensitively against blanked Java source:

  identifiers          exact extracted identifier: class/interface/enum/
                       record declarations, annotation names, generic
                       type uses, ``new`` targets, and call sites recorded
                       as ``qualifier``, ``member``, and ``qualifier.member``
  identifier_contains  substring of an extracted identifier
  text                 substring of the source with comments and string
                       literals blanked out
  imports              substring of an imported Java package path

Every pattern ID here MUST also exist in the Python pattern catalog:
the rater resolves scoring weights from the Python definitions
(regression-locked in tests). Identifier extraction is regex-based and
approximate, so generic terms keep the same ``min_signals``
corroboration discipline as the other languages.
"""

JAVA_DSA_PATTERNS = {
    "hash_map": {
        "identifiers": [
            "hashmap", "linkedhashmap", "treemap", "concurrenthashmap",
            "enummap",
        ],
        "min_signals": 1,
        "description": "Hash-based data structures for O(1) lookups",
    },
    "set_operations": {
        "identifiers": [
            "hashset", "treeset", "linkedhashset", "enumset",
            "retainall", "removeall",
        ],
        "min_signals": 1,
        "description": "Set operations for unique elements and fast membership",
    },
    "sorting": {
        "identifiers": [
            "collections.sort", "arrays.sort", "comparator", "sorted",
            "comparing", "thencomparing",
        ],
        "min_signals": 1,
        "description": "Sorting algorithms and ordered operations",
    },
    "binary_search": {
        "identifiers": [
            "collections.binarysearch", "arrays.binarysearch", "binarysearch",
        ],
        "text": ["mid =", "lo, hi", "low, high", ">>> 1"],
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
        "identifiers": ["treenode", "binarytree", "btree", "avltree"],
        "min_signals": 1,
        "description": "Tree data structures",
    },
    "linked_list": {
        "identifiers": ["linkedlist", "listnode"],
        "min_signals": 1,
        "description": "Linked list structures",
    },
    "queue_stack": {
        "identifiers": [
            "arraydeque", "deque", "stack", "queue", "offer", "poll",
            "push", "pop",
        ],
        "min_signals": 2,
        "description": "Queue and stack disciplines",
    },
    "heap_priority": {
        "identifiers": [
            "priorityqueue", "priorityblockingqueue", "minheap", "maxheap",
        ],
        "min_signals": 1,
        "description": "Heaps and priority queues",
    },
    "trie": {
        "identifiers": ["trie", "trienode", "prefixtree"],
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
            "topologicalsort", "toposort", "topological", "indegree",
        ],
        "min_signals": 1,
        "description": "Topological ordering of dependencies",
    },
    "sliding_window": {
        "identifiers": ["slidingwindow"],
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
        "identifiers": ["segmenttree"],
        "min_signals": 1,
        "description": "Segment tree range structures",
    },
    "fenwick_tree": {
        "identifiers": ["fenwick", "fenwicktree", "binaryindexedtree"],
        "min_signals": 1,
        "description": "Fenwick / Binary Indexed Tree structures",
    },
    "lru_cache_manual": {
        "identifiers": ["lru", "lrucache", "removeeldestentry"],
        "min_signals": 1,
        "description": "Manual LRU cache implementation",
    },
    "bloom_filter": {
        "identifiers": ["bloomfilter"],
        "min_signals": 1,
        "description": "Bloom filter probabilistic membership",
    },
    "dijkstra": {
        "identifiers": ["dijkstra", "shortestpath", "bellmanford", "astar"],
        "min_signals": 1,
        "description": "Shortest path algorithms",
    },
    "minimum_spanning_tree": {
        "identifiers": ["kruskal", "prim", "spanningtree"],
        "min_signals": 1,
        "description": "Minimum spanning tree algorithms",
    },
    "monotonic_stack": {
        "identifiers": ["monotonicstack", "monotonic"],
        "min_signals": 1,
        "description": "Monotonic stack technique",
    },
    "interval_operations": {
        "identifiers": ["interval", "intervals", "mergeintervals"],
        "min_signals": 1,
        "description": "Interval merge and overlap operations",
    },
}

JAVA_DESIGN_PATTERNS = {
    "api_design": {
        "imports": [
            "org.springframework.web", "javax.ws.rs", "jakarta.ws.rs",
            "io.javalin", "io.micronaut.http", "io.vertx.ext.web",
            "io.grpc", "spark.spark",
        ],
        "identifiers": [
            "restcontroller", "requestmapping", "getmapping", "postmapping",
            "putmapping", "deletemapping",
        ],
        "min_signals": 1,
        "description": "HTTP/RPC API design",
    },
    "database_orm": {
        "imports": [
            "jakarta.persistence", "javax.persistence", "org.hibernate",
            "java.sql", "org.jooq", "org.springframework.data",
            "org.springframework.jdbc", "org.mybatis",
        ],
        "min_signals": 1,
        "description": "Database access layers",
    },
    "caching": {
        "imports": [
            "com.github.benmanes.caffeine", "redis.clients", "io.lettuce",
            "org.springframework.cache", "org.ehcache", "net.sf.ehcache",
        ],
        "identifiers": ["cacheable", "cacheevict", "cache"],
        "min_signals": 1,
        "description": "Caching layers",
    },
    "message_queue": {
        "imports": [
            "org.apache.kafka", "javax.jms", "jakarta.jms", "com.rabbitmq",
            "org.springframework.kafka", "org.springframework.amqp",
            "software.amazon.awssdk.services.sqs",
        ],
        "identifiers": ["kafkalistener", "jmslistener", "rabbitlistener"],
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
        "imports": [
            "org.springframework.beans.factory.annotation", "javax.inject",
            "jakarta.inject", "com.google.inject", "dagger",
        ],
        "identifiers": ["autowired", "inject", "component", "service"],
        "min_signals": 2,
        "description": "Dependency injection frameworks",
    },
    "error_handling": {
        "text": ["try {", "catch ("],
        "identifiers": ["controlleradvice", "exceptionhandler"],
        "min_signals": 2,
        "description": "Structured error handling",
    },
    "logging": {
        "imports": [
            "org.slf4j", "org.apache.logging.log4j", "java.util.logging",
            "ch.qos.logback", "org.apache.log4j",
        ],
        "identifiers": ["logger", "slf4j"],
        "min_signals": 2,
        "description": "Structured logging",
    },
    "authentication": {
        "imports": [
            "org.springframework.security", "io.jsonwebtoken", "com.auth0",
            "com.nimbusds", "org.keycloak",
        ],
        "identifiers": [
            "jwt", "oauth", "authenticate", "bcrypt", "preauthorize",
        ],
        "min_signals": 1,
        "description": "Authentication and authorization",
    },
    "testing": {
        "imports": [
            "org.junit", "org.mockito", "org.testng", "org.assertj",
            "org.hamcrest",
        ],
        "identifiers": ["test", "mock", "assertequals", "asserttrue"],
        "min_signals": 2,
        "description": "Testing discipline",
    },
    "microservices": {
        "imports": [
            "io.grpc", "org.springframework.cloud", "feign",
            "org.springframework.web.reactive.function.client",
        ],
        "identifiers": ["feignclient", "client", "service", "endpoint"],
        "min_signals": 2,
        "description": "Service clients and RPC boundaries",
    },
    "repository_pattern": {
        "identifier_contains": ["repository"],
        "identifiers": ["findbyid", "findall", "save"],
        "min_signals": 2,
        "description": "Repository data-access pattern",
    },
    "config_management": {
        "imports": [
            "org.springframework.boot.context.properties",
            "com.typesafe.config", "org.apache.commons.configuration",
        ],
        "identifiers": [
            "configurationproperties", "system.getenv", "config",
            "configuration",
        ],
        "min_signals": 2,
        "description": "Configuration management",
    },
}
