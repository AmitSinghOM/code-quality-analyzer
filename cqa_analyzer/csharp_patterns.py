"""C#/.NET DSA and System Design pattern definitions.

Mirrors the Python pattern semantics with .NET idioms. Signal types are
matched case-insensitively against blanked C# source:

  identifiers          exact extracted identifier: type/namespace
                       declarations, attribute names, generic type uses,
                       ``new`` targets, and call sites recorded as
                       ``qualifier``, ``member``, and ``qualifier.member``
  identifier_contains  substring of an extracted identifier
  text                 substring of the source with comments and all
                       string forms blanked out
  imports              substring of a ``using`` namespace

Every pattern ID here MUST also exist in the Python pattern catalog
(regression-locked in tests). Generic terms keep ``min_signals``
corroboration.
"""

CSHARP_DSA_PATTERNS = {
    "hash_map": {
        "identifiers": [
            "dictionary", "concurrentdictionary", "sorteddictionary",
            "hashtable",
        ],
        "min_signals": 1,
        "description": "Hash-based data structures for O(1) lookups",
    },
    "set_operations": {
        "identifiers": [
            "hashset", "sortedset", "intersectwith", "unionwith",
            "exceptwith", "issubsetof",
        ],
        "min_signals": 1,
        "description": "Set operations for unique elements and fast membership",
    },
    "sorting": {
        "identifiers": [
            "orderby", "orderbydescending", "array.sort", "sort", "comparer",
            "icomparer", "icomparable",
        ],
        "min_signals": 1,
        "description": "Sorting algorithms and ordered operations",
    },
    "binary_search": {
        "identifiers": ["binarysearch", "array.binarysearch"],
        "text": ["mid =", "lo, hi", "low, high", ">> 1"],
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
        "identifiers": ["linkedlist", "linkedlistnode", "listnode"],
        "min_signals": 1,
        "description": "Linked list structures",
    },
    "queue_stack": {
        "identifiers": [
            "queue", "stack", "concurrentqueue", "enqueue", "dequeue",
            "push", "pop",
        ],
        "min_signals": 2,
        "description": "Queue and stack disciplines",
    },
    "heap_priority": {
        "identifiers": ["priorityqueue", "minheap", "maxheap"],
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
            "unionfind", "disjointset", "find", "union", "parent", "rank",
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
        "identifiers": ["left", "right", "slow", "fast", "twopointer"],
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
        "identifiers": ["lru", "lrucache"],
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

CSHARP_DESIGN_PATTERNS = {
    "api_design": {
        "imports": ["microsoft.aspnetcore", "grpc.core", "grpc.aspnetcore"],
        "identifiers": [
            "apicontroller", "controllerbase", "httpget", "httppost",
            "httpput", "httpdelete", "mapget", "mappost", "mapput",
            "mapdelete", "route",
        ],
        "min_signals": 1,
        "description": "HTTP/RPC API design",
    },
    "database_orm": {
        "imports": [
            "microsoft.entityframeworkcore", "dapper", "npgsql",
            "microsoft.data.sqlclient", "system.data.sqlclient",
            "mongodb.driver", "nhibernate",
        ],
        "identifiers": ["dbcontext", "dbset"],
        "min_signals": 1,
        "description": "Database access layers",
    },
    "caching": {
        "imports": [
            "microsoft.extensions.caching", "stackexchange.redis",
            "lazycache",
        ],
        "identifiers": ["imemorycache", "idistributedcache", "cache"],
        "min_signals": 1,
        "description": "Caching layers",
    },
    "message_queue": {
        "imports": [
            "masstransit", "confluent.kafka", "rabbitmq.client",
            "azure.messaging.servicebus", "nservicebus", "amazon.sqs",
        ],
        "identifiers": ["kafka", "rabbitmq", "servicebus"],
        "min_signals": 1,
        "description": "Message queue integration",
    },
    "factory_pattern": {
        "identifier_contains": ["factory"],
        "min_signals": 1,
        "description": "Factory construction pattern",
    },
    "singleton_pattern": {
        "identifiers": ["getinstance", "addsingleton", "lazy"],
        "identifier_contains": ["singleton"],
        "min_signals": 1,
        "description": "Singleton pattern",
    },
    "dependency_injection": {
        "imports": ["microsoft.extensions.dependencyinjection", "autofac"],
        "identifiers": [
            "iservicecollection", "addscoped", "addtransient", "addsingleton",
            "fromservices",
        ],
        "min_signals": 2,
        "description": "Dependency injection frameworks",
    },
    "error_handling": {
        "text": ["try", "catch ("],
        "identifiers": ["exceptionfilter", "problemdetails"],
        "min_signals": 2,
        "description": "Structured error handling",
    },
    "logging": {
        "imports": ["serilog", "nlog", "microsoft.extensions.logging"],
        "identifiers": [
            "ilogger", "logger", "loginformation", "logerror", "logwarning",
            "log.information", "log.error", "log.warning",
        ],
        "min_signals": 2,
        "description": "Structured logging",
    },
    "authentication": {
        "imports": [
            "microsoft.aspnetcore.authentication",
            "microsoft.aspnetcore.authorization",
            "system.identitymodel.tokens.jwt", "microsoft.identitymodel",
            "duende.identityserver", "microsoft.aspnetcore.identity",
        ],
        "identifiers": ["authorize", "jwt", "oauth", "claimsprincipal"],
        "min_signals": 1,
        "description": "Authentication and authorization",
    },
    "testing": {
        "imports": [
            "xunit", "nunit.framework", "microsoft.visualstudio.testtools",
            "moq", "nsubstitute", "fluentassertions",
        ],
        "identifiers": ["fact", "theory", "testmethod", "test", "mock"],
        "min_signals": 2,
        "description": "Testing discipline",
    },
    "microservices": {
        "imports": ["grpc.net.client", "refit", "polly"],
        "identifiers": [
            "ihttpclientfactory", "httpclient", "client", "service",
        ],
        "min_signals": 2,
        "description": "Service clients and RPC boundaries",
    },
    "repository_pattern": {
        "identifier_contains": ["repository"],
        "identifiers": ["getbyidasync", "getbyid", "saveasync", "save"],
        "min_signals": 2,
        "description": "Repository data-access pattern",
    },
    "config_management": {
        "imports": ["microsoft.extensions.configuration", "microsoft.extensions.options"],
        "identifiers": [
            "iconfiguration", "ioptions", "getenvironmentvariable",
            "appsettings", "configuration",
        ],
        "min_signals": 2,
        "description": "Configuration management",
    },
}
