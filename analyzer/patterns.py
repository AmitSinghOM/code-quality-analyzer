"""DSA and System Design pattern definitions.

Signal types, all matched case-insensitively:

  identifiers          exact identifier from the AST (name, attribute, def,
                       class, argument, import alias)
  identifier_contains  substring of an identifier — for naming conventions like
                       ``OrderRepository`` or ``WidgetFactory``
  text                 substring of the source with comments and string
                       literals blanked out — for syntax like ``dp[`` or
                       ``@app.route``
  imports              substring of an imported module path

``min_signals`` is how many distinct signals a file must provide before the
pattern is reported. Generic patterns need corroboration; a single mention of
``visited`` is not a graph traversal.
"""

# DSA patterns to detect
DSA_PATTERNS = {
    "hash_map": {
        "identifiers": ["defaultdict", "Counter", "hashmap", "hash_map", "setdefault"],
        "imports": ["collections.counter", "collections.defaultdict"],
        "weight": 1.5,
        "min_signals": 1,
        "description": "Hash-based data structures for O(1) lookups"
    },
    "set_operations": {
        "identifiers": [
            "frozenset", "union", "intersection", "difference",
            "issubset", "issuperset", "symmetric_difference",
        ],
        "weight": 1.2,
        "min_signals": 1,
        "description": "Set operations for unique elements and fast membership"
    },
    "sorting": {
        "identifiers": ["sorted", "sort", "heapq", "bisect", "itemgetter"],
        "imports": ["heapq", "bisect", "operator.itemgetter"],
        "weight": 1.3,
        "min_signals": 1,
        "description": "Sorting algorithms and ordered operations"
    },
    "binary_search": {
        "identifiers": ["bisect_left", "bisect_right", "binary_search", "insort"],
        "text": ["mid =", "lo, hi", "low, high", "// 2"],
        "imports": ["bisect"],
        "weight": 2.0,
        "min_signals": 2,
        "description": "Binary search for O(log n) lookups"
    },
    "graph_traversal": {
        "identifiers": [
            "bfs", "dfs", "visited", "neighbors", "neighbours",
            "adjacency", "adj_list", "graph",
        ],
        "imports": ["collections.deque", "networkx"],
        "weight": 2.5,
        "min_signals": 2,
        "description": "Graph traversal algorithms (BFS/DFS)"
    },
    "dynamic_programming": {
        "identifiers": ["lru_cache", "memoize", "memo", "dp", "tabulation"],
        "text": ["dp[", "memo[", "@lru_cache", "@cache", "@functools.cache"],
        "imports": ["functools.lru_cache", "functools.cache"],
        "weight": 3.0,
        "min_signals": 1,
        "description": "Dynamic programming and memoization"
    },
    "tree_structures": {
        "identifiers": ["treenode", "left_child", "right_child", "subtree"],
        "identifier_contains": ["treenode"],
        "text": ["root.left", "root.right", "node.left", "node.right"],
        "weight": 2.0,
        "min_signals": 1,
        "description": "Tree data structures"
    },
    "linked_list": {
        "identifiers": ["listnode", "next_node", "prev_node"],
        "identifier_contains": ["listnode"],
        "text": ["head.next", "curr.next", "current.next", "node.next"],
        "weight": 1.5,
        "min_signals": 1,
        "description": "Linked list implementations"
    },
    "queue_stack": {
        "identifiers": ["deque", "lifoqueue", "simplequeue", "popleft", "appendleft"],
        "text": ["stack.append", "stack.pop", "queue.append", "queue.popleft"],
        "imports": ["collections.deque", "queue.queue", "queue.lifoqueue"],
        "weight": 1.2,
        "min_signals": 1,
        "description": "Queue and stack data structures"
    },
    "heap_priority": {
        "identifiers": [
            "heappush", "heappop", "heapify", "heappushpop", "heapreplace",
            "priorityqueue", "nlargest", "nsmallest",
        ],
        "imports": ["heapq", "queue.priorityqueue"],
        "weight": 2.0,
        "min_signals": 1,
        "description": "Heap/priority queue for efficient min/max operations"
    },
    "trie": {
        "identifiers": ["trienode", "trie", "prefix_tree", "insert_word", "search_prefix"],
        "identifier_contains": ["trienode"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Trie/prefix tree for string operations"
    },
    "union_find": {
        "identifiers": [
            "unionfind", "disjointset", "find_parent", "find_root",
            "path_compression", "union_by_rank",
        ],
        "identifier_contains": ["unionfind", "disjointset"],
        "text": ["parent[", "rank["],
        "weight": 2.5,
        "min_signals": 2,
        "description": "Union-Find/Disjoint Set for connectivity"
    },
    "topological_sort": {
        "identifiers": [
            "topological_sort", "toposort", "in_degree", "indegree",
            "kahn", "topologicalsorter",
        ],
        "identifier_contains": ["topological"],
        "imports": ["graphlib", "toposort"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Topological sorting for DAG ordering"
    },
    "sliding_window": {
        "identifiers": [
            "window_start", "window_end", "window_size",
            "shrink_window", "expand_window", "sliding_window",
        ],
        "weight": 2.0,
        "min_signals": 1,
        "description": "Sliding window technique for subarray problems"
    },
    "two_pointers": {
        "identifiers": [
            "two_pointer", "two_pointers", "left_pointer", "right_pointer",
            "slow_fast", "fast_slow", "tortoise_hare", "slow", "fast",
        ],
        "weight": 1.5,
        "min_signals": 2,
        "description": "Two pointers technique for array traversal"
    },
    "backtracking": {
        "identifiers": ["backtrack", "backtracking", "unchoose", "is_valid_state", "prune"],
        "identifier_contains": ["backtrack"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Backtracking for constraint satisfaction"
    },
    "segment_tree": {
        "identifiers": [
            "segmenttree", "segment_tree", "range_query", "range_update",
            "build_tree", "query_range", "lazy_propagation",
        ],
        "identifier_contains": ["segmenttree"],
        "weight": 3.0,
        "min_signals": 1,
        "description": "Segment tree for range queries"
    },
    "fenwick_tree": {
        "identifiers": [
            "fenwicktree", "fenwick_tree", "binaryindexedtree",
            "update_bit", "query_bit",
        ],
        "identifier_contains": ["fenwick", "binaryindexedtree"],
        "weight": 3.0,
        "min_signals": 1,
        "description": "Fenwick/Binary Indexed Tree for prefix operations"
    },
    "lru_cache_manual": {
        "identifiers": [
            "ordereddict", "move_to_end", "popitem", "capacity",
            "evict", "cache_hit", "cache_miss",
        ],
        "imports": ["collections.ordereddict"],
        "weight": 2.0,
        "min_signals": 2,
        "description": "Manual LRU cache implementation"
    },
    "bloom_filter": {
        "identifiers": [
            "bloomfilter", "bloom_filter", "hash_functions",
            "bit_array", "false_positive_rate",
        ],
        "identifier_contains": ["bloomfilter"],
        "imports": ["pybloom", "bloom_filter", "bitarray"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Bloom filter for probabilistic membership"
    },
    "dijkstra": {
        "identifiers": ["dijkstra", "bellman_ford", "shortest_path", "a_star", "astar"],
        "text": ["dist[", "distance["],
        "imports": ["networkx.dijkstra", "networkx.shortest_path"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Shortest path algorithms (Dijkstra/Bellman-Ford)"
    },
    "minimum_spanning_tree": {
        "identifiers": ["kruskal", "prim", "mst", "minimum_spanning", "spanning_tree"],
        "identifier_contains": ["spanning_tree"],
        "imports": ["networkx.minimum_spanning_tree"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Minimum spanning tree algorithms"
    },
    "monotonic_stack": {
        "identifiers": [
            "monotonic_stack", "monotonicstack", "mono_stack", "next_greater",
            "next_smaller", "previous_greater", "previous_smaller",
        ],
        "weight": 2.0,
        "min_signals": 1,
        "description": "Monotonic stack for next greater/smaller element"
    },
    "interval_operations": {
        "identifiers": [
            "merge_intervals", "interval_overlap", "interval_intersection",
            "intervaltree", "overlaps",
        ],
        "text": ["intervals.sort"],
        "imports": ["intervaltree"],
        "weight": 2.0,
        "min_signals": 1,
        "description": "Interval merging and overlap detection"
    }
}

# System Design patterns to detect
SYSTEM_DESIGN_PATTERNS = {
    "api_design": {
        "identifiers": ["fastapi", "flask", "apirouter", "blueprint", "asgiapp"],
        "text": ["@app.route", "@router.", "@app.get", "@app.post", "@bp.route"],
        "imports": ["fastapi", "flask", "django.urls", "starlette", "aiohttp.web"],
        "weight": 2.0,
        "min_signals": 1,
        "description": "RESTful API design"
    },
    "database_orm": {
        "identifiers": [
            "foreignkey", "relationship", "declarative_base",
            "sessionmaker", "column", "querySet",
        ],
        "text": ["base.metadata", "session.query", "objects.filter"],
        "imports": ["sqlalchemy", "django.db", "peewee", "tortoise", "sqlmodel"],
        "weight": 2.0,
        "min_signals": 1,
        "description": "Database ORM patterns"
    },
    "caching": {
        "identifiers": ["redis", "memcached", "cache_key", "ttl", "cached", "cache_clear"],
        "imports": ["redis", "cachetools", "django.core.cache", "aiocache", "diskcache"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Caching layer implementation"
    },
    "message_queue": {
        "identifiers": [
            "celery", "kafkaproducer", "kafkaconsumer",
            "basic_publish", "send_message",
        ],
        "identifier_contains": ["rabbitmq", "kafka"],
        "imports": ["celery", "pika", "kafka", "aiokafka", "kombu"],
        "weight": 3.0,
        "min_signals": 1,
        "description": "Message queue/async processing"
    },
    "factory_pattern": {
        "identifiers": [
            "factory", "factory_method", "factorymethod", "get_instance",
            "create_instance", "from_config", "abstractfactory",
        ],
        "weight": 1.5,
        "min_signals": 1,
        "description": "Factory design pattern"
    },
    "singleton_pattern": {
        "identifiers": ["_instance", "getinstance", "singleton"],
        "identifier_contains": ["singleton"],
        "text": ["def __new__"],
        "weight": 1.0,
        "min_signals": 2,
        "description": "Singleton design pattern"
    },
    "dependency_injection": {
        "identifiers": ["depends", "inject", "provider", "container"],
        "text": ["@inject", "= Depends(", "Depends("],
        "imports": ["dependency_injector", "fastapi", "injector"],
        "weight": 2.5,
        "min_signals": 2,
        "description": "Dependency injection pattern"
    },
    "error_handling": {
        "identifiers": ["httpexception", "exception_handler", "errorhandler"],
        "identifier_contains": ["error", "exception"],
        "text": ["except ", "raise "],
        "weight": 1.5,
        "min_signals": 2,
        "description": "Structured error handling"
    },
    "logging": {
        "identifiers": ["getlogger", "logger", "structlog", "loguru", "basicconfig"],
        "imports": ["logging", "structlog", "loguru"],
        "weight": 1.5,
        "min_signals": 2,
        "description": "Logging implementation"
    },
    "authentication": {
        "identifiers": [
            "jwt", "oauth", "authenticate", "authorize", "verify_password",
            "password_hash", "hash_password", "access_token", "bearer",
        ],
        "imports": ["jwt", "jose", "passlib", "authlib", "bcrypt", "argon2"],
        "weight": 2.5,
        "min_signals": 1,
        "description": "Authentication/Authorization"
    },
    "testing": {
        "identifiers": ["pytest", "unittest", "fixture", "monkeypatch", "mock", "patch"],
        "identifier_contains": ["test_"],
        "imports": ["pytest", "unittest", "mock", "hypothesis"],
        "weight": 2.0,
        "min_signals": 2,
        "description": "Testing patterns"
    },
    "microservices": {
        "identifiers": ["grpc", "httpx", "aiohttp", "servicestub", "channel"],
        "identifier_contains": ["serviceclient", "apiclient"],
        "imports": ["grpc", "httpx", "aiohttp", "requests"],
        "weight": 2.5,
        "min_signals": 2,
        "description": "Microservices architecture"
    },
    "repository_pattern": {
        "identifiers": ["get_by_id", "find_all", "find_by", "baserepository"],
        "identifier_contains": ["repository"],
        "weight": 2.0,
        "min_signals": 2,
        "description": "Repository pattern for data access"
    },
    "config_management": {
        "identifiers": ["basesettings", "getenv", "load_dotenv", "environ", "settings"],
        "imports": ["pydantic_settings", "dotenv", "dynaconf", "environs"],
        "weight": 1.5,
        "min_signals": 2,
        "description": "Configuration management"
    }
}
