"""DSA and System Design pattern definitions."""

# DSA patterns to detect
DSA_PATTERNS = {
    "hash_map": {
        "keywords": ["dict", "dictionary", "hashmap", "hash_map", "Counter", "defaultdict"],
        "imports": ["collections.Counter", "collections.defaultdict"],
        "weight": 1.5,
        "description": "Hash-based data structures for O(1) lookups"
    },
    "set_operations": {
        "keywords": ["set(", "frozenset", ".union", ".intersection", ".difference"],
        "imports": [],
        "weight": 1.2,
        "description": "Set operations for unique elements and fast membership"
    },
    "sorting": {
        "keywords": ["sorted(", ".sort(", "heapq", "bisect"],
        "imports": ["heapq", "bisect"],
        "weight": 1.3,
        "description": "Sorting algorithms and ordered operations"
    },
    "binary_search": {
        "keywords": ["bisect_left", "bisect_right", "binary_search", "lo, hi", "mid ="],
        "imports": ["bisect"],
        "weight": 2.0,
        "description": "Binary search for O(log n) lookups"
    },
    "graph_traversal": {
        "keywords": ["bfs", "dfs", "visited", "queue.append", "stack.append", "neighbors"],
        "imports": ["collections.deque", "networkx"],
        "weight": 2.5,
        "description": "Graph traversal algorithms (BFS/DFS)"
    },
    "dynamic_programming": {
        "keywords": ["dp[", "memo[", "@lru_cache", "@cache", "memoize"],
        "imports": ["functools.lru_cache", "functools.cache"],
        "weight": 3.0,
        "description": "Dynamic programming and memoization"
    },
    "tree_structures": {
        "keywords": ["TreeNode", "left_child", "right_child", "parent", "root.left", "root.right"],
        "imports": [],
        "weight": 2.0,
        "description": "Tree data structures"
    },
    "linked_list": {
        "keywords": ["ListNode", "next_node", "head.next", "prev", "curr.next"],
        "imports": [],
        "weight": 1.5,
        "description": "Linked list implementations"
    },
    "queue_stack": {
        "keywords": ["deque", "queue", "stack", "LIFO", "FIFO", "push", "pop"],
        "imports": ["collections.deque", "queue.Queue"],
        "weight": 1.2,
        "description": "Queue and stack data structures"
    },
    "heap_priority": {
        "keywords": ["heappush", "heappop", "heapify", "PriorityQueue", "nlargest", "nsmallest"],
        "imports": ["heapq", "queue.PriorityQueue"],
        "weight": 2.0,
        "description": "Heap/priority queue for efficient min/max operations"
    },
    "trie": {
        "keywords": ["TrieNode", "Trie", "prefix_tree", "children[", "is_end", "insert_word", "search_prefix"],
        "imports": ["pygtrie", "marisa_trie"],
        "weight": 2.5,
        "description": "Trie/prefix tree for string operations"
    },
    "union_find": {
        "keywords": ["UnionFind", "DisjointSet", "find_parent", "union(", "parent[", "rank[", "path_compression"],
        "imports": [],
        "weight": 2.5,
        "description": "Union-Find/Disjoint Set for connectivity"
    },
    "topological_sort": {
        "keywords": ["topological", "toposort", "in_degree", "indegree", "kahn", "dag"],
        "imports": ["graphlib", "toposort"],
        "weight": 2.5,
        "description": "Topological sorting for DAG ordering"
    },
    "sliding_window": {
        "keywords": ["window_start", "window_end", "left_ptr", "right_ptr", "window_size", "shrink_window", "expand_window"],
        "imports": [],
        "weight": 2.0,
        "description": "Sliding window technique for subarray problems"
    },
    "two_pointers": {
        "keywords": ["two_pointer", "left_pointer", "right_pointer", "slow_fast", "fast_slow", "tortoise_hare"],
        "imports": [],
        "weight": 1.5,
        "description": "Two pointers technique for array traversal"
    },
    "backtracking": {
        "keywords": ["backtrack", "backtracking", "choose", "unchoose", "explore", "is_valid_state"],
        "imports": [],
        "weight": 2.5,
        "description": "Backtracking for constraint satisfaction"
    },
    "segment_tree": {
        "keywords": ["SegmentTree", "segment_tree", "range_query", "range_update", "build_tree", "query_range"],
        "imports": [],
        "weight": 3.0,
        "description": "Segment tree for range queries"
    },
    "fenwick_tree": {
        "keywords": ["FenwickTree", "BinaryIndexedTree", "BIT", "prefix_sum", "update_bit", "query_bit"],
        "imports": [],
        "weight": 3.0,
        "description": "Fenwick/Binary Indexed Tree for prefix operations"
    },
    "lru_cache_manual": {
        "keywords": ["OrderedDict", "move_to_end", "popitem", "capacity", "cache_hit", "cache_miss", "evict"],
        "imports": ["collections.OrderedDict"],
        "weight": 2.0,
        "description": "Manual LRU cache implementation"
    },
    "bloom_filter": {
        "keywords": ["BloomFilter", "bloom_filter", "hash_functions", "bit_array", "false_positive"],
        "imports": ["pybloom", "bloom_filter", "bitarray"],
        "weight": 2.5,
        "description": "Bloom filter for probabilistic membership"
    },
    "dijkstra": {
        "keywords": ["dijkstra", "shortest_path", "distance[", "dist[", "relaxation", "bellman_ford"],
        "imports": ["networkx.dijkstra", "networkx.shortest_path"],
        "weight": 2.5,
        "description": "Shortest path algorithms (Dijkstra/Bellman-Ford)"
    },
    "minimum_spanning_tree": {
        "keywords": ["kruskal", "prim", "mst", "minimum_spanning", "spanning_tree"],
        "imports": ["networkx.minimum_spanning_tree"],
        "weight": 2.5,
        "description": "Minimum spanning tree algorithms"
    },
    "monotonic_stack": {
        "keywords": ["monotonic_stack", "mono_stack", "next_greater", "next_smaller", "previous_greater"],
        "imports": [],
        "weight": 2.0,
        "description": "Monotonic stack for next greater/smaller element"
    },
    "interval_operations": {
        "keywords": ["merge_intervals", "interval_overlap", "interval_intersection", "start_end", "intervals.sort"],
        "imports": ["intervaltree"],
        "weight": 2.0,
        "description": "Interval merging and overlap detection"
    }
}

# System Design patterns to detect
SYSTEM_DESIGN_PATTERNS = {
    "api_design": {
        "keywords": ["@app.route", "@router", "APIRouter", "FastAPI", "Flask", "endpoint"],
        "imports": ["fastapi", "flask", "django.urls"],
        "weight": 2.0,
        "description": "RESTful API design"
    },
    "database_orm": {
        "keywords": ["Base.metadata", "session.query", "Model", "ForeignKey", "relationship"],
        "imports": ["sqlalchemy", "django.db", "peewee", "tortoise"],
        "weight": 2.0,
        "description": "Database ORM patterns"
    },
    "caching": {
        "keywords": ["cache", "redis", "memcached", "@cached", "cache_key", "ttl"],
        "imports": ["redis", "cachetools", "django.core.cache"],
        "weight": 2.5,
        "description": "Caching layer implementation"
    },
    "message_queue": {
        "keywords": ["celery", "rabbitmq", "kafka", "sqs", "publish", "subscribe", "consumer"],
        "imports": ["celery", "pika", "kafka", "boto3.client('sqs')"],
        "weight": 3.0,
        "description": "Message queue/async processing"
    },
    "factory_pattern": {
        "keywords": ["Factory", "create_", "get_instance", "register", "build"],
        "imports": [],
        "weight": 1.5,
        "description": "Factory design pattern"
    },
    "singleton_pattern": {
        "keywords": ["_instance", "__new__", "getInstance", "Singleton"],
        "imports": [],
        "weight": 1.0,
        "description": "Singleton design pattern"
    },
    "dependency_injection": {
        "keywords": ["Depends", "inject", "@inject", "Container", "provider"],
        "imports": ["dependency_injector", "fastapi.Depends"],
        "weight": 2.5,
        "description": "Dependency injection pattern"
    },
    "error_handling": {
        "keywords": ["try:", "except", "raise", "HTTPException", "custom exception", "ErrorHandler"],
        "imports": [],
        "weight": 1.5,
        "description": "Structured error handling"
    },
    "logging": {
        "keywords": ["logging", "logger", "log.info", "log.error", "log.debug"],
        "imports": ["logging", "structlog", "loguru"],
        "weight": 1.5,
        "description": "Logging implementation"
    },
    "authentication": {
        "keywords": ["jwt", "token", "authenticate", "authorize", "OAuth", "bearer", "password_hash"],
        "imports": ["jwt", "passlib", "python-jose", "authlib"],
        "weight": 2.5,
        "description": "Authentication/Authorization"
    },
    "testing": {
        "keywords": ["pytest", "unittest", "mock", "fixture", "assert", "test_"],
        "imports": ["pytest", "unittest", "mock"],
        "weight": 2.0,
        "description": "Testing patterns"
    },
    "microservices": {
        "keywords": ["service", "client", "grpc", "proto", "api_client", "ServiceClient"],
        "imports": ["grpc", "httpx", "aiohttp"],
        "weight": 2.5,
        "description": "Microservices architecture"
    },
    "repository_pattern": {
        "keywords": ["Repository", "BaseRepository", "get_by_id", "find_all", "save", "delete"],
        "imports": [],
        "weight": 2.0,
        "description": "Repository pattern for data access"
    },
    "config_management": {
        "keywords": ["Settings", "Config", "env", "getenv", "pydantic.BaseSettings"],
        "imports": ["pydantic", "python-dotenv", "dynaconf"],
        "weight": 1.5,
        "description": "Configuration management"
    }
}
