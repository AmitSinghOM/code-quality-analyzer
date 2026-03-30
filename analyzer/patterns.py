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
