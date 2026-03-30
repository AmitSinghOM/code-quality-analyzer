# Code Quality Analyzer

A Python tool that analyzes codebases to detect:
- **Data Structures & Algorithms (DSA)** patterns used
- **System Design** principles implemented
- Generates a **quality rating from 1-10**

## Rating Scale

| Rating | Description |
|--------|-------------|
| 1-2 | Poor: No meaningful DSA/design, wasteful code |
| 3-4 | Basic: Simple structures, minimal design thought |
| 5-6 | Average: Some DSA usage, basic patterns |
| 7-8 | Good: Strategic DSA, clear design patterns |
| 9-10 | Excellent: Optimal DSA, comprehensive system design |

## Project Structure

```
code-quality-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── __main__.py      # CLI entry point
│   ├── patterns.py      # DSA & System Design pattern definitions
│   ├── scanner.py       # File scanner and pattern detector
│   └── rater.py         # Rating calculator (1-10)
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

```bash
cd code-quality-analyzer
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a project
python -m analyzer /path/to/project

# Analyze with detailed report (shows file matches)
python -m analyzer /path/to/project -v

# Output as JSON
python -m analyzer /path/to/project -f json
```

## Important: Use Absolute/Full Paths

⚠️ **Recommendation:** Always use full absolute paths to avoid "Path does not exist" errors.

Relative paths like `../my-project` may fail depending on your current working directory.

**Examples:**

```bash
# ✅ Recommended: Full absolute path
python -m analyzer "/Users/username/projects/my-fastapi-app" -v

# ✅ Also works: Home directory shortcut
python -m analyzer ~/projects/my-fastapi-app -v

# ⚠️ May fail: Relative path (depends on current directory)
python -m analyzer "../my-fastapi-app" -v
```

## Troubleshooting

### Path does not exist error
```
Error: Invalid value for 'PROJECT_PATH': Path '../project' does not exist.
```
**Solution:** Use the full absolute path instead of relative path.

### Python not found / wrong version
If your default `python` command doesn't work, use the full path to your Python installation:
```bash
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3 -m analyzer /path/to/project -v
```
Or create an alias in your shell config (`~/.zshrc` or `~/.bashrc`):
```bash
alias py3="/Library/Frameworks/Python.framework/Versions/3.14/bin/python3"
py3 -m analyzer /path/to/project -v
```

## Complexity Analysis

Use the `-c` flag to include time/space complexity analysis:

```bash
python -m analyzer /path/to/project -c
python -m analyzer /path/to/project -v -c  # verbose with reasoning
```

### Confidence Score

The confidence score indicates how reliable the complexity estimate is.

**Starting point:** 80%

**Deductions:**

| Condition | Deduction | Reason |
|-----------|-----------|--------|
| Recursion without memoization | -20% | Hard to determine if it's O(n), O(2^n), or O(n!) without runtime analysis |
| Deep nesting (>2 loops) | -10% | Complex control flow makes static analysis less reliable |
| No type hints on parameters | -10% | Can't infer if input is a collection or its size relationship |

**Minimum:** 30% (never goes below this)

**Interpreting confidence:**
- 80%+ → High confidence, estimate is likely accurate
- 60-80% → Medium confidence, estimate is reasonable but verify manually
- 30-60% → Low confidence, treat as rough estimate only

---

## What It Detects

### DSA Patterns
- Hash maps, sets, dictionaries
- Trees, graphs, linked lists
- Sorting algorithms
- Search algorithms (binary search, BFS, DFS)
- Dynamic programming patterns
- Caching/memoization
- Heaps and priority queues
- Queue and stack structures

### System Design Patterns
- Microservices architecture
- API design (REST, GraphQL)
- Database patterns (ORM, connection pooling)
- Caching layers
- Message queues
- Design patterns (Factory, Singleton, Repository, etc.)
- Dependency injection
- Error handling & logging
- Authentication/Authorization
- Configuration management
- Testing patterns

## License

MIT
