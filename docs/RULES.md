# Rule reference

The built-in SARIF catalog mirrors the rule IDs, titles, categories, default
severities, confidence, and remediation documented here. Catalog completeness
is tested so a built-in finding cannot be rendered without stable metadata.
Runtime severity policy may override a finding's level without changing the
documented default.

## PY-COR-001: Mutable default argument

**Category:** Correctness  
**Default severity:** Warning  
**Confidence:** High

Python evaluates function defaults once when the function is defined. Mutating a list, dictionary, set, comprehension result, or mutable built-in factory default can therefore leak state between calls.

### Non-compliant

```python
def add_item(item, items=[]):
    items.append(item)
    return items
```

### Compliant

```python
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
```

The rule reports the default expression with a one-based file, line, and column location. It currently recognizes list, dictionary, and set literals; list, dictionary, and set comprehensions; and direct calls to `list()`, `dict()`, `set()`, and `bytearray()`.

A same-line suppression is accepted only when it names the rule and includes a nonempty quoted reason:

```python
def compatibility(cache={}):  # cqa: ignore=PY-COR-001 reason="legacy API"
    return cache
```

Malformed directives, blank or missing reasons, and directive-like strings do not suppress the finding. Reasons are not copied into reports or baselines. See [`CONFIGURATION.md`](CONFIGURATION.md) for the complete contract.

## PY-COR-002: Broad exception handler

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A bare `except` or a handler for `Exception`/`BaseException` can hide unrelated failures and, for the broadest forms, process-control exceptions. Catch only exception types the operation can recover from.

```python
# Non-compliant
try:
    load_order()
except Exception:
    recover()

# Compliant
try:
    load_order()
except OrderNotFoundError:
    recover()
```

Tuples are reported when they contain `Exception` or `BaseException`. Attribute-qualified application exception types are not assumed to be broad.

## PY-COR-003: Silently swallowed exception

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

An exception handler whose only statement is `pass` or `...` discards the failure without recovery, propagation, or actionable context. If the handler carries a comment (`except Exception:  # best effort`), the swallow is documented intent and is reported at **note** severity with a "documenting the intent" message — the same grading the regex-language empty-catch rules apply.

```python
# Non-compliant
try:
    refresh()
except RefreshError:
    pass

# Compliant
try:
    refresh()
except RefreshError as error:
    logger.warning("Refresh failed", exc_info=error)
```

If discarding a known failure is intentional, use a reason-required same-line suppression on the `except` line rather than an unrecorded empty handler.

## PY-COR-004: Unreachable statement

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A statement immediately following a direct `return`, `raise`, `break`, or `continue` in the same suite cannot execute. The rule reports the first unreachable statement in each affected suite.

```python
# Non-compliant
def load():
    return cached_value
    refresh_cache()

# Compliant
def load():
    refresh_cache()
    return cached_value
```

The rule is intentionally conservative: it does not infer that a conditional or compound statement always transfers control.

## PY-COR-005: Blocking synchronous call in async code

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A known synchronous standard-library operation is called directly inside an `async def`. The bounded allowlist covers `time.sleep`, synchronous `subprocess` helpers, `os.system`, `urllib.request.urlopen`, built-in/`io.open`, and direct `pathlib.Path` file methods. Imported aliases are resolved conservatively; shadowed or ambiguous names are ignored.

Use the corresponding async API, `asyncio.create_subprocess_*`, or move unavoidable synchronous work to `asyncio.to_thread`. Calls passed as callables to `to_thread` or an executor are not reported. Generic methods and third-party clients are intentionally outside this rule.

## PY-COR-006: Resource without guaranteed cleanup

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A locally acquired file or temporary resource is not protected by `with`, `ExitStack.enter_context`, or `try...finally` cleanup. The bounded rule covers built-in/`io.open`, direct `Path(...).open()`, and standard `tempfile` context-manager factories.

Directly returned, yielded, passed, or attribute-stored resources are treated as escaped ownership and are not judged locally. A plain later `close()` is not considered guaranteed when intervening work can raise. Use a context manager whenever possible.

Both rules report the call location and support reason-required same-line suppressions. A bare `open()` in async code may intentionally emit both rule IDs.

## PY-MAINT-001: High cyclomatic complexity

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function has more than 10 independent control-flow paths. The measured value starts at one and counts conditionals, loops, exception handlers, conditional expressions, boolean branches, comprehensions, and match branches.

The finding reports the function definition and measured value. Extract independent decisions into focused helpers. A value of exactly 10 is accepted; the first reported value is 11.

## PY-MAINT-002: High cognitive complexity

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function has cognitive complexity above 15. Decisions add one point plus their current control-flow nesting depth; boolean sequences and comprehensions also add bounded structural cost. The measurement is deterministic and syntax-derived rather than an estimated Big-O class.

Flatten nested conditionals and loops, use guard clauses, and extract focused helpers. A value of exactly 15 is accepted. Nested functions and methods are measured independently, and a suppression must appear on the reported function-definition line.

## PY-MAINT-003: Long function

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function spans more than 60 physical source lines from its definition through its final statement. A span of exactly 60 lines is accepted. Extract cohesive responsibilities into focused helpers.

## PY-MAINT-004: Excessive parameters

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function declares more than seven effective parameters. The leading `self` or `cls` receiver is excluded; positional-only, positional, keyword-only, variadic positional, and variadic keyword parameters are counted. Group related inputs in a value object or split the responsibility.

## PY-MAINT-005: Boolean parameter proliferation

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

A function exposes more than two parameters identified as boolean by an explicit `bool` annotation or a `True`/`False` default. Multiple mode flags create combinatorial behavior that is hard to name and test. Prefer explicit operations, an enum, or a typed configuration object.

All three rules report the function definition line, where a reason-required suppression can be placed when a stable external interface cannot yet be changed.

## PY-DUP-001: Duplicate function implementation

**Category:** Duplication
**Default severity:** Warning
**Confidence:** High

A significant function body is structurally identical to another function in
the project. Detection compares docstring-stripped bodies, parameter lists,
and return annotations by exact AST structure, so a renamed or re-decorated
copy of the same implementation still reports, while a docstring-only or
comment-only difference does not hide a copy. Function names and decorators
are deliberately excluded from the comparison.

Only significant functions participate: the docstring-stripped body must
contain at least three statements and at least forty AST nodes, so trivial
getters and delegation stubs never report. When a duplicated function
encloses other duplicated functions, only the outermost duplicate reports.
Every occurrence in a duplicate group receives its own finding, and each
message names one other occurrence so the copy is reviewable. Analysis is
cross-file but project-local, fully static, and deterministic; findings can
be suppressed on the reported definition line with a reason-required inline
suppression, and the rule can be disabled or re-leveled in
`.code-quality.toml`.

## Python package rules

Package rules analyze conventional `src` and initialized flat packages plus
PEP 420 namespaces identified by bounded static setuptools discovery metadata.
Ambiguous configuration is skipped without executing build hooks or weakening
strict-mode analysis health.

## PY-PKG-001: Circular local imports

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

The package import graph contains two or more modules that directly or indirectly depend on each other. Circular imports make initialization order fragile and can expose partially initialized modules.

Move shared contracts into a lower-level module, invert one dependency, or introduce a narrow interface that removes the cycle.

## PY-PKG-002: Missing console-script module

**Category:** Package health
**Default severity:** Error
**Confidence:** High

A `[project.scripts]` entry in `pyproject.toml` points to a module that is not present in the detected local package modules.

Correct the entry-point target or ensure that the target module is included in the package source layout.

## PY-PKG-003: Invalid pyproject metadata

**Category:** Package health
**Default severity:** Error
**Confidence:** High

The project contains `pyproject.toml`, but it cannot be read as valid TOML. Package metadata and build configuration cannot be trusted until parsing succeeds. This finding also marks strict analysis as incomplete.

Correct the TOML syntax and rerun the analyzer. The report intentionally avoids reproducing source content from the invalid file.

## PY-PKG-004: Missing literal public export binding

**Category:** Package health
**Default severity:** Error
**Confidence:** High

A literal string in an eligible module-level `__all__` list or tuple has no
module-scope binding. Forward definitions and names bound by functions, classes,
assignments, imports, and module-level control-flow suites are recognized.

Define or import the name at module scope, or remove it from `__all__`.
Analysis is skipped when `__all__` is dynamic or ambiguous, including multiple
assignments, mutation, wildcard imports, module `__getattr__`, namespace
manipulation, comprehensions, concatenation, unpacking, or non-string values.

## PY-PKG-005: Duplicate literal public export

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

An eligible literal module-level `__all__` declaration repeats an exported
name. Each occurrence after the first receives a finding at its own string
literal, with case-sensitive comparison.

Remove repeated names from `__all__`. The same conservative eligibility
boundaries as `PY-PKG-004` apply.

## PY-PKG-006: Missing literal package-data target

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

An eligible static `[tool.setuptools.package-data]` declaration names a literal
source-tree path that does not exist as a regular file beneath the uniquely
resolved package directory. The finding is reported at `pyproject.toml:1:1`
because the bounded TOML parser does not expose key locations.

Add the file, correct the literal path, or disable the rule when a documented
build step generates it. The rule does not make strict analysis incomplete.
It runs only for standard setuptools builds with one unambiguous setuptools
build requirement and no custom setup file, backend path, command class, or
package remapping. Wildcard package keys, globs, unsafe paths, malformed or
oversized tables, unknown/ambiguous packages, symlinks, directories, special
files, and stat errors are skipped. The analyzer never reads package-data
contents, walks data directories, executes build hooks, or claims that a file
is present in a built wheel or source distribution.

## GO-COR-001: Ignored standard-library error

**Category:** Correctness

**Default severity:** Warning

**Confidence:** High

A two-result assignment discards the second result from a known imported Go standard-library function whose second result is an `error`. The pilot is intentionally narrow: it covers selected functions from `encoding/json`, `io`, `net/http`, `net/url`, `os`, and `strconv`; it does not assume every second return value is an error.

### Non-compliant

```go
data, _ := os.ReadFile(path)
```

### Compliant

```go
data, err := os.ReadFile(path)
if err != nil {
    return nil, err
}
```

The rule requires the corresponding standard-library import, ignores comments and string literals, follows explicit import aliases, and reports the discarded result's one-based location. Blank and dot imports are recorded but intentionally do not authorize qualified-call matches.

## TS-COR-001: Empty catch block

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A `catch` block whose body is empty after comment blanking discards the
failure without recovery or context. A catch whose braces contain only a
comment is reported at **note** severity with a "documented" message: the
author declared the swallow intentional, which is reviewable but not a
defect (the ErrorProne/SonarQube convention). This applies identically to
`JAVA-COR-001`, `KT-COR-001`, `CS-COR-001`, and `C-COR-001`.

### Non-compliant

```ts
try {
  await persist();
} catch (error) {}
```

### Compliant

```ts
try {
  await persist();
} catch (error) {
  logger.error("persist failed", error);
  throw error;
}
```

The rule matches blanked source, so string or comment mentions of `catch`
are never evidence. Optional catch binding (`catch {}`) is covered.

## TS-PKG-001: Undeclared imported dependency

**Category:** Package health
**Default severity:** Warning
**Confidence:** High

A bare module specifier is imported (via `import`, `export ... from`,
`require(...)`, or dynamic `import(...)`) but not declared in any
dependency section of its governing `package.json`. Manifests are
discovered at the scan root and in every non-excluded directory that
encloses an analyzed TS/JS file; each file is checked against its
nearest enclosing manifest with declared dependencies unioned up the
ancestor chain, matching Node module resolution. Relative paths, node
builtins (including the `node:` prefix), path aliases (`@/`, `~`, `#`),
and specifiers that are not valid npm package names (directive strings,
minifier artifacts) are never flagged. Files under a manifest chain
that declares `workspaces` — or contains an unreadable manifest — skip
drift analysis entirely. Findings locate at the governing manifest's
project-relative path.

## TS-PKG-002: Invalid package.json

**Category:** Package health
**Default severity:** Error
**Confidence:** High

The root `package.json` exists but cannot be read as a valid JSON object.
Correct the syntax and run analysis again.

## JAVA-COR-001: Empty catch block

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A `catch` block whose body is empty after comment blanking discards the
exception without recovery or context. Matched on blanked source, so
string, char, and text-block mentions are never evidence.

## JAVA-PKG-001: Undeclared direct library

**Category:** Package health
**Default severity:** Warning
**Confidence:** Medium

A commonly direct third-party library (Guava, Gson, Commons Lang/IO,
Lombok, OkHttp, Retrofit, MapStruct, JJWT, Caffeine, AssertJ, Mockito,
Testcontainers, HikariCP, Flyway, Liquibase) is imported but no
dependency with the matching `groupId`/`artifactId` prefix is declared
in the governing `pom.xml` or Gradle build file, including parent
manifests up the module chain. The check is deliberately limited to
this curated set: Java imports name packages while manifests name
artifacts, and Maven/Gradle make transitively provided classes
importable, so libraries commonly supplied by starters (Jackson, SLF4J,
Hibernate) are never flagged.

Gradle declarations are recognised in three forms: string coordinates
(`implementation("g:a:v")`), platform BOMs (`implementation(platform("g:a:v"))`),
and **version-catalog accessors** (`implementation(libs.guava.core)`),
which are resolved through the nearest `gradle/*.versions.toml`
(`[libraries]` and `[bundles]`, with `libs.a.b` normalised to alias `a-b`).
A build script that references a catalog alias the analyzer cannot
resolve makes no drift claims at all (`unresolved_catalog_refs` in the
report), because such a script may declare anything.

## JAVA-PKG-002: Invalid build manifest

**Category:** Package health
**Default severity:** Error
**Confidence:** High

A `pom.xml`, `build.gradle`, or `build.gradle.kts` cannot be read.
`pom.xml` parsing fails closed on any document declaring a DOCTYPE or
entities, so entity expansion and external-entity retrieval cannot
occur. Files under an invalid manifest skip drift analysis.

## CS-COR-001: Empty catch block

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A `catch` block — with or without an exception declaration or `when`
filter — whose body is empty after comment blanking. Matched on blanked
source; regular, verbatim, interpolated, and raw strings are never
evidence.

## CS-PKG-001: Undeclared package namespace

**Category:** Package health
**Default severity:** Warning
**Confidence:** Medium

A `using` directive names a namespace with no matching
`PackageReference` in the nearest enclosing `.csproj` (or its parents).
Matching is case-insensitive by prefix in either direction, so
`using Microsoft.EntityFrameworkCore` is satisfied by the
`Microsoft.EntityFrameworkCore.SqlServer` package and
`using Serilog.Events` by `Serilog`. Never flagged: `System.*`,
shared-framework `Microsoft.AspNetCore`/`Microsoft.Extensions`/
`Microsoft.NET` namespaces, any namespace whose root segment the
analyzed source itself declares or the project's `RootNamespace`/
`AssemblyName` names, and any namespace sharing a root segment with a
declared package (vendors split one namespace across many packages).
Declared packages flow transitively through `ProjectReference`s and from
ancestor `Directory.Build.props`/`Directory.Packages.props` files.
Confidence is medium because a namespace can be legitimately provided by
a declared package's own transitive dependencies (FluentValidation via
FastEndpoints); such findings are still worth reviewing under a
"declare what you use" policy.

## CS-PKG-002: Invalid project file

**Category:** Package health
**Default severity:** Error
**Confidence:** High

A `.csproj` cannot be read as XML, or declares a DOCTYPE or entities
(rejected fail-closed). Files under an invalid project skip drift
analysis.

## KT-COR-001: Empty catch block

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A Kotlin `catch` block whose body is empty after comment blanking.
Matched on blanked source; string templates, raw strings, and nested
block comments are never evidence.

## KT-PKG-001: Undeclared direct library

**Category:** Package health
**Default severity:** Warning
**Confidence:** Medium

Kotlin sources are checked against the same Maven/Gradle manifests and
curated direct-library set as `JAVA-PKG-001`; see that rule for the
transitive-dependency rationale. In a mixed Java/Kotlin module the two
rules report independently per source language.

## KT-PKG-002: Invalid build manifest

**Category:** Package health
**Default severity:** Error
**Confidence:** High

The governing `pom.xml` or Gradle build file cannot be read; identical
semantics to `JAVA-PKG-002`.

## C-COR-001: Empty catch block

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A C++ `catch` block whose body is empty after comment blanking. Macro
bodies are blanked before matching, so a catch generated by a macro is
never reported (and never inspected).

## C-PKG-001: Undeclared third-party header

**Category:** Package health
**Default severity:** Warning
**Confidence:** Medium

A header from a curated set of well-known third-party libraries (Boost,
GoogleTest, fmt, spdlog, nlohmann/json, OpenSSL, libcurl, SQLite, gRPC,
protobuf, Abseil, ZeroMQ, yaml-cpp, RapidJSON, libpqxx, hiredis,
librdkafka, OpenTelemetry, prometheus-cpp, libuv, libevent, zlib) is
included, but none of that library's CMake tokens (`find_package` name,
imported target, pkg-config module, or `FetchContent` name) appears
anywhere in the governing `CMakeLists.txt` chain — matched as whole
tokens of at least three characters with comments removed, so `z` inside
another word never "declares" zlib and a URL in a comment never declares
curl. Medium confidence
because CMake is Turing-complete and dependencies can arrive through
toolchain files, `include()`d modules, or header-only adapters shipped
for downstream builds (hiredis's `adapters/libuv.h` is a known example).
Files with no enclosing `CMakeLists.txt` produce no finding.

## GO-DUP-001 / C-DUP-001: Duplicate function implementation (requires `[deep]`)

**Category:** Duplication
**Default severity:** Warning
**Confidence:** High

Cross-file structural duplicates for Go and C/C++ via tree-sitter, with
exactly `PY-DUP-001`'s semantics: the function's own name is excluded,
the signature and body are compared structurally (comments ignored,
identifiers and literals included), only significant functions
participate (≥ 3 statements and ≥ 40 named nodes), and only top-level
functions and methods are compared. Go receivers are not part of the key, so two types whose methods have
identical bodies are duplicates — correct for copy-paste, but small
interface implementations (`String()`, `Error()`) across types can meet
the significance floor; review such groups with that in mind. Generated files are skipped
(`files_skipped_generated`): Go's official `// Code generated … DO NOT
EDIT.` header, `*.pb.go`, `*_generated.go`, `zz_generated*`, `mock_*.go`,
`*.g.cs`, `*.designer.cs`. Vendored trees (`vendor/`, `third_party/`,
`external/`) are excluded from discovery entirely. Functions whose subtree contains a
parse error are excluded and counted in
`functions_excluded_for_parse_errors`, because a partially recovered
tree could fabricate a match. Without `pip install 'cqa-analyzer[deep]'`
the provider reports `available: false` and emits nothing.

## GO-MAINT-001 / C-MAINT-001: High cyclomatic complexity (requires `[deep]`)

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

Cyclomatic complexity per function against the shared limit of 10. Go
follows gocyclo: `if`, `for`, non-default `case` (expression, type, and
select cases), `&&`, `||`. C/C++ count `if`, `for`, range-`for`,
`while`, `do`, non-default `case`, `?:`, `catch`, `&&`, `||`. Nested
function literals and lambdas are **not** entered — the same scope as
`PY-MAINT-001` and as cognitive complexity below (this deliberately
differs from gocyclo, which folds closures into the enclosing
function; cross-language parity wins). C code
routinely exceeds 10 (hiredis averages 4.4 with 49 of 635 functions
over; jq averages 6.0) — the limit is the same standard applied to
every language, not a claim that the code is wrong.

## GO-MAINT-002 / C-MAINT-002: High cognitive complexity (requires `[deep]`)

**Category:** Maintainability
**Default severity:** Warning
**Confidence:** High

Cognitive complexity per function against the shared limit of 15,
computed by exactly `PY-MAINT-002`'s rules on tree-sitter nodes: each
branch (`if`, `for`, `while`, `do`, range-`for`, `?:`, `catch`) adds
`1 + nesting`, with its condition at the current nesting and its bodies
one level deeper — so `else if` costs one more than the `if` it follows;
a `switch`/`select` adds `1 + nesting` once with its cases one deeper; a
boolean-operator sequence adds 1 regardless of nesting, and a chain of
the same operator (`a && b && c`) counts once, as Python's single
`BoolOp` node does; Go `func` literals and C++ lambdas are not entered.
Unlike cyclomatic complexity, this metric is what makes a function hard
to *read*: six flat `if`s score 6, six nested ones score 21.

## PY-COR-007 / GO-COR-002 / TS-COR-002 / JAVA-COR-002 / KT-COR-002 / CS-COR-002 / C-COR-002 / RS-COR-002: SQL statement assembled from runtime values

**Category:** Correctness
**Default severity:** Warning
**Confidence:** Medium

A string literal that reads as the head of a SQL statement (`SELECT … FROM`,
`INSERT INTO … VALUES`, `UPDATE … SET`, `DELETE FROM … WHERE`, DDL) is
combined with runtime values by interpolation, `+` concatenation or a
formatting call. The statement text — not its execution site — is the hazard,
so a dynamically built query later passed to a prepared-statement API is
still reported. One finding per statement line.

```python
# Non-compliant
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
cur.execute("SELECT * FROM users WHERE id = " + str(user_id))

# Compliant
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cur.execute("SELECT * FROM users WHERE id = ?", [user_id])
```

Per language the dynamic forms are: Python f-strings, `%`, `.format`, `+`;
Kotlin `$x`/`${x}` templates, `+`, `String.format`/`.format`; TypeScript
template `${x}`, `+`; C# `$"…{x}"`, `+`, `string.Format`; Java `+`,
`String.format`, `.formatted`; Go `+`, `fmt.Sprintf`; C/C++ `+`
(`std::string`), `snprintf`/`sprintf`, `std::format`/`fmt::format`; Rust
`format!`/`write!`/`writeln!` (inline `{id}` holes included) and
`"…".to_string() + &id`. Raw `r#"…"#` and byte strings are recognised.

Not reported: driver parameters (`?`, `$1`, `:name`, `@p`), literal-only
concatenation (`"SELECT * FROM t " + "WHERE id = 1"`), numeric constants
(`"… LIMIT " + 10`), and prose that merely contains SQL words — the statement
and clause keywords must share case (`SELECT … FROM` or `select … from`);
`"Select an item from the list"` mixes case and is rejected. Known bounds:
`StringBuilder.append`, `+=` accumulation and queries assembled across
statements are not followed.

## JAVA-COR-003 / KT-COR-003 / CS-COR-003 / C-COR-003: Broad exception handler

**Category:** Correctness
**Default severity:** Warning (Note when the handler rethrows)
**Confidence:** High

The counterpart of PY-COR-002. Java and Kotlin report `Exception`,
`Throwable`, `RuntimeException` and `Error` (including in multi-catch); C#
reports `Exception`, `System.Exception` and the bare `catch`; C++ reports
`catch (...)`. C# exception filters (`catch (Exception e) when (…)`) narrow
the clause and are not reported. A handler whose body contains `throw` is
graded **Note** — wrap-and-rethrow is an accepted idiom — while
catch-and-continue keeps the warning. This grading is *not* applied to
PY-COR-002, whose semantics predate it; the asymmetry is documented in
MAINTENANCE.md.

```java
// Non-compliant (warning)
try { load(); } catch (Exception e) { log.warn("failed", e); }

// Note: wraps and rethrows
try { load(); } catch (Exception e) { throw new LoadFailed(e); }

// Compliant
try { load(); } catch (IOException e) { retry(); }
```

## CS-COR-004 / KT-COR-004 / TS-COR-003: Blocking call in an asynchronous body

**Category:** Correctness
**Default severity:** Warning
**Confidence:** Medium

The counterpart of PY-COR-005. Inside an `async` method or lambda (C#), a
`suspend fun` (Kotlin) or an `async` function/method/arrow (TypeScript), a
synchronous blocking call defeats the asynchrony and, on a thread-pool
scheduler, can deadlock. Nested lambdas own their own asynchrony and are not
attributed to the enclosing declaration.

| Language | Reported calls |
|---|---|
| C# | `<call>.Result`, `<task>.Result`, `.Wait()`, `.GetAwaiter().GetResult()`, `Thread.Sleep` |
| Kotlin | `runBlocking`, `Thread.sleep` (also in expression bodies: `suspend fun f() = runBlocking { … }`) |
| TypeScript | `fs.*Sync(...)` and any `.xxxSync(` member, `execSync`, `execFileSync`, `spawnSync` |

Known bounds: C# `.Result` requires a call-shaped receiver (`GetAsync().Result`)
or a receiver named `*task*` so a plain property named `Result` on a message
type is not reported (calibrated on StackExchange.Redis); a guarded
`if (task.IsCompleted) task.Result` is still reported because it is the
target pattern. Expression-bodied C# members (`=> …;`) are not analysed.

## TS-COR-004: Unexplained type-check suppression

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

`// @ts-ignore`, `// @ts-expect-error` or `/* @ts-nocheck */` without a
reason (at least three characters after the directive, punctuation excluded)
disables the compiler at that line with no record of why. The 4th, 7th and
9th most-voted TypeScript questions on Stack Overflow are about `any`,
`unknown` and implicit-`any` errors — the errors these directives hide.

```ts
// Non-compliant
// @ts-ignore
const port = config.port;

// Compliant: the reason is recorded and the suppression self-expires
// @ts-expect-error upstream types lag the 4.x runtime; remove with #1234
const port = config.port;
```

## TS-COR-005 / KT-COR-005: Non-null assertion density

**Category:** Correctness
**Default severity:** Warning (Note in test files)
**Confidence:** Medium

One finding per file, anchored on the first assertion, when a file uses more
than four postfix `!` (TypeScript) or `!!` (Kotlin) operators. Each assertion
switches off null safety at that point; a handful is a local judgement call,
a file full of them is a design signal ("the `!` operator" is the 4th
most-voted TypeScript question). `!=`/`!==` never count, strings are blanked
before counting, and `.js` files are exempt (postfix `!` does not exist in
JavaScript). In test paths (`*.spec.ts`, `*Test.kt`, `tests/`, `__tests__/`,
`e2e/`) the finding is a **Note**: compact test bodies idiomatically assert
non-null (calibration: most of ktor's and nest's density was in tests).

## GO-COR-003: Unchecked type assertion

**Category:** Correctness
**Default severity:** Warning (Note in `_test.go`)
**Confidence:** Medium

`x.(T)` in single-value form panics when the dynamic type differs. The
two-value form `v, ok := x.(T)` and the type switch `switch v := x.(type)`
are not reported. In `_test.go` files the finding is a **Note**: test bodies
assert the type on purpose (calibration: 167 of go-redis's 209 assertions
were in tests). "Pointers vs. values" and "how to find the type of an object"
are among Go's most-voted questions; this is the runtime consequence.

## GO-COR-004: defer inside a loop

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

`defer` directly inside a `for` body runs only when the enclosing function
returns, so files, locks or connections accumulate across iterations.
Function literals inside the loop own their own defers and are not reported.
Nested loops report each defer once.

```go
// Non-compliant
for _, p := range paths {
    f, _ := os.Open(p)
    defer f.Close() // all files stay open until the function returns
}

// Compliant
for _, p := range paths {
    if err := process(p); err != nil { return err } // process defers f.Close()
}
```

## C-COR-004: `using namespace` in a header

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A file-scope `using namespace X;` in a header (`.h`, `.hh`, `.hpp`, `.hxx`)
is injected into every translation unit that includes it, silently changing
name lookup for code that never asked for it — the 6th most-voted C++
question on Stack Overflow. The directive inside a function body or a
`namespace { … }` block is scoped and not reported; `.cpp`/`.cc` files are
not reported.

## RS-COR-001: `unwrap()` density outside test code

**Category:** Correctness
**Default severity:** Warning
**Confidence:** Medium

One finding per file, anchored on the first call, when a file calls
`.unwrap()` more than four times outside test code. Each call is a latent
panic; `.expect("why this cannot fail")` documents the invariant and is
*not* counted. Test code is excluded structurally — `#[cfg(test)] mod … { }`
blocks and functions preceded by `#[test]`, `#[tokio::test]`,
`#[async_std::test]` or `#[rstest]` are blanked before counting — and by
path (`tests/`, `benches/`, `examples/`). Raw and byte strings are blanked,
so an `.unwrap()` inside a doc string is never counted.

```rust
// Non-compliant (five or more of these in one production file)
let cfg = std::fs::read_to_string(path).unwrap();

// Compliant
let cfg = std::fs::read_to_string(path)?;
let port = env::var("PORT").expect("PORT is set by the launcher");
```

## RS-PKG-001: Undeclared crate / RS-PKG-002: Invalid Cargo.toml

**Category:** Package health
**Default severity:** Warning (RS-PKG-001) / Error (RS-PKG-002)
**Confidence:** Medium / High

Governing manifest = nearest enclosing `Cargo.toml`, with every ancestor's
`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`,
`[target.*.dependencies]` and `[workspace.dependencies]` counting. A crate
root named by `use foo::…` or `extern crate foo;` is undeclared when it is
not `std`/`core`/`alloc`/`crate`/`self`/`super`, not a module declared
anywhere in the project (`mod foo;`, `src/foo.rs`), not the crate's own
package name, and absent from the chain. `package = "real-name"` renames are
honoured and names are compared with `-`/`_` removed (`md-5` provides
`md5`). `use` paths are read from blanked text, so an `extern crate` inside
a string literal is never an import. `RS-PKG-002` reports a manifest
`tomllib` cannot parse; no drift claim is made under an unreadable chain.

## RS-DUP-001 / RS-MAINT-001 / RS-MAINT-002 (requires `[deep]`)

Rust joins `GO-DUP-001 / C-DUP-001` and `GO-MAINT-001/002 / C-MAINT-001/002`
above with identical thresholds and reporting, through `tree-sitter-rust`.
Functions are `function_item`; closures are their own scope and are not
entered; `match` arms count as cases with the `_ =>` wildcard arm treated as
the default (not a decision); `line_comment`/`block_comment` are ignored.
Calibration: ripgrep's `pcre2` and `regex` matcher crates carry the
well-known duplicated `word`/`line_terminator_crlf`/`case_smart` trio, which
`RS-DUP-001` reports.

## RS-COR-003: Blocking call in async function

**Category:** Correctness
**Default severity:** Warning
**Confidence:** Medium

The Rust counterpart of PY-COR-005 / CS-COR-004 / KT-COR-004 / TS-COR-003.
Inside an `async fn`, `std::thread::sleep`, any `std::fs::*` call,
`.block_on(…)`, `std::net::TcpStream::connect` or `reqwest::blocking` stalls
the executor thread. Closures are excluded — `spawn_blocking(|| std::fs::read(p))`
is the correct fix and must not be reported — and a file that imports
`tokio::fs`, `async_std::fs`, `async_fs` or `smol::fs` keeps its unqualified
`fs::read(…)` calls (they are the async versions); fully qualified
`std::fs::` always fires.

```rust
// Non-compliant
async fn load(p: &str) -> String {
    std::thread::sleep(Duration::from_millis(50));
    std::fs::read_to_string(p).unwrap()
}

// Compliant
async fn load(p: &str) -> std::io::Result<String> {
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::fs::read_to_string(p).await
}
```

## RS-COR-004: Crate-wide lint allow without reason

**Category:** Correctness
**Default severity:** Warning
**Confidence:** High

A crate-level inner attribute `#![allow(…)]` naming `dead_code`, `unused`,
`unused_imports`, `unused_variables`, `warnings` or `clippy::all` silences
the compiler for the whole crate with no record of why — "How do you disable
dead code warnings at the crate level" is Stack Overflow's 4th most-voted
Rust question, and the accepted answer is the pattern this rule reports.
`reason = "…"` (stable since Rust 1.81) documents the suppression and is not
reported; item-scoped `#[allow(dead_code)]` and narrow lints
(`non_snake_case`) are not reported.

```rust
// Non-compliant
#![allow(dead_code, unused_imports)]

// Compliant
#![allow(dead_code, reason = "generated bindings are pruned at link time")]
#[allow(dead_code)]
fn kept_for_ffi_layout() {}
```

# Security rules (`*-SEC-*`)

Added in 3.2.0. Every rule fires on a call shape or a literal the lexer can
see — never on where a value came from. That is the honest boundary for a
bounded lexer: `system(cmd)` with a non-literal `cmd` is reportable; "user
input reaches `open()`" is not (that needs taint tracking, which Semgrep and
CodeQL own). Dependency vulnerabilities are also out of scope: they need a
database, so either network egress or a stale bundled copy, and this tool
is zero-egress by design — use `pip-audit`, `osv-scanner` or Dependabot.

Every security rule:

* has category `security` and default severity `warning`, so an existing
  `--fail-on error` gate does not start failing on upgrade;
* is anchored to one or more CWE identifiers and carries a SARIF
  `security-severity` (CVSS-like), rendered as `properties.security-severity`
  and `properties.tags: ["security", "external/cwe/cwe-NNN"]` on the rule
  descriptor. GitHub code scanning classifies these as security alerts and
  ranks them by that number. The eight dynamic-SQL rules (`PY-COR-007`,
  `*-COR-002`) keep their identifiers but are tagged `CWE-89` / `8.8` too;
* documents its `not_when` conditions (`explain_rule`), including whether a
  conventional test path downgrades the finding to `note` — TLS-off and
  trust-all fixtures are the norm in tests, shell and `eval` are not;
* can be suppressed on its line with a reason, in **every** language:

```go
cfg := &tls.Config{InsecureSkipVerify: true} // cqa: ignore=GO-SEC-001 reason="local test proxy"
```

`//`, `#`, `/* */` and `--` comments are recognised; a directive with a
blank reason, or naming a different rule, does not suppress. (Python has had
this directive since 2.x; 3.2.0 extends it to the other seven languages for
all rules, not only security.)

Calibration: on the 24-project corpus plus four of the author's repositories
the family produced 94 findings (46 warnings, 48 test-path notes), each
traced to source; two false-positive classes found there (a TypeScript
interface method literally named `eval`, C adjacent-literal concatenation
around `#ifdef`) were fixed before release and are locked by tests. Scores
did not move — findings are reported, never scored.

| Rule | Fires on | CWE | sec-sev | Test path |
|---|---|---|---|---|
| PY-SEC-001 | `pickle`/`marshal`/`shelve`/`dill` loads; `yaml.load` without `SafeLoader`/`CSafeLoader`/`BaseLoader`; `yaml.unsafe_load` | 502 | 8.8 | note |
| PY-SEC-002 | `subprocess.*(cmd, shell=True)`, `os.system(cmd)`, `os.popen(cmd)` with non-literal `cmd` | 78 | 8.8 | warning |
| PY-SEC-003 | bare `eval(x)` / `exec(x)` with non-literal `x` (`ast.literal_eval`, `df.eval` never) | 95 | 8.8 | warning |
| PY-SEC-004 | `verify=False`, `ssl._create_unverified_context()`, `CERT_NONE` in `cert_reqs`/`verify_mode`, `check_hostname = False` | 295 | 7.4 | note |
| PY-SEC-005 | `random.*` bound to a secret-shaped name (`token`, `secret`, `password`, `nonce`, `salt`, `otp`, `api_key`, `session_id`, `csrf`, …); `SystemRandom`/`secrets` never | 330 | 5.9 | warning |
| GO-SEC-001 | `InsecureSkipVerify: true` | 295 | 7.4 | note |
| GO-SEC-002 | `exec.Command("sh"\|"bash"\|"cmd", "-c", x)` / `CommandContext` with non-literal `x` | 78 | 8.8 | warning |
| GO-SEC-003 | `math/rand` (import-checked) bound to a secret-shaped name | 338 | 5.9 | warning |
| JAVA-SEC-001 / KT-SEC-001 | `new ObjectInputStream(`, `.readObject()`, `XMLDecoder` | 502 | 8.8 | note |
| JAVA-SEC-002 / KT-SEC-002 | `Runtime.getRuntime().exec(x)`, `ProcessBuilder("sh", "-c", x)` with non-literal `x` | 78 | 8.8 | warning |
| JAVA-SEC-003 / KT-SEC-003 | empty `checkServerTrusted`/`checkClientTrusted`, `verify(..., SSLSession) { return true; }`, `NoopHostnameVerifier`, `ALLOW_ALL_HOSTNAME_VERIFIER`, `TrustAllStrategy` | 295 | 7.4 | note |
| CS-SEC-001 | `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, `ObjectStateFormatter`, Newtonsoft `TypeNameHandling.All/Auto/Objects/Arrays` | 502 | 8.8 | note |
| CS-SEC-002 | `Process.Start("cmd.exe"\|"sh", x)` / `new ProcessStartInfo(shell, x)` with non-literal or interpolated `x` | 78 | 8.8 | warning |
| CS-SEC-003 | certificate validation callback `=> true` / `delegate { return true; }`, `DangerousAcceptAnyServerCertificateValidator` | 295 | 7.4 | note |
| TS-SEC-001 | `eval(x)`, `new Function(..., x)` with non-literal `x`; declarations named `eval` are skipped | 95 | 8.8 | warning |
| TS-SEC-002 | `child_process` `exec`/`execSync` with template/concat command; `spawn`/`execFile` with `shell: true`. Binding resolved from the import, so `RegExp.exec` is never confused with it | 78 | 8.8 | warning |
| TS-SEC-003 | `innerHTML`/`outerHTML` `=`/`+=`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML={{__html: x}}` with non-literal `x`; a leading `DOMPurify.sanitize(`/`sanitizeHtml(`/`*.sanitize(` is silent | 79 | 6.1 | note |
| TS-SEC-004 | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = "0"` | 295 | 7.4 | note |
| C-SEC-001 | calls to `gets`, `strcpy`, `strcat`, `stpcpy`, `sprintf`, `vsprintf`, `wcscpy`, `wcscat`; declarations, `#define`s, member calls and `my_strcpy` are not | 120, 676 | 7.5 | warning |
| C-SEC-002 | `system(x)` / `popen(x, …)` with non-literal `x` | 78 | 8.8 | warning |
| C-SEC-003 | `printf`-family / `syslog` whose format is a non-literal **and** the last argument (`-Wformat-security`); ALL_CAPS macros are treated as literals | 134 | 7.5 | warning |
| RS-SEC-001 | `unsafe {`, `unsafe fn`, `unsafe impl` with no `// SAFETY:` (or `# Safety` doc) in the comment block above, on the line, or first inside the block — clippy `undocumented_unsafe_blocks` | 119 | 5.9 | note |
| RS-SEC-002 | `Command::new("sh")` … `.arg("-c").arg(x)` / `.args(["-c", x])` with non-literal `x` | 78 | 8.8 | warning |
| RS-SEC-003 | reqwest `danger_accept_invalid_certs(true)` / `danger_accept_invalid_hostnames(true)`, rustls `.dangerous()` | 295 | 7.4 | note |

Deliberately not rules: weak hashing (`md5` for a cache key is fine — the
rule is context-blind and is Bandit's worst false positive), hardcoded
secrets (gitleaks owns it, and literal blanking makes this lexer
structurally poor at it), path traversal / open redirect / SSRF (taint).

```python
# Non-compliant
subprocess.run(f"convert {path} out.png", shell=True)
data = yaml.load(text)
token = random.randint(0, 2**64)

# Compliant
subprocess.run(["convert", path, "out.png"])
data = yaml.safe_load(text)
token = secrets.token_urlsafe(32)
```

## Per-rule detail

One subsection per security rule, mirroring `RuleMetadata` (the text
`explain_rule` returns): the call shape that fires, every `not_when`
condition, and the remediation. The SARIF `helpUri` of each security rule
points at its subsection; `tests/test_rule_help.py` keeps the headings and
the metadata in step.

### PY-SEC-001: Unsafe deserialization of untrusted data

`unsafe-deserialization` · CWE-502 · security-severity 8.8 · confidence high · test path: note

pickle/marshal/shelve/dill loads, or yaml.load without a safe Loader, can instantiate arbitrary objects and run code from the payload.

**Fires on:** `pickle`/`marshal`/`shelve`/`dill` loads; `yaml.load` without `SafeLoader`/`CSafeLoader`/`BaseLoader`; `yaml.unsafe_load`

**Not reported when:**

* yaml.load/load_all passes Loader=SafeLoader, CSafeLoader, BaseLoader or CBaseLoader (positionally or by keyword); yaml.safe_load is never reported.
* The call is not one of the fixed pickle/cPickle/_pickle/marshal/shelve/dill/yaml.unsafe_load targets (python_security._UNSAFE_LOADS).
* The payload is a direct `dumps(...)`/`dump(...)` call in the same expression (`pickle.loads(pickle.dumps(x))`): the bytes were produced right there, so no attacker input reaches the deserializer. A name bound elsewhere is still reported.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Deserialize with a format that cannot execute code (json, yaml.safe_load) or restrict the loader.

### PY-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

subprocess.*(cmd, shell=True), os.system(cmd) or os.popen(cmd) with a non-literal command lets a shell re-parse runtime data.

**Fires on:** `subprocess.*(cmd, shell=True)`, `os.system(cmd)`, `os.popen(cmd)` with non-literal `cmd`

**Not reported when:**

* The command is a string literal, or the subprocess call has no shell=True keyword (a list of arguments is never reported).
* os.system/os.popen are only recognised through the `os.` qualifier; a `from os import system` call is not seen.

**Remediation:** Pass an argument list without shell=True; quote with shlex.quote if a shell is unavoidable.

### PY-SEC-003: eval/exec of a runtime string

`dynamic-code-execution` · CWE-95 · security-severity 8.8 · confidence high · test path: warning

eval() or exec() receives a value that is not a string literal.

**Fires on:** bare `eval(x)` / `exec(x)` with non-literal `x` (`ast.literal_eval`, `df.eval` never)

**Not reported when:**

* The first argument is a string literal, or the callee is an attribute (pandas `df.eval`, `ast.literal_eval`) rather than the bare builtin.

**Remediation:** Use ast.literal_eval for data, a dispatch table for behaviour, or importlib for module names.

### PY-SEC-004: TLS certificate verification disabled

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

verify=False, ssl._create_unverified_context(), ssl.CERT_NONE or check_hostname = False turns off peer authentication.

**Fires on:** `verify=False`, `ssl._create_unverified_context()`, `CERT_NONE` in `cert_reqs`/`verify_mode`, `check_hostname = False`

**Not reported when:**

* verify= is anything other than the literal False (a CA bundle path is the recommended form), or CERT_NONE appears outside a cert_reqs/verify_mode slot.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Keep verification on; point verify= at a CA bundle for private CAs.

### PY-SEC-005: Non-cryptographic random used for a secret

`insecure-random-for-secret` · CWE-330 · security-severity 5.9 · confidence medium · test path: warning

A value bound to a secret-shaped name (token, password, nonce, salt, otp, api_key, session id, csrf) is produced by the random module.

**Fires on:** `random.*` bound to a secret-shaped name (`token`, `secret`, `password`, `nonce`, `salt`, `otp`, `api_key`, `session_id`, `csrf`, …); `SystemRandom`/`secrets` never

**Not reported when:**

* The bound name or keyword does not match the secret-shaped pattern (languages/_security.is_secret_name); `counter = random.randint(...)` is fine.
* The expression mentions SystemRandom, or uses the secrets module.

**Remediation:** Generate secrets with the secrets module (token_urlsafe, choice).

### GO-SEC-001: TLS certificate verification disabled

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

tls.Config sets InsecureSkipVerify: true.

**Fires on:** `InsecureSkipVerify: true`

**Not reported when:**

* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Verify certificates; load a private CA into tls.Config.RootCAs.

### GO-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

exec.Command("sh", "-c", cmd) (or CommandContext) with a non-literal cmd.

**Fires on:** `exec.Command("sh"|"bash"|"cmd", "-c", x)` / `CommandContext` with non-literal `x`

**Not reported when:**

* The program is not a shell (`exec.Command(cmd)` and `exec.Command("ls", arg)` are not reported), the flag is not -c, or the command string is a literal.

**Remediation:** Call the binary directly with exec.Command(name, args...).

### GO-SEC-003: math/rand used for a secret

`insecure-random-for-secret` · CWE-338 · security-severity 5.9 · confidence medium · test path: warning

A value bound to a secret-shaped name is produced by math/rand.

**Fires on:** `math/rand` (import-checked) bound to a secret-shaped name

**Not reported when:**

* The file does not import math/rand (crypto/rand is fine), or the bound name is not secret-shaped (languages/_security.is_secret_name).

**Remediation:** Use crypto/rand for tokens, keys, nonces and passwords.

### JAVA-SEC-001: Java native deserialization

`unsafe-deserialization` · CWE-502 · security-severity 8.8 · confidence high · test path: note

ObjectInputStream / readObject() / XMLDecoder instantiate arbitrary classes named by the stream.

**Fires on:** `new ObjectInputStream(`, `.readObject()`, `XMLDecoder`

**Not reported when:**

* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Use a schema-bound format (JSON, protobuf) or an ObjectInputFilter allowlist.

### JAVA-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

Runtime.getRuntime().exec(cmd) or ProcessBuilder("sh", "-c", cmd) with a non-literal cmd.

**Fires on:** `Runtime.getRuntime().exec(x)`, `ProcessBuilder("sh", "-c", x)` with non-literal `x`

**Not reported when:**

* The exec/ProcessBuilder command is a string literal, or ProcessBuilder's program is not a shell / its second argument is not -c.

**Remediation:** Pass the program and each argument separately to ProcessBuilder.

### JAVA-SEC-003: TLS certificate or hostname verification disabled

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

A trust-all TrustManager (empty checkServerTrusted), a hostname verifier returning true, NoopHostnameVerifier or ALLOW_ALL_HOSTNAME_VERIFIER.

**Fires on:** empty `checkServerTrusted`/`checkClientTrusted`, `verify(..., SSLSession) { return true; }`, `NoopHostnameVerifier`, `ALLOW_ALL_HOSTNAME_VERIFIER`, `TrustAllStrategy`

**Not reported when:**

* checkServerTrusted has a non-empty body, or the HostnameVerifier does more than `return true` (comments are blanked, so a commented empty body still counts).
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Keep the default TrustManager and HostnameVerifier; add a private CA to a truststore.

### KT-SEC-001: Java native deserialization

`unsafe-deserialization` · CWE-502 · security-severity 8.8 · confidence high · test path: note

ObjectInputStream / readObject() / XMLDecoder instantiate arbitrary classes named by the stream.

**Fires on:** `new ObjectInputStream(`, `.readObject()`, `XMLDecoder`

**Not reported when:**

* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Use a schema-bound format (JSON, protobuf) or an ObjectInputFilter allowlist.

### KT-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

Runtime.getRuntime().exec(cmd) or ProcessBuilder("sh", "-c", cmd) with a non-literal cmd.

**Fires on:** `Runtime.getRuntime().exec(x)`, `ProcessBuilder("sh", "-c", x)` with non-literal `x`

**Not reported when:**

* The exec/ProcessBuilder command is a string literal, or ProcessBuilder's program is not a shell / its second argument is not -c.

**Remediation:** Pass the program and each argument separately to ProcessBuilder.

### KT-SEC-003: TLS certificate or hostname verification disabled

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

A trust-all TrustManager (empty checkServerTrusted), a hostname verifier returning true, NoopHostnameVerifier or ALLOW_ALL_HOSTNAME_VERIFIER.

**Fires on:** empty `checkServerTrusted`/`checkClientTrusted`, `verify(..., SSLSession) { return true; }`, `NoopHostnameVerifier`, `ALLOW_ALL_HOSTNAME_VERIFIER`, `TrustAllStrategy`

**Not reported when:**

* checkServerTrusted has a non-empty body, or the verify override is not `= true` / `{ return true }`.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Keep the default TrustManager and HostnameVerifier; add a private CA to a truststore.

### CS-SEC-001: Type-resolving deserializer

`unsafe-deserialization` · CWE-502 · security-severity 8.8 · confidence high · test path: note

BinaryFormatter, NetDataContractSerializer, LosFormatter, SoapFormatter, ObjectStateFormatter or Newtonsoft TypeNameHandling other than None.

**Fires on:** `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`, `ObjectStateFormatter`, Newtonsoft `TypeNameHandling.All/Auto/Objects/Arrays`

**Not reported when:**

* TypeNameHandling.None; serializers other than the fixed list (System.Text.Json, XmlSerializer, DataContractSerializer) are never reported.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Use System.Text.Json or a DataContract serializer with known types.

### CS-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

Process.Start("cmd.exe", args) or new ProcessStartInfo("sh", args) with non-literal args.

**Fires on:** `Process.Start("cmd.exe"|"sh", x)` / `new ProcessStartInfo(shell, x)` with non-literal or interpolated `x`

**Not reported when:**

* The program is not a shell (`Process.Start(exe, args)`), or the arguments are a plain literal without interpolation or concatenation.

**Remediation:** Start the program directly and use ProcessStartInfo.ArgumentList.

### CS-SEC-003: Certificate validation callback accepts everything

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

ServerCertificateCustomValidationCallback / ServerCertificateValidationCallback returns true, or DangerousAcceptAnyServerCertificateValidator is used.

**Fires on:** certificate validation callback `=> true` / `delegate { return true; }`, `DangerousAcceptAnyServerCertificateValidator`

**Not reported when:**

* The callback body is anything other than a constant `true`.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Remove the callback or validate the chain; trust a private CA via the store.

### TS-SEC-001: eval / new Function of a runtime string

`dynamic-code-execution` · CWE-95 · security-severity 8.8 · confidence high · test path: warning

eval(x) or new Function(..., x) receives a value that is not a string literal.

**Fires on:** `eval(x)`, `new Function(..., x)` with non-literal `x`; declarations named `eval` are skipped

**Not reported when:**

* The evaluated argument (last argument for new Function) is a string literal; `obj.eval(...)` is not the global eval and is not reported.

**Remediation:** Use JSON.parse for data and a dispatch table or dynamic import for behaviour.

### TS-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

child_process exec/execSync with a non-literal command, or spawn/execFile with { shell: true } and a non-literal program.

**Fires on:** `child_process` `exec`/`execSync` with template/concat command; `spawn`/`execFile` with `shell: true`. Binding resolved from the import, so `RegExp.exec` is never confused with it

**Not reported when:**

* The file does not import child_process (`RegExp.prototype.exec` is never confused with it), the command is a literal without `${}`/`+`, or spawn/execFile is called without `shell: true`.

**Remediation:** Use execFile/spawn with an argument array and no shell option.

### TS-SEC-003: Runtime value written as HTML

`html-injection-sink` · CWE-79 · security-severity 6.1 · confidence medium · test path: note

innerHTML/outerHTML assignment, insertAdjacentHTML, document.write or dangerouslySetInnerHTML receives a non-literal value.

**Fires on:** `innerHTML`/`outerHTML` `=`/`+=`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML={{__html: x}}` with non-literal `x`; a leading `DOMPurify.sanitize(`/`sanitizeHtml(`/`*.sanitize(` is silent

**Not reported when:**

* The assigned value is a string literal, or starts with a recognised sanitizer call (DOMPurify.sanitize, sanitizeHtml, escapeHtml, *.sanitize).
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Set textContent, build DOM nodes, or sanitize with DOMPurify first.

### TS-SEC-004: TLS certificate verification disabled

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

rejectUnauthorized: false, or NODE_TLS_REJECT_UNAUTHORIZED set to '0'.

**Fires on:** `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = "0"`

**Not reported when:**

* NODE_TLS_REJECT_UNAUTHORIZED is compared or set to anything other than the literal '0'.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Keep rejectUnauthorized on; pass a private CA through the ca option.

### C-SEC-001: Unbounded buffer write

`unbounded-buffer-write` · CWE-120, CWE-676 · security-severity 7.5 · confidence high · test path: warning

gets, strcpy, strcat, stpcpy, sprintf, vsprintf, wcscpy or wcscat is called; none bounds the bytes written.

**Fires on:** calls to `gets`, `strcpy`, `strcat`, `stpcpy`, `sprintf`, `vsprintf`, `wcscpy`, `wcscat`; declarations, `#define`s, member calls and `my_strcpy` are not

**Not reported when:**

* The identifier is declared rather than called (`char *strcpy(`, `#define strcpy`), is a member call (`obj.strcpy(`), or is a differently named function (`my_strcpy`).

**Remediation:** Use the bounded form (strlcpy/strncpy_s, snprintf, fgets) or std::string.

### C-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

system(cmd) or popen(cmd, mode) with a non-literal cmd.

**Fires on:** `system(x)` / `popen(x, …)` with non-literal `x`

**Not reported when:**

* The command is a string literal, or system/popen is being declared.

**Remediation:** Use execve/posix_spawn with an argument vector.

### C-SEC-003: Runtime string used as a format

`format-string-from-runtime-value` · CWE-134 · security-severity 7.5 · confidence medium · test path: warning

printf-family or syslog call whose format argument is a non-literal and the last argument (the -Wformat-security shape).

**Fires on:** `printf`-family / `syslog` whose format is a non-literal **and** the last argument (`-Wformat-security`); ALL_CAPS macros are treated as literals

**Not reported when:**

* The format is a string literal or an ALL_CAPS macro constant, or further arguments follow it (`printf(fmt, x)` is not this shape).

**Remediation:** Pass a literal format and the value as an argument: printf("%s", msg).

### RS-SEC-001: unsafe without a SAFETY comment

`undocumented-unsafe` · CWE-119 · security-severity 5.9 · confidence medium · test path: note

An unsafe block, fn or impl has no SAFETY comment (or # Safety doc section) stating the invariants it relies on.

**Fires on:** `unsafe {`, `unsafe fn`, `unsafe impl` with no `// SAFETY:` (or `# Safety` doc) in the comment block above, on the line, or first inside the block — clippy `undocumented_unsafe_blocks`

**Not reported when:**

* A comment block immediately above the unsafe item, its own line, or the first line inside the block contains `SAFETY` or `# Safety`.
* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Add `// SAFETY: ...` above the block explaining why the operation is sound.

### RS-SEC-002: Shell command assembled at runtime

`shell-command-from-runtime-string` · CWE-78 · security-severity 8.8 · confidence medium · test path: warning

Command::new("sh") followed by .arg("-c").arg(cmd) or .args(["-c", cmd]) with a non-literal cmd.

**Fires on:** `Command::new("sh")` … `.arg("-c").arg(x)` / `.args(["-c", x])` with non-literal `x`

**Not reported when:**

* Command::new's program is not a shell, no -c flag precedes the argument, or the argument is a string literal.

**Remediation:** Run the program directly with Command::new(program).args([...]).

### RS-SEC-003: TLS certificate verification disabled

`tls-verification-disabled` · CWE-295 · security-severity 7.4 · confidence high · test path: note

reqwest danger_accept_invalid_certs(true) / danger_accept_invalid_hostnames(true) or rustls .dangerous().

**Fires on:** reqwest `danger_accept_invalid_certs(true)` / `danger_accept_invalid_hostnames(true)`, rustls `.dangerous()`

**Not reported when:**

* The file is on a conventional test path (tests/, __tests__/, spec/, *_test.go, *.spec.ts, *Test.kt, test_*.py): the finding is downgraded to informational, not dropped — disabled TLS verification and trust-all fixtures are the norm in tests (languages/_parity.py: downgrade_in_tests).

**Remediation:** Keep verification on; add a private CA with add_root_certificate.

