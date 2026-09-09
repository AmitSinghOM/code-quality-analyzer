# Cross-language scoring fairness calibration

**Status:** roadmap item 5, calibration round 1 (2.35.0). Re-run with
`.venv/bin/python scripts/calibration_corpus.py` (development tool: it
clones public repositories; the analyzer itself never touches the
network).

## Question

Does the architecture signal score depend on the *language* a project
is written in, or only on what the project does? Seven languages share
one 56-pattern catalog and one scoring curve, but each language has its
own anchor vocabulary and its own lexer, so a language could be
penalised structurally (catalog gaps, weak anchors) or operationally
(lexer failures that make files non-authoritative).

## Method

A fixed corpus: the **same two domains in every language** — a Redis
client library and a web framework — chosen as the most widely used
project in each language for that domain. Same domain, same
expectations; a systematic gap across languages is a tool defect, a gap
within a language is the project.

Three structural checks were run first, then the corpus was scanned,
then every non-authoritative result was root-caused.

## Structural findings

| check | before | after |
|---|---|---|
| Catalog IDs reachable per language | Go 55/56 (no `hash_map`); TS 53/56 (no `segment_tree`, `fenwick_tree`, `minimum_spanning_tree`) | 56/56 for all seven — locked by `tests/test_fairness.py` |
| Curve ceilings | full marks at weight 12 (DSA) / 22.5 (design); every catalog offers 62.7 / 53.2 | unchanged — catalog size is not the constraint |
| Import-only specs (a pattern only a library can prove) | ≤1 per language | unchanged; allowed only for `database_orm`, `message_queue`, `observability` |

Conclusion: the curve is not what makes languages unequal. Anchor
vocabulary and lexer completeness are.

## Corpus results (after fixes)

| language | domain | repo @ sha | files | lines | score | dsa | design | #dsa | #design | auth |
|---|---|---|---|---|---|---|---|---|---|---|
| c_cpp | redis-client | redis/hiredis @ 33a12fb | 53 | 17594 | 4.1 | 3.0 | 5.28 | 1 | 6 | yes |
| csharp | redis-client | StackExchange/StackExchange.Redis @ 7648fc8 | 700 | 160220 | 8.0 | 7.1 | 8.56 | 7 | 18 | yes |
| go | redis-client | redis/go-redis @ 8010edc | 385 | 174408 | 8.8 | 8.41 | 8.86 | 11 | 20 | yes |
| java | redis-client | redis/jedis @ 6dac31d | 1126 | 251950 | 8.5 | 8.09 | 8.64 | 9 | 18 | yes |
| kotlin | redis-client | crackthecodeabhi/kreds @ 7979192 | 59 | 9952 | 3.8 | 1.0 | 6.2 | 0 | 9 | yes |
| python | redis-client | redis/redis-py @ 5b3c871 | 324 | 207731 | 8.7 | 8.23 | 8.73 | 9 | 19 | yes |
| typescript | redis-client | redis/ioredis @ d1ec3e3 | 424 | 51788 | 6.5 | 5.56 | 7.51 | 4 | 12 | yes |
| c_cpp | web-framework | drogonframework/drogon @ da0f506 | 445 | 100834 | 7.9 | 7.0 | 8.56 | 6 | 18 | yes |
| csharp | web-framework | FastEndpoints/FastEndpoints @ 67370ea | 904 | 86452 | 8.0 | 6.27 | 9.12 | 5 | 22 | yes |
| go | web-framework | gin-gonic/gin @ dcaa429 | 99 | 24099 | 5.6 | 4.39 | 6.8 | 2 | 11 | yes |
| java | web-framework | javalin/javalin @ 219f8c1 | 64 | 36020 | 7.1 | 5.36 | 8.34 | 4 | 17 | yes |
| kotlin | web-framework | ktorio/ktor @ 166c52b | 952 | 134738 | 7.9 | 6.93 | 8.48 | 7 | 17 | yes |
| python | web-framework | fastapi/fastapi @ 50113da | 1138 | 113579 | 7.6 | 6.7 | 8.39 | 5 | 15 | yes |
| typescript | web-framework | nestjs/nest @ 39fbdda | 1838 | 132895 | 7.7 | 6.67 | 8.52 | 6 | 17 | yes |

`files` counts only the row's language; javalin, for example, is 303
Kotlin files plus the 64 Java files counted here.

### Reading the table

- **Size dominates language.** The four large Redis clients (Python,
  Go, Java, C#; 324–1126 files) land within 8.0–8.8. The two small ones
  (Kotlin kreds, 59 files; C hiredis, 53 files) land at 3.8–4.1 — and
  inspection shows why: kreds's only "sorted" mentions are doc comments
  about Redis sorted sets (correctly not evidence) and it uses nothing
  beyond `List<>`; hiredis is a thin C protocol client. Those scores
  are honest, not unfair.
- **Web frameworks cluster at 7.1–8.0** across C++, C#, Java, Kotlin,
  Python, and TypeScript. gin (5.6) is the outlier and is also the
  smallest (99 files, 24K lines); its design column (11 patterns)
  matches its scope.
- **ioredis (6.5)** is mid-pack with 4 DSA / 12 design patterns; a
  TypeScript-specific anchor gap is not evident from the matrix, but
  TypeScript has the fewest DSA anchors after this round and remains
  the language to watch.

## Defects found and fixed in this round

Every non-authoritative result was a lexer bug, and each was
language-specific — exactly the shape of unfairness this review exists
to catch, because a language whose files silently fail lexing is scored
on a lower bound.

| language | defect | example | fix |
|---|---|---|---|
| TypeScript/JS | regex literals containing quotes opened a string (`/\\"/g`); minified bundles hit the same bound | ioredis `lib/DataHandler.ts`, `docs/assets/main.js` | regex literals lexed by previous-significant-token rule and blanked; 100% of ioredis now complete |
| TypeScript/JS | *(introduced by the fix above, caught by dogfooding before release)* JSX closing tags `</p>` and `{x}</b>` read as regex starts, marking 31 TSX files non-authoritative in a private Next.js app | `</AppShell>` | `<`, `>` and `}` are not regex-preceding characters (`=>` is special-cased); an unterminated candidate is ordinary code, never a lexing failure |
| Kotlin | backtick identifiers with apostrophes opened a char literal | javalin ``fun `can't set duplicate cookies`()`` (15 test files) | backtick identifiers lexed as code |
| Kotlin | Kotlin 2.2 multi-dollar interpolation: `$$"""` makes `${` literal | ktor `YamlConfigTest.kt` | template marker follows the string's `$` prefix |
| Kotlin | trailing-lambda calls (`items.sortedBy { }`) were not identifiers | any idiomatic Kotlin | selector/bare call regexes accept `{` |
| Go | no `hash_map` ID at all — maps are a builtin type | go-redis, gin | anchored on `make(map[`, `map[string]` etc. |
| TypeScript | three rare DSA IDs missing | — | added |

Scores moved by at most +0.4 (javalin 6.7 → 7.1, gin 5.2 → 5.6) and no
project moved down.

## What this round does not settle

- **Per-language anchor density** is now equal in *reach* (56/56) but
  not in *depth*: Python has 527 anchor strings, Go 331. The corpus
  does not show that producing systematic bias, but a second corpus
  domain (a CLI tool, or an ORM) would strengthen the claim.
- **Mixed-language projects** are scored on the union of signals, which
  is correct for "what does this system use" but means a polyglot repo
  is compared against single-language curves. No change proposed.
- **Any weight or curve change** remains a `scoring_policy_version`
  bump with a migration note (ADR 002). This round changed none.
- A shared UI-component pattern ID (roadmap 5) is still
  unrepresentable and deferred.

## Pattern matrices

### redis-client: pattern matrix
| pattern | python | go | typescript | java | kotlin | csharp | c_cpp |
|---|---|---|---|---|---|---|---|
| adapter_pattern | x | x |  | x | x |  | x |
| api_design |  | x | x |  |  | x |  |
| authentication | x |  |  | x |  |  |  |
| binary_search | x |  |  |  |  |  |  |
| bit_manipulation | x | x | x | x |  | x | x |
| bloom_filter |  | x |  |  |  |  |  |
| builder_pattern | x | x |  | x | x | x |  |
| caching | x | x | x | x |  | x | x |
| concurrency | x | x | x | x | x | x | x |
| config_management | x | x | x |  |  |  |  |
| consistent_hashing |  | x |  |  |  |  |  |
| database_orm | x |  |  |  |  |  |  |
| decorator_pattern | x | x | x |  | x |  |  |
| dependency_injection |  | x |  |  |  |  |  |
| dynamic_programming | x | x |  |  |  |  |  |
| error_handling | x | x | x | x | x | x | x |
| event_sourcing_cqrs |  |  |  |  |  | x |  |
| factory_pattern | x | x |  | x |  | x |  |
| hash_map | x | x | x | x |  | x |  |
| idempotency | x | x |  | x |  | x |  |
| interval_operations |  | x |  | x |  | x |  |
| linked_list |  | x |  | x |  | x |  |
| logging | x | x |  | x | x | x |  |
| lru_cache_manual | x |  |  | x |  |  |  |
| message_queue |  | x |  |  |  |  |  |
| microservices | x | x | x | x | x |  |  |
| observability | x | x |  | x |  | x | x |
| observer_pattern | x | x | x | x | x | x |  |
| pagination |  |  |  | x |  | x |  |
| prefix_sum |  | x |  | x |  |  |  |
| queue_stack | x | x |  | x |  | x |  |
| rate_limiting | x |  |  | x |  | x |  |
| repository_pattern |  |  |  |  |  | x |  |
| resilience | x | x | x | x |  | x | x |
| segment_tree | x |  |  |  |  |  |  |
| set_operations | x | x | x | x |  | x |  |
| singleton_pattern |  | x | x | x |  | x |  |
| sorting | x | x | x | x |  | x |  |
| strategy_pattern | x | x | x | x |  | x |  |
| testing | x | x | x | x | x | x |  |

### web-framework: pattern matrix
| pattern | python | go | typescript | java | kotlin | csharp | c_cpp |
|---|---|---|---|---|---|---|---|
| adapter_pattern | x |  | x | x | x | x | x |
| api_design | x | x | x | x | x | x | x |
| authentication | x | x |  | x | x | x |  |
| bit_manipulation |  | x | x |  | x | x | x |
| builder_pattern |  | x | x | x | x | x | x |
| caching | x |  | x | x | x | x |  |
| concurrency | x | x | x | x | x | x | x |
| config_management | x |  |  |  | x | x | x |
| database_orm | x | x | x |  |  | x | x |
| decorator_pattern | x | x | x |  | x | x | x |
| dependency_injection | x |  | x | x |  | x |  |
| dynamic_programming | x |  |  |  |  |  |  |
| error_handling | x | x | x | x | x | x | x |
| event_sourcing_cqrs | x |  |  |  |  | x |  |
| factory_pattern |  |  | x | x | x | x | x |
| hash_map | x | x | x | x | x | x | x |
| idempotency |  |  |  | x |  | x |  |
| interval_operations |  |  | x |  |  |  |  |
| linked_list |  |  |  |  | x |  | x |
| logging | x | x |  | x | x | x | x |
| message_queue |  |  | x |  |  |  | x |
| microservices | x |  | x | x | x | x |  |
| monotonic_stack |  |  |  |  | x |  |  |
| observability |  |  | x | x | x | x | x |
| observer_pattern |  |  | x |  |  | x | x |
| queue_stack | x |  |  | x | x | x | x |
| rate_limiting |  |  |  | x | x | x | x |
| repository_pattern |  |  | x |  |  |  |  |
| resilience | x | x |  |  |  |  | x |
| set_operations | x |  | x | x | x | x | x |
| singleton_pattern |  | x | x | x | x | x | x |
| sorting | x |  | x | x | x | x |  |
| strategy_pattern |  |  | x | x | x | x | x |
| testing | x | x |  | x | x | x | x |
| tree_structures |  |  | x |  |  |  | x |

