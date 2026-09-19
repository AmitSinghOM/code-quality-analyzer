# 3.2.0 security family — before/after calibration record (2026-09-19)

Method: `scripts/findings_snapshot.py snapshot` on `main` (3.1.0) and again on
`dev/v3.2.0-security-rules` against the **same kept clones** of the 24-project
calibration corpus plus four local repositories and the analyzer itself; then
`scripts/findings_snapshot.py diff before.json after.json --rules SEC`.
A rule shipped only if every hit below was traced to source and the scores
did not move.

Verdict: 28 of 29 scores unchanged to the decimal; the analyzer's own score
moved 7.4 -> 7.5 because its new source files add pattern evidence (its own
finding count is unchanged at 149 after refactoring the first draft's
complexity hits away rather than suppressing them). The private repository's non-security count
changes are working-tree edits by a concurrent session in five feed/post
files, not analyzer behaviour. Two false-positive classes were found in the
first after-run and fixed before this record: a TypeScript interface method
literally named `eval(script: string, ...)` (ioredis, 9 hits -> 0) and C
adjacent-literal concatenation around `#ifdef` inside `fprintf` (jq, 1 -> 0);
both are locked in `tests/test_security_rules.py`.

Rules with **no** corpus hits — precision proven on fixtures only:
`PY-SEC-002/003/005`, `GO-SEC-002/003`, `JAVA-SEC-002`, `KT-SEC-002`,
`CS-SEC-001/002/003`, `TS-SEC-001/002`, `C-SEC-002`, `RS-SEC-002`.

Known residual: ioredis `docs/assets/main.js` is a minified, vendored typedoc
bundle; its `innerHTML` assignments are genuine shapes but not actionable for
the project. A scanner-level minified-file exclusion is the right fix
(roadmap), not a rule change.

| project | score before | score after | findings before | findings after | rules added | rules removed |
|---|---|---|---|---|---|---|
| BurntSushi/ripgrep | 7.0 | 7.0 | 98 | 98 | - | - |
| FastEndpoints/FastEndpoints | 8.4 | 8.4 | 136 | 136 | - | - |
| private repo (Go+TS) | 7.7 | 7.7 | 133 | 153 | TS-SEC-003 (1) | - |
|  | | | | | changed counts: {'GO-MAINT-002': (33, 39), 'GO-DUP-001': (10, 13), 'GO-MAINT-001': (74, 84)} | |
| JakeWharton/diffuse | 4.8 | 4.8 | 1 | 1 | - | - |
| StackExchange/StackExchange.Redis | 8.3 | 8.3 | 392 | 392 | - | - |
| cloudscale-backend | 8.1 | 8.1 | 69 | 69 | - | - |
| code-quality-analyzer | 7.4 | 7.5 **MOVED** | 149 | 149 | - | - |
| crackthecodeabhi/kreds | 3.8 | 3.8 | 7 | 7 | - | - |
| dotnet-outdated/dotnet-outdated | 5.1 | 5.1 | 17 | 17 | - | - |
| drogonframework/drogon | 7.9 | 7.9 | 621 | 621 | - | - |
| fastapi-microservices-platform | 8.6 | 8.6 | 110 | 110 | - | - |
| fastapi/fastapi | 7.6 | 7.6 | 858 | 861 | PY-SEC-001 (2), TS-SEC-003 (1) | - |
| gin-gonic/gin | 5.8 | 5.8 | 204 | 208 | GO-SEC-001 (4) | - |
| google/zx | 5.0 | 5.0 | 41 | 41 | - | - |
| httpie/cli | 6.2 | 6.2 | 75 | 77 | PY-SEC-004 (2) | - |
| javalin/javalin | 7.3 | 7.3 | 58 | 62 | KT-SEC-003 (4) | - |
| jbangdev/jbang | 6.8 | 6.8 | 131 | 133 | JAVA-SEC-003 (2) | - |
| jqlang/jq | 4.4 | 4.4 | 113 | 119 | C-SEC-001 (6) | - |
| junegunn/fzf | 6.0 | 6.0 | 230 | 230 | - | - |
| ktorio/ktor | 8.1 | 8.1 | 269 | 273 | KT-SEC-001 (2), KT-SEC-003 (2) | - |
| nestjs/nest | 7.6 | 7.6 | 88 | 88 | - | - |
| redis-rs/redis-rs | 8.8 | 8.8 | 73 | 89 | RS-SEC-001 (6), RS-SEC-003 (10) | - |
| redis/go-redis | 8.9 | 8.9 | 769 | 789 | GO-SEC-001 (20) | - |
| redis/hiredis | 3.2 | 3.2 | 91 | 98 | C-SEC-001 (7) | - |
| redis/ioredis | 6.5 | 6.5 | 112 | 121 | TS-SEC-003 (4), TS-SEC-004 (5) | - |
| redis/jedis | 8.7 | 8.7 | 338 | 352 | JAVA-SEC-001 (10), JAVA-SEC-003 (4) | - |
| redis/redis-py | 9.0 | 9.0 | 1560 | 1562 | PY-SEC-004 (2) | - |
| tokio-rs/axum | 8.7 | 8.7 | 39 | 39 | - | - |
| wallet-transfer-service | 6.0 | 6.0 | 8 | 8 | - | - |

### Every hit from a rule that did not exist before
| project | rule | severity | location | message |
|---|---|---|---|---|
| private repo (Go+TS) | TS-SEC-003 | warning | app layout (JSON-LD script) | Unescaped markup is written to the DOM from a runtime value (CWE-79). |
| fastapi/fastapi | PY-SEC-001 | warning | scripts/docs.py:105 | yaml.unsafe_load deserializes arbitrary objects (CWE-502). |
| fastapi/fastapi | PY-SEC-001 | warning | scripts/docs.py:295 | yaml.unsafe_load deserializes arbitrary objects (CWE-502). |
| fastapi/fastapi | TS-SEC-003 | warning | docs/en/docs/js/termynal.js:228 | Unescaped markup is written to the DOM from a runtime value (CWE-79). |
| gin-gonic/gin | GO-SEC-001 | note | gin_integration_test.go:39 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| gin-gonic/gin | GO-SEC-001 | note | gin_test.go:177 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| gin-gonic/gin | GO-SEC-001 | note | gin_test.go:295 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| gin-gonic/gin | GO-SEC-001 | note | gin_test.go:404 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| httpie/cli | PY-SEC-004 | warning | httpie/internal/update_warnings.py:44 | TLS certificate verification is disabled with verify=False (CWE-295). |
| httpie/cli | PY-SEC-004 | warning | httpie/ssl_.py:89 | TLS certificate verification is disabled with verify=False (CWE-295). |
| javalin/javalin | KT-SEC-003 | note | javalin-ssl/src/test/kotlin/io/javalin/community/ssl/IntegrationTestClass.kt:73 | TLS certificate or hostname verification is disabled (CWE-295). |
| javalin/javalin | KT-SEC-003 | note | javalin-ssl/src/test/kotlin/io/javalin/community/ssl/IntegrationTestClass.kt:74 | TLS certificate or hostname verification is disabled (CWE-295). |
| javalin/javalin | KT-SEC-003 | note | javalin/src/test/java/io/javalin/staticfiles/TestStaticFilesEdgeCases.kt:165 | TLS certificate or hostname verification is disabled (CWE-295). |
| javalin/javalin | KT-SEC-003 | note | javalin/src/test/java/io/javalin/staticfiles/TestStaticFilesEdgeCases.kt:166 | TLS certificate or hostname verification is disabled (CWE-295). |
| jbangdev/jbang | JAVA-SEC-003 | warning | src/main/java/dev/jbang/cli/BaseCommand.java:122 | TLS certificate or hostname verification is disabled (CWE-295). |
| jbangdev/jbang | JAVA-SEC-003 | warning | src/main/java/dev/jbang/cli/BaseCommand.java:125 | TLS certificate or hostname verification is disabled (CWE-295). |
| jqlang/jq | C-SEC-001 | warning | src/compile.c:378 | strcpy() writes without a length bound (CWE-120). |
| jqlang/jq | C-SEC-001 | warning | src/compile.c:379 | strcpy() writes without a length bound (CWE-120). |
| jqlang/jq | C-SEC-001 | warning | src/compile.c:387 | strcpy() writes without a length bound (CWE-120). |
| jqlang/jq | C-SEC-001 | warning | src/compile.c:388 | strcpy() writes without a length bound (CWE-120). |
| jqlang/jq | C-SEC-001 | warning | src/jv_dtoa.c:1656 | strcpy() writes without a length bound (CWE-120). |
| jqlang/jq | C-SEC-001 | warning | tests/jq_fuzz_load_file.c:10 | sprintf() writes without a length bound (CWE-120). |
| ktorio/ktor | KT-SEC-001 | note | ktor-server-test-host/jvm/test/TestApplicationTestJvm.kt:218 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| ktorio/ktor | KT-SEC-001 | note | ktor-server-test-host/jvm/test/TestApplicationTestJvm.kt:361 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| ktorio/ktor | KT-SEC-003 | note | ktor-server-test-base/jvm/src/io/ktor/server/test/base/EngineTestBaseJvm.kt:391 | TLS certificate or hostname verification is disabled (CWE-295). |
| ktorio/ktor | KT-SEC-003 | note | ktor-server-test-base/jvm/src/io/ktor/server/test/base/EngineTestBaseJvm.kt:395 | TLS certificate or hostname verification is disabled (CWE-295). |
| redis-rs/redis-rs | RS-SEC-001 | warning | redis/src/cmd.rs:414 | unsafe code has no SAFETY comment stating the invariants it relies on (CWE-119). |
| redis-rs/redis-rs | RS-SEC-001 | warning | redis/src/cmd.rs:419 | unsafe code has no SAFETY comment stating the invariants it relies on (CWE-119). |
| redis-rs/redis-rs | RS-SEC-001 | warning | redis/src/cmd.rs:420 | unsafe code has no SAFETY comment stating the invariants it relies on (CWE-119). |
| redis-rs/redis-rs | RS-SEC-001 | warning | redis/src/types.rs:954 | unsafe code has no SAFETY comment stating the invariants it relies on (CWE-119). |
| redis-rs/redis-rs | RS-SEC-001 | warning | redis/src/types.rs:959 | unsafe code has no SAFETY comment stating the invariants it relies on (CWE-119). |
| redis-rs/redis-rs | RS-SEC-001 | warning | redis/src/types.rs:960 | unsafe code has no SAFETY comment stating the invariants it relies on (CWE-119). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/aio/smol.rs:190 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/aio/smol.rs:191 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/aio/tokio.rs:129 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/aio/tokio.rs:130 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/connection.rs:923 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/connection.rs:924 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/connection.rs:1232 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | warning | redis/src/connection.rs:1266 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | note | redis/tests/test_cluster.rs:140 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis-rs/redis-rs | RS-SEC-003 | note | redis/tests/test_cluster_async.rs:510 | TLS certificate verification is disabled or replaced (CWE-295). |
| redis/go-redis | GO-SEC-001 | warning | example/tls-cert-auth/main.go:82 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | warning | example/tls-connection/main.go:21 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | warning | example/tls-connection/main.go:104 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | main_test.go:570 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | main_test.go:588 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | maintnotifications/e2e/config_parser_test.go:369 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | maintnotifications/e2e/config_parser_test.go:400 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | options_test.go:50 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | re_endpoints_test.go:186 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | re_endpoints_test.go:205 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | sentinel_test.go:456 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_cert_auth_test.go:112 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_cert_auth_test.go:230 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_cluster_test.go:209 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_standalone_test.go:29 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_standalone_test.go:78 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_test.go:39 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_test.go:212 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_test.go:253 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/go-redis | GO-SEC-001 | note | tls_test.go:274 | TLS certificate verification is disabled (InsecureSkipVerify: true) (CWE-295). |
| redis/hiredis | C-SEC-001 | warning | hiredis.c:523 | sprintf() writes without a length bound (CWE-120). |
| redis/hiredis | C-SEC-001 | warning | hiredis.c:525 | sprintf() writes without a length bound (CWE-120). |
| redis/hiredis | C-SEC-001 | warning | hiredis.c:671 | sprintf() writes without a length bound (CWE-120). |
| redis/hiredis | C-SEC-001 | warning | hiredis.c:674 | sprintf() writes without a length bound (CWE-120). |
| redis/hiredis | C-SEC-001 | warning | test.c:2205 | strcpy() writes without a length bound (CWE-120). |
| redis/hiredis | C-SEC-001 | warning | test.c:2223 | strcpy() writes without a length bound (CWE-120). |
| redis/hiredis | C-SEC-001 | warning | test.c:2236 | strcpy() writes without a length bound (CWE-120). |
| redis/ioredis | TS-SEC-003 | warning | docs/assets/main.js:4 | Unescaped markup is written to the DOM from a runtime value (CWE-79). |
| redis/ioredis | TS-SEC-003 | warning | docs/assets/main.js:4 | Unescaped markup is written to the DOM from a runtime value (CWE-79). |
| redis/ioredis | TS-SEC-003 | warning | docs/assets/main.js:5 | Unescaped markup is written to the DOM from a runtime value (CWE-79). |
| redis/ioredis | TS-SEC-003 | warning | docs/assets/main.js:5 | Unescaped markup is written to the DOM from a runtime value (CWE-79). |
| redis/ioredis | TS-SEC-004 | note | test/functional/tls.ts:31 | TLS certificate verification is disabled (CWE-295). |
| redis/ioredis | TS-SEC-004 | note | test/functional/tls.ts:90 | TLS certificate verification is disabled (CWE-295). |
| redis/ioredis | TS-SEC-004 | note | test/functional/tls.ts:127 | TLS certificate verification is disabled (CWE-295). |
| redis/ioredis | TS-SEC-004 | note | test/unit/connectors/connector.ts:35 | TLS certificate verification is disabled (CWE-295). |
| redis/ioredis | TS-SEC-004 | note | test/unit/connectors/connector.ts:43 | TLS certificate verification is disabled (CWE-295). |
| redis/jedis | JAVA-SEC-001 | warning | src/main/java/redis/clients/jedis/csc/CacheEntry.java:50 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | warning | src/main/java/redis/clients/jedis/csc/CacheEntry.java:51 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/collections/JedisByteHashMapTest.java:132 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/collections/JedisByteHashMapTest.java:133 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/collections/JedisByteHashMapTest.java:201 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/collections/JedisByteHashMapTest.java:202 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/collections/SetFromListTest.java:122 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/collections/SetFromListTest.java:124 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/search/DocumentTest.java:35 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-001 | note | src/test/java/redis/clients/jedis/search/DocumentTest.java:36 | Java native deserialization instantiates arbitrary classes from the stream (CWE-502). |
| redis/jedis | JAVA-SEC-003 | note | src/test/java/redis/clients/jedis/mcf/RedisRestAPIIT.java:50 | TLS certificate or hostname verification is disabled (CWE-295). |
| redis/jedis | JAVA-SEC-003 | note | src/test/java/redis/clients/jedis/mcf/RedisRestAPIIT.java:53 | TLS certificate or hostname verification is disabled (CWE-295). |
| redis/jedis | JAVA-SEC-003 | note | src/test/java/redis/clients/jedis/scenario/LagAwareStrategySslIT.java:213 | TLS certificate or hostname verification is disabled (CWE-295). |
| redis/jedis | JAVA-SEC-003 | note | src/test/java/redis/clients/jedis/scenario/LagAwareStrategySslIT.java:216 | TLS certificate or hostname verification is disabled (CWE-295). |
| redis/redis-py | PY-SEC-004 | warning | redis/http/http_client.py:276 | Hostname verification is disabled (check_hostname = False) (CWE-295). |
| redis/redis-py | PY-SEC-004 | warning | redis/http/http_client.py:277 | TLS peer certificates are not required (ssl.CERT_NONE) (CWE-295). |
