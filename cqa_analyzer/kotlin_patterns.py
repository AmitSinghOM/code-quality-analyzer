"""Kotlin DSA and System Design pattern definitions.

Kotlin shares the JVM, its standard library, build tools, and frameworks
with Java, so the Kotlin catalog is the Java catalog extended with
Kotlin-specific idioms: ``kotlinx.coroutines`` for concurrency, Ktor and
http4k for APIs, Exposed/Room/Ktorm for data access, Koin/Hilt for
dependency injection, kotest/MockK for testing, and the ``mapOf`` /
``mutableListOf`` collection builders.

Every pattern ID exists in the Python catalog (regression-locked).
"""

from __future__ import annotations

from copy import deepcopy

from .java_patterns import JAVA_DESIGN_PATTERNS, JAVA_DSA_PATTERNS

KOTLIN_DSA_PATTERNS = deepcopy(JAVA_DSA_PATTERNS)
KOTLIN_DESIGN_PATTERNS = deepcopy(JAVA_DESIGN_PATTERNS)

_EXTRA_DSA = {
    "hash_map": {"identifiers": ["mutablemapof", "hashmapof", "linkedmapof", "mapof"]},
    "set_operations": {
        "identifiers": ["mutablesetof", "hashsetof", "setof", "intersect", "union", "subtract"]
    },
    "sorting": {
        "identifiers": [
            "sortedby",
            "sortby",
            "sortedwith",
            "sorteddescending",
            "sortedbydescending",
        ]
    },
    "queue_stack": {"identifiers": ["ardeque", "removefirst", "removelast", "addfirst", "addlast"]},
}
_EXTRA_DESIGN = {
    "api_design": {
        "imports": ["io.ktor", "org.http4k", "io.micronaut", "org.springframework.web"],
        "identifiers": ["routing", "embeddedserver", "install"],
    },
    "database_orm": {
        "imports": [
            "org.jetbrains.exposed",
            "io.r2dbc",
            "androidx.room",
            "org.ktorm",
            "app.cash.sqldelight",
        ],
    },
    "dependency_injection": {
        "imports": ["org.koin", "dagger.hilt", "dagger", "javax.inject", "jakarta.inject"],
        "identifiers": ["koin", "inject", "single", "factory", "hiltviewmodel"],
    },
    "concurrency": {
        "imports": ["kotlinx.coroutines", "kotlinx.coroutines.flow"],
        "identifiers": [
            "launch",
            "async",
            "runblocking",
            "withcontext",
            "coroutinescope",
            "dispatchers",
            "flow",
            "channel",
            "mutex",
        ],
    },
    "testing": {
        "imports": ["io.kotest", "io.mockk", "kotlin.test", "org.junit"],
        "identifiers": ["shouldbe", "mockk", "every", "verify", "test"],
    },
    "logging": {
        "imports": ["io.github.oshai", "mu.kotlinlogging", "timber.log", "org.slf4j"],
        "identifiers": ["kotlinlogging", "logger", "timber"],
    },
    "error_handling": {
        "identifiers": ["runcatching", "getorelse", "onfailure", "result"],
    },
}

for _name, _extra in _EXTRA_DSA.items():
    for _key, _values in _extra.items():
        KOTLIN_DSA_PATTERNS[_name][_key] = list(KOTLIN_DSA_PATTERNS[_name].get(_key, [])) + _values
for _name, _extra in _EXTRA_DESIGN.items():
    for _key, _values in _extra.items():
        KOTLIN_DESIGN_PATTERNS[_name][_key] = (
            list(KOTLIN_DESIGN_PATTERNS[_name].get(_key, [])) + _values
        )
