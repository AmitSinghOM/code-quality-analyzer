"""Path-scoped rule policy (``[overrides."<glob>"]``), ADR 005 decisions 1, 2, 5."""

import json
import random
import time
from pathlib import Path

import pytest

from cqa_analyzer.config import (
    MAX_PATTERN_LENGTH,
    MAX_PATTERNS,
    AnalyzerConfig,
    ConfigError,
    EffectivePolicy,
    OverridePolicy,
    _parse_config,
    load_config,
)

FIXTURES = Path(__file__).parent / "fixtures"

ADR_EXAMPLE = (
    '[overrides."tests/**"]\n'
    'disabled = ["PY-MAINT-003"]\n'
    'severity = { "PY-COR-007" = "note" }\n'
    "\n"
    '[overrides."db/**"]\n'
    'severity = { "PY-COR-007" = "error" }\n'
)


def _config(project, toml: str) -> AnalyzerConfig:
    return load_config(project({".code-quality.toml": toml, "module.py": "VALUE = 1\n"}))


# --- Shape --------------------------------------------------------------------


def test_overrides_table_parses_in_file_order(project):
    config = _config(project, ADR_EXAMPLE)

    assert config.overrides == (
        OverridePolicy(
            glob="tests/**",
            disabled=("PY-MAINT-003",),
            severity=(("PY-COR-007", "note"),),
        ),
        OverridePolicy(glob="db/**", severity=(("PY-COR-007", "error"),)),
    )
    # Still works: a configuration without the table has none.
    assert _config(project, '[rules."PY-COR-001"]\nenabled = false\n').overrides == ()


def test_override_entries_are_normalised(project):
    config = _config(
        project,
        '[overrides."tests\\\\unit\\\\**"]\n'
        'disabled = ["PY-MAINT-003", "PY-COR-001", "PY-MAINT-003"]\n'
        'severity = { "PY-COR-007" = "note", "PY-COR-002" = "error" }\n',
    )

    assert config.overrides == (
        OverridePolicy(
            glob="tests/unit/**",
            disabled=("PY-COR-001", "PY-MAINT-003"),
            severity=(("PY-COR-002", "error"), ("PY-COR-007", "note")),
        ),
    )


@pytest.mark.parametrize(
    "source, message",
    [
        ('[overrides."tests/**"]\nenabled = false\n', r"Unknown overrides\.tests/\*\* key"),
        ('[overrides."/abs/**"]\ndisabled = ["PY-COR-001"]\n', "must be project-relative"),
        ('[overrides."../up/**"]\ndisabled = ["PY-COR-001"]\n', "cannot traverse parent"),
        ('[overrides."a/../b/**"]\ndisabled = ["PY-COR-001"]\n', "cannot traverse parent"),
        ('[overrides.""]\ndisabled = ["PY-COR-001"]\n', "overrides contains an invalid pattern"),
        (
            f'[overrides."{"x" * (MAX_PATTERN_LENGTH + 1)}"]\ndisabled = ["PY-COR-001"]\n',
            "overrides contains an invalid pattern",
        ),
        ('[overrides."tests\\n**"]\ndisabled = ["PY-COR-001"]\n', "invalid pattern"),
        ('[overrides."tests/**"]\ndisabled = ["py-cor-001"]\n', "Invalid rule ID"),
        ('[overrides."tests/**"]\ndisabled = "PY-COR-001"\n', "disabled must be an array"),
        ('[overrides."tests/**"]\ndisabled = ["PY-COR-001", 7]\n', "disabled must be an array"),
        ('[overrides."tests/**"]\nseverity = { bad = "note" }\n', "Invalid rule ID"),
        (
            '[overrides."tests/**"]\nseverity = { "PY-COR-007" = "info" }\n',
            r"severity\.PY-COR-007 must be 'note', 'warning' or 'error'",
        ),
        (
            '[overrides."tests/**"]\nseverity = { "PY-COR-007" = ["note"] }\n',
            "must be 'note', 'warning' or 'error'",
        ),
        ('[overrides."tests/**"]\nseverity = "note"\n', r"severity must be a TOML table"),
        ('[overrides]\n"tests/**" = 1\n', r"overrides\.tests/\*\* must be a TOML table"),
        ("overrides = 1\n", "overrides must be a TOML table"),
    ],
)
def test_invalid_override_is_rejected_before_scanning(project, source, message):
    with pytest.raises(ConfigError, match=message):
        _config(project, source)


def test_exactly_max_pattern_length_glob_is_accepted(project):
    glob = "x" * MAX_PATTERN_LENGTH
    assert (
        _config(project, f'[overrides."{glob}"]\ndisabled = ["PY-COR-001"]\n').overrides[0].glob
        == glob
    )


def test_more_than_max_patterns_tables_are_rejected():
    tables = {f"pkg{i:04d}/**": {"disabled": ["PY-COR-001"]} for i in range(MAX_PATTERNS)}
    assert len(_parse_config({"overrides": tables}).overrides) == MAX_PATTERNS

    tables["one-too-many/**"] = {"disabled": ["PY-COR-001"]}
    with pytest.raises(ConfigError, match="overrides contains too many patterns"):
        _parse_config({"overrides": tables})


def test_well_formed_unknown_rule_ids_stay_inert(project):
    config = _config(project, '[overrides."tests/**"]\ndisabled = ["ZZ-FUTURE-999"]\n')
    policy = config.effective_policy("ZZ-FUTURE-999", "tests/a.py")
    assert policy == EffectivePolicy(enabled=False, severity=None, source="override:tests/**")
    assert config.effective_policy("PY-COR-001", "tests/a.py") == EffectivePolicy(
        enabled=True, severity=None, source="project"
    )


# --- ``note`` severity -------------------------------------------------------


def test_rules_severity_accepts_note(project):
    config = _config(project, '[rules."PY-COR-001"]\nseverity = "note"\n')
    assert config.policy_for("PY-COR-001").severity == "note"
    assert config.effective_policy("PY-COR-001", "a.py") == EffectivePolicy(
        enabled=True, severity="note", source="project"
    )


@pytest.mark.parametrize("source", ['severity = "info"\n', 'severity = ["error"]\n'])
def test_rules_severity_error_names_all_three_levels(project, source):
    with pytest.raises(ConfigError, match=r"must be 'note', 'warning' or 'error'"):
        _config(project, f'[rules."PY-COR-001"]\n{source}')


# --- Resolution --------------------------------------------------------------


def test_longest_literal_prefix_wins_severity(project):
    config = _config(
        project,
        '[overrides."src/db/**"]\nseverity = { "PY-COR-007" = "error" }\n'
        '[overrides."src/**"]\nseverity = { "PY-COR-007" = "warning" }\n',
    )

    assert config.effective_policy("PY-COR-007", "src/db/x.py") == EffectivePolicy(
        enabled=True, severity="error", source="override:src/db/**"
    )
    assert config.effective_policy("PY-COR-007", "src/a.py") == EffectivePolicy(
        enabled=True, severity="warning", source="override:src/**"
    )


def test_equal_literal_prefix_later_table_wins(project):
    first = (
        '[overrides."src/*.py"]\nseverity = { "PY-COR-007" = "note" }\n'
        '[overrides."src/**"]\nseverity = { "PY-COR-007" = "error" }\n'
    )
    reordered = (
        '[overrides."src/**"]\nseverity = { "PY-COR-007" = "error" }\n'
        '[overrides."src/*.py"]\nseverity = { "PY-COR-007" = "note" }\n'
    )

    assert _config(project, first).effective_policy("PY-COR-007", "src/a.py") == EffectivePolicy(
        enabled=True, severity="error", source="override:src/**"
    )
    assert _config(project, reordered).effective_policy(
        "PY-COR-007", "src/a.py"
    ) == EffectivePolicy(enabled=True, severity="note", source="override:src/*.py")


def test_disable_is_monotone_and_names_most_specific_disabler(project):
    config = _config(
        project,
        '[overrides."tests/**"]\ndisabled = ["PY-MAINT-003"]\n'
        '[overrides."tests/unit/**"]\nseverity = { "PY-MAINT-003" = "error" }\n',
    )
    # A more specific table setting a severity does not re-enable the rule.
    assert config.effective_policy("PY-MAINT-003", "tests/unit/a.py") == EffectivePolicy(
        enabled=False, severity=None, source="override:tests/**"
    )

    config = _config(
        project,
        '[overrides."tests/**"]\ndisabled = ["PY-MAINT-003"]\n'
        '[overrides."tests/unit/**"]\ndisabled = ["PY-MAINT-003"]\n'
        '[overrides."**"]\ndisabled = ["PY-MAINT-003"]\n',
    )
    assert config.effective_policy("PY-MAINT-003", "tests/unit/a.py").source == (
        "override:tests/unit/**"
    )
    assert config.effective_policy("PY-MAINT-003", "tests/a.py").source == "override:tests/**"
    assert config.effective_policy("PY-MAINT-003", "src/a.py").source == "override:**"


def test_rules_disable_wins_over_any_table(project):
    config = _config(
        project,
        '[rules."PY-COR-007"]\nenabled = false\nseverity = "error"\n'
        '[overrides."src/**"]\nseverity = { "PY-COR-007" = "note" }\n',
    )
    assert config.effective_policy("PY-COR-007", "src/a.py") == EffectivePolicy(
        enabled=False, severity="error", source="project"
    )


def test_table_severity_beats_rules_severity(project):
    config = _config(
        project,
        '[rules."PY-COR-007"]\nseverity = "error"\n'
        '[overrides."tests/**"]\nseverity = { "PY-COR-007" = "note" }\n',
    )
    assert config.effective_policy("PY-COR-007", "tests/a.py") == EffectivePolicy(
        enabled=True, severity="note", source="override:tests/**"
    )
    # Outside the glob the project severity holds and the source stays
    # "project" even though [rules] set it.
    assert config.effective_policy("PY-COR-007", "src/a.py") == EffectivePolicy(
        enabled=True, severity="error", source="project"
    )


def test_source_strings_are_exact(project):
    config = _config(project, ADR_EXAMPLE)

    assert config.effective_policy("PY-COR-001", "src/a.py").source == "project"
    assert config.effective_policy("PY-COR-007", "tests/a.py").source == "override:tests/**"
    assert config.effective_policy("PY-COR-007", "db/a.py").source == "override:db/**"
    assert config.effective_policy("PY-MAINT-003", "tests/a.py").source == "override:tests/**"


def test_unmatched_path_returns_rules_policy_with_project_source(project):
    config = _config(
        project,
        '[rules."PY-COR-007"]\nseverity = "warning"\n'
        '[overrides."tests/**"]\ndisabled = ["PY-COR-007"]\n',
    )
    policy = config.policy_for("PY-COR-007")
    assert config.effective_policy("PY-COR-007", "src/a.py") == EffectivePolicy(
        enabled=policy.enabled, severity=policy.severity, source="project"
    )


def test_glob_without_slash_matches_at_any_depth(project):
    config = _config(project, '[overrides."*_test.py"]\ndisabled = ["PY-MAINT-003"]\n')

    assert not config.effective_policy("PY-MAINT-003", "a/b/c_test.py").enabled
    assert not config.effective_policy("PY-MAINT-003", "c_test.py").enabled
    assert config.effective_policy("PY-MAINT-003", "a/b/c_test.pyi").enabled
    # A glob with a slash is anchored at the project root.
    config = _config(project, '[overrides."tests/*.py"]\ndisabled = ["PY-MAINT-003"]\n')
    assert not config.effective_policy("PY-MAINT-003", "tests/a.py").enabled
    assert config.effective_policy("PY-MAINT-003", "pkg/tests/a.py").enabled


def test_identity_path_is_normalised(project):
    config = _config(project, '[overrides."tests/**"]\ndisabled = ["PY-MAINT-003"]\n')

    for path in ("tests\\unit\\a.py", "./tests/unit/a.py", "././tests/a.py"):
        assert config.effective_policy("PY-MAINT-003", path).source == "override:tests/**"
    assert config.effective_policy("PY-MAINT-003", "src/tests.py").source == "project"


def test_without_overrides_effective_policy_mirrors_policy_for(project):
    config = _config(
        project,
        '[rules."PY-COR-001"]\nenabled = false\n[rules."PY-COR-002"]\nseverity = "note"\n',
    )
    for rule_id in ("PY-COR-001", "PY-COR-002", "PY-COR-003"):
        policy = config.policy_for(rule_id)
        assert config.effective_policy(rule_id, "any/where.py") == EffectivePolicy(
            enabled=policy.enabled, severity=policy.severity, source="project"
        )


# --- Fingerprint --------------------------------------------------------------


def test_fingerprint_without_overrides_matches_golden(project):
    golden = json.loads((FIXTURES / "analysis-authority.json").read_text(encoding="utf-8"))
    root = project({"module.py": "VALUE = 1\n"})

    assert load_config(root).fingerprint == golden["configuration_fingerprint"]


def test_fingerprint_changes_when_overrides_are_added_edited_or_reordered(project):
    rules_only = _config(project, '[rules."PY-COR-001"]\nseverity = "error"\n').fingerprint
    with_override = _config(
        project,
        '[rules."PY-COR-001"]\nseverity = "error"\n'
        '[overrides."tests/**"]\ndisabled = ["PY-MAINT-003"]\n',
    ).fingerprint
    edited = _config(
        project,
        '[rules."PY-COR-001"]\nseverity = "error"\n'
        '[overrides."tests/**"]\ndisabled = ["PY-MAINT-004"]\n',
    ).fingerprint
    ordered = _config(
        project,
        '[overrides."src/**"]\nseverity = { "PY-COR-007" = "note" }\n'
        '[overrides."tests/**"]\nseverity = { "PY-COR-007" = "error" }\n',
    ).fingerprint
    reordered = _config(
        project,
        '[overrides."tests/**"]\nseverity = { "PY-COR-007" = "error" }\n'
        '[overrides."src/**"]\nseverity = { "PY-COR-007" = "note" }\n',
    ).fingerprint

    assert len({rules_only, with_override, edited, ordered, reordered}) == 5


def test_fingerprint_ignores_comments_and_key_order_inside_a_table(project):
    first = _config(project, ADR_EXAMPLE).fingerprint
    second = _config(
        project,
        "# comment\n"
        '[overrides."tests/**"]\n'
        'severity = { "PY-COR-007" = "note" }  # swapped keys\n'
        'disabled = ["PY-MAINT-003"]\n'
        '[overrides."db/**"]\n'
        'severity = { "PY-COR-007" = "error" }\n',
    ).fingerprint

    assert first == second


# --- Adversarial inputs --------------------------------------------------------


def _expected_policy(path: str, rule_id: str, glob_tail: str) -> EffectivePolicy:
    if "abc/abc" not in path:  # too shallow for any table
        return EffectivePolicy(True, None, "project")
    source = f"override:{path[:8]}{glob_tail}"
    if rule_id == "PY-MAINT-003":
        return EffectivePolicy(False, None, source)
    if rule_id == "PY-COR-007":
        return EffectivePolicy(True, "note", source)
    return EffectivePolicy(True, None, "project")


def test_thousand_wildcard_heavy_tables_resolve_in_linear_time():
    # 1000 tables of ~512-char globs heavy in *, ** and [...] against 1000
    # (path, rule) pairs: 1,000,000 glob tests. Each override's regex must be
    # compiled once, not once per finding.
    depth = 31
    glob_tail = "[a-z0-9_]*[!x]?/" * depth + "**/*.py"
    tables = {}
    for i in range(MAX_PATTERNS):
        glob = f"pkg{i:04d}/" + glob_tail
        assert len(glob) <= MAX_PATTERN_LENGTH
        tables[glob] = {"disabled": ["PY-MAINT-003"], "severity": {"PY-COR-007": "note"}}
    config = _parse_config({"overrides": tables})
    assert len(config.overrides) == MAX_PATTERNS

    rng = random.Random(7)  # noqa: S311 - deterministic test corpus
    deep = "/".join("abc" for _ in range(depth)) + "/f.py"
    pairs = [
        (
            f"pkg{rng.randrange(MAX_PATTERNS):04d}/" + (deep if n % 2 else "abc/f.py"),
            rng.choice(["PY-MAINT-003", "PY-COR-007", "PY-COR-001"]),
        )
        for n in range(1000)
    ]

    started = time.perf_counter()
    results = [config.effective_policy(rule_id, path) for path, rule_id in pairs]
    elapsed = time.perf_counter() - started

    assert elapsed < 2.0, elapsed
    expected = [_expected_policy(path, rule_id, glob_tail) for path, rule_id in pairs]
    assert results == expected
    assert sum(result.source != "project" for result in results) > 100


GLOB_TOKENS = [
    "*",
    "**",
    "?",
    "[",
    "]",
    "!",
    "^",
    "-",
    "/",
    "//",
    "\\",
    ".",
    "..",
    "./",
    "a",
    "b",
    "z",
    "0",
    "_",
    "tests",
    "src",
    ".py",
    "\0",
    "\n",
    "\t",
    " ",
    "é",
]
RULE_TOKENS = ["PY-COR-001", "GO-SEC-001", "py-cor-001", "PY", "", "ZZ-FUTURE-999", 7]
LEVEL_TOKENS = ["note", "warning", "error", "info", "", 1, ["note"]]


def _random_glob(rng: random.Random) -> str:
    return "".join(rng.choice(GLOB_TOKENS) for _ in range(rng.randrange(1, 40)))


def _random_entry(rng: random.Random) -> object:
    if rng.random() > 0.95:
        return rng.choice(LEVEL_TOKENS)  # not a table at all
    entry: dict[str, object] = {}
    if rng.random() < 0.7:
        ids = [rng.choice(RULE_TOKENS) for _ in range(rng.randrange(0, 3))]
        entry["disabled"] = ids if rng.random() < 0.9 else rng.choice(RULE_TOKENS)
    if rng.random() < 0.7:
        table = {str(rng.choice(RULE_TOKENS)): rng.choice(LEVEL_TOKENS)}
        entry["severity"] = table if rng.random() < 0.9 else rng.choice(LEVEL_TOKENS)
    if rng.random() < 0.1:
        entry["enabled"] = False
    return entry


@pytest.mark.parametrize("seed", range(12))
def test_random_overrides_only_ever_raise_config_error(seed):
    rng = random.Random(seed)  # noqa: S311 - deterministic test corpus
    parsed = 0
    for _ in range(60):
        tables = {_random_glob(rng): _random_entry(rng) for _ in range(rng.randrange(0, 6))}
        try:
            config = _parse_config({"overrides": tables})
        except ConfigError:
            continue
        parsed += 1
        globs = {override.glob for override in config.overrides}
        for _ in range(10):
            policy = config.effective_policy("PY-COR-001", _random_glob(rng))
            assert policy.source == "project" or policy.source[len("override:") :] in globs
        assert len(config.fingerprint) == 64
    assert parsed > 0  # not vacuous: some random tables must be accepted
