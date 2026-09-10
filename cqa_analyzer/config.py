"""Bounded, deterministic project configuration and path policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

import tomllib

from .safe_io import SafeReadError, read_bounded_text

CONFIG_NAME = ".code-quality.toml"
MAX_CONFIG_SIZE = 256 * 1024
MAX_PATTERNS = 1_000
MAX_PATTERN_LENGTH = 512
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")


class ConfigError(ValueError):
    """Raised when project configuration cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class RulePolicy:
    """Optional behavior overrides for one stable rule ID."""

    enabled: bool = True
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    """Project-relative source selection settings."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    respect_gitignore: bool = True
    gitignore: tuple[str, ...] = field(default=(), repr=False)
    # Directory names to scan even though they are in the built-in skip list
    # (`external/`, `vendor/`, … are first-party in some projects).
    keep_directories: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalyzerConfig:
    """Validated effective analyzer configuration."""

    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    rules: tuple[tuple[str, RulePolicy], ...] = ()

    def policy_for(self, rule_id: str) -> RulePolicy:
        return dict(self.rules).get(rule_id, RulePolicy())

    @property
    def fingerprint(self) -> str:
        payload = {
            "analysis": {
                "include": list(self.analysis.include),
                "exclude": list(self.analysis.exclude),
                "respect_gitignore": self.analysis.respect_gitignore,
                "gitignore": list(self.analysis.gitignore),
                # Only when set: fingerprints of configurations that predate
                # this key must not change, or every pinned gate would break.
                **(
                    {"keep_directories": list(self.analysis.keep_directories)}
                    if self.analysis.keep_directories
                    else {}
                ),
            },
            "rules": {
                rule_id: {
                    "enabled": policy.enabled,
                    "severity": policy.severity,
                }
                for rule_id, policy in self.rules
            },
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def load_config(
    root: Path,
    *,
    config_path: Path | None = None,
    use_project_config: bool = True,
) -> AnalyzerConfig:
    """Load the effective configuration and ignore rules.

    By default the project root's ``.code-quality.toml`` is used. A CI gate
    should not trust the tree it is gating: ``config_path`` loads an
    explicit file instead (the repository's own file is ignored), and
    ``use_project_config=False`` runs with defaults only. Either way the
    root ``.gitignore`` still applies when ``respect_gitignore`` is set.
    """
    root = Path(root).resolve()
    if config_path is not None:
        explicit = Path(config_path).resolve()
        if not explicit.is_file():
            raise ConfigError(f"--config file not found: {explicit}")
        data = _load_toml(explicit, explicit.parent)
        config = _parse_config(data)
    elif use_project_config:
        path = root / CONFIG_NAME
        if path.exists() or path.is_symlink():
            data = _load_toml(path, root)
            config = _parse_config(data)
        else:
            config = AnalyzerConfig()
    else:
        config = AnalyzerConfig()

    if config.analysis.respect_gitignore:
        ignore = _load_gitignore(root / ".gitignore", root)
        config = replace(
            config,
            analysis=replace(config.analysis, gitignore=ignore),
        )
    return config


def path_is_selected(relative_path: str, analysis: AnalysisConfig) -> bool:
    """Return whether a POSIX project-relative source path is selected."""
    path = relative_path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if analysis.include and not any(_glob_matches(pattern, path) for pattern in analysis.include):
        return False
    if any(_glob_matches(pattern, path) for pattern in analysis.exclude):
        return False

    ignored = False
    for rule in analysis.gitignore:
        escaped_marker = rule.startswith(r"\#") or rule.startswith(r"\!")
        negated = rule.startswith("!") and not escaped_marker
        if negated or escaped_marker:
            pattern = rule[1:]
        else:
            pattern = rule
        if _glob_matches(pattern, path):
            ignored = not negated
    return not ignored


def _load_toml(path: Path, root: Path) -> dict:
    content = _read_bounded_file(path, root, "Configuration")
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError("Configuration is not valid TOML.") from error
    if not isinstance(data, dict):  # Defensive: TOML roots are mappings.
        raise ConfigError("Configuration root must be a TOML table.")
    return data


def _parse_config(data: dict) -> AnalyzerConfig:
    _reject_unknown(data, {"analysis", "rules"}, "configuration")
    analysis_data = _table(data.get("analysis"), "analysis")
    _reject_unknown(
        analysis_data,
        {"include", "exclude", "respect_gitignore", "keep_directories"},
        "analysis",
    )
    analysis = AnalysisConfig(
        include=_patterns(analysis_data.get("include"), "analysis.include"),
        exclude=_patterns(analysis_data.get("exclude"), "analysis.exclude"),
        respect_gitignore=_boolean(
            analysis_data.get("respect_gitignore"),
            "analysis.respect_gitignore",
            default=True,
        ),
        keep_directories=_directory_names(
            analysis_data.get("keep_directories"), "analysis.keep_directories"
        ),
    )

    rules_data = _table(data.get("rules"), "rules")
    rules = []
    for rule_id, value in sorted(rules_data.items()):
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise ConfigError(f"Invalid rule ID in configuration: {rule_id!r}.")
        policy = _table(value, f"rules.{rule_id}")
        _reject_unknown(policy, {"enabled", "severity"}, f"rules.{rule_id}")
        severity = policy.get("severity")
        if severity is not None and severity not in {"warning", "error"}:
            raise ConfigError(f"rules.{rule_id}.severity must be 'warning' or 'error'.")
        rules.append(
            (
                rule_id,
                RulePolicy(
                    enabled=_boolean(
                        policy.get("enabled"),
                        f"rules.{rule_id}.enabled",
                        default=True,
                    ),
                    severity=severity,
                ),
            )
        )
    return AnalyzerConfig(analysis=analysis, rules=tuple(rules))


def _load_gitignore(path: Path, root: Path) -> tuple[str, ...]:
    if not path.exists() and not path.is_symlink():
        return ()
    content = _read_bounded_file(path, root, ".gitignore")
    rules = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        escaped_marker = line.startswith(r"\#") or line.startswith(r"\!")
        pattern = line[1:] if line.startswith("!") or escaped_marker else line
        _validate_pattern(pattern, ".gitignore", allow_rooted=True)
        rules.append(line)
        if len(rules) > MAX_PATTERNS:
            raise ConfigError(".gitignore contains too many patterns.")
    return tuple(rules)


def _read_bounded_file(path: Path, root: Path, label: str) -> str:
    try:
        return read_bounded_text(path, MAX_CONFIG_SIZE, root=root)
    except SafeReadError as error:
        if error.reason == "not_regular_file":
            raise ConfigError(f"{label} must be a regular file.") from error
        if error.reason == "too_large":
            raise ConfigError(f"{label} exceeds the 256 KiB safety limit.") from error
        raise ConfigError(f"{label} could not be read safely.") from error
    except (FileNotFoundError, ValueError) as error:
        raise ConfigError(f"{label} could not be read safely.") from error


def _table(value, name: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a TOML table.")
    return value


def _reject_unknown(data: dict, allowed: set[str], name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"Unknown {name} key: {unknown[0]}.")


def _boolean(value, name: str, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false.")
    return value


def _patterns(value, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be an array of strings.")
    if len(value) > MAX_PATTERNS:
        raise ConfigError(f"{name} contains too many patterns.")
    patterns = []
    for item in value:
        _validate_pattern(item, name, allow_rooted=False)
        patterns.append(item)
    return tuple(patterns)


def _validate_pattern(pattern: str, name: str, *, allow_rooted: bool) -> None:
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH or "\0" in pattern:
        raise ConfigError(f"{name} contains an invalid pattern.")
    normalized = pattern.replace("\\", "/")
    if not allow_rooted and normalized.startswith("/"):
        raise ConfigError(f"{name} patterns must be project-relative.")
    if ".." in normalized.split("/"):
        raise ConfigError(f"{name} patterns cannot traverse parent paths.")


def _glob_matches(pattern: str, path: str) -> bool:
    pattern = pattern.replace("\\", "/")
    rooted = pattern.startswith("/")
    pattern = pattern.lstrip("/")
    pattern = pattern.rstrip("/")
    if not pattern:
        return False

    body = _translate_glob(pattern)
    if rooted or "/" in pattern:
        prefix = "^"
    else:
        prefix = r"(?:^|.*/)"
    suffix = r"(?:/.*)?$"
    return re.match(prefix + body + suffix, path) is not None


def _translate_glob(pattern: str) -> str:
    output = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    output.append(r"(?:.*/)?")
                    index += 1
                else:
                    output.append(".*")
                continue
            output.append("[^/]*")
        elif character == "?":
            output.append("[^/]")
        elif character == "[":
            # Character class (round 2, C5): `[abc]`, `[a-z]`, `[!x]`/`[^x]`.
            close = pattern.find("]", index + 2)
            if close == -1:
                output.append(re.escape(character))
            else:
                body = pattern[index + 1 : close]
                negate = body[:1] in {"!", "^"}
                if negate:
                    body = body[1:]
                output.append("[" + ("^" if negate else "") + _class_body(body) + "]")
                index = close
        else:
            output.append(re.escape(character))
        index += 1
    return "".join(output)


def _directory_names(value: object, label: str) -> tuple[str, ...]:
    """Validate a list of bare directory names (no separators, no globs)."""
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{label} must be a list of directory names.")
    for name in value:
        if (
            not name
            or "/" in name
            or "\\" in name
            or name in {".", ".."}
            or any(ch in name for ch in "*?[")
        ):
            raise ConfigError(f"{label} entries must be bare directory names; got {name!r}.")
    return tuple(sorted(set(value)))


def _class_body(body: str) -> str:
    """Render a glob character-class body as a safe regex class body.

    Ranges are kept only when well-formed (`a-z`); anything else — a
    reversed range like `s-:`, a stray `-`, `\\`, `]`, `^` — is escaped so a
    crafted `.gitignore` can never make `re.compile` raise (found by
    tests/test_lexer_fuzz.py).
    """
    out = []
    index = 0
    while index < len(body):
        char = body[index]
        if (
            index + 2 < len(body)
            and body[index + 1] == "-"
            and body[index] <= body[index + 2]
            and body[index].isalnum()
            and body[index + 2].isalnum()
        ):
            out.append(re.escape(body[index]) + "-" + re.escape(body[index + 2]))
            index += 3
            continue
        out.append(re.escape(char))
        index += 1
    return "".join(out)
