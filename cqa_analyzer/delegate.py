"""Delegate mode: deterministic review planning for a host agent.

The analyzer never reasons about code. A host agent (Kiro, Claude Code, Codex)
that wants to review a change can still borrow the analyzer's *deterministic*
half — which files count, which language adapter owns each, which rules apply,
and what those rules deliberately stay silent on — and do the reasoning itself.

Everything here is pure: no subprocess, no git, no network, no source parsing
beyond the project's own configuration. The same inputs always yield the same
plan, so a host agent can cache or diff the output.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .config import AnalyzerConfig, load_config, path_is_selected
from .discovery import DEFAULT_MAX_FILE_SIZE, SKIP_DIRS
from .plugins import create_default_registry
from .registry import PluginRegistry
from .rule_metadata import RuleMetadata, builtin_rule_ids, rule_metadata

DELEGATE_SCHEMA_VERSION = "1.0.0"

# Bounded so a hostile or careless caller cannot make the server allocate an
# unbounded response. Matches the scanner's own discovery cap.
MAX_DELEGATE_FILES = 20_000
MAX_PATH_LENGTH = 4_096


class DelegateError(ValueError):
    """Raised when a delegate request cannot be answered safely."""


@dataclass(frozen=True, slots=True)
class FilePlan:
    """The analyzer's verdict on one requested path."""

    path: str
    language: str | None
    selected: bool
    reason: str | None  # why the file is not selected; None when selected


def _reject_non_relative(raw: str, candidate: str) -> None:
    """Refuse anything that is not a plain project-relative path."""
    head = candidate.split("/", 1)[0]
    if candidate.startswith("/") or (":" in head and not candidate.startswith("./")):
        # Absolute, `scheme:` or a Windows drive — none are project-relative.
        raise DelegateError(f"file path must be project-relative: {raw!r}")


def normalise_relative_path(raw: str) -> str:
    """Validate and normalise a project-relative path from a caller.

    Rejects absolute paths, parent traversal, URL schemes and oversized
    strings. Returns a forward-slash relative path.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise DelegateError("file paths must be non-empty strings")
    if len(raw) > MAX_PATH_LENGTH or "\x00" in raw:
        raise DelegateError("file path is too long or contains a NUL byte")
    candidate = raw.replace("\\", "/").strip()
    _reject_non_relative(raw, candidate)
    parts = [part for part in candidate.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise DelegateError(f"file path must not traverse upward: {raw!r}")
    if not parts:
        raise DelegateError("file path must name a file")
    return "/".join(parts)


def _skipped_directory(parts: tuple[str, ...], keep: tuple[str, ...]) -> str | None:
    for part in parts[:-1]:
        if part in SKIP_DIRS and part not in keep:
            return part
    return None


def plan_file(
    relative: str,
    registry: PluginRegistry,
    configuration: AnalyzerConfig,
    *,
    root: Path | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> FilePlan:
    """Decide whether the analyzer would consider ``relative`` and under which adapter.

    Mirrors :mod:`cqa_analyzer.discovery` ordering: built-in skip directories,
    configured include/exclude and gitignore, then adapter ownership by
    extension. When ``root`` is given, the on-disk size is also checked so the
    plan matches what a scan would do; a missing file is reported, not guessed.
    """
    parts = tuple(relative.split("/"))
    pruned = _skipped_directory(parts, configuration.analysis.keep_directories)
    if pruned is not None:
        return FilePlan(relative, None, False, f"skipped_directory:{pruned}")
    if not path_is_selected(relative, configuration.analysis):
        return FilePlan(relative, None, False, "excluded_by_configuration")
    adapter = registry.adapter_for_path(relative)
    if adapter is None:
        return FilePlan(relative, None, False, "unsupported_extension")
    if root is not None:
        candidate = root / relative
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return FilePlan(relative, adapter.language_id, False, "missing")
        if root.resolve() not in resolved.parents:
            return FilePlan(relative, adapter.language_id, False, "outside_project")
        if not resolved.is_file():
            return FilePlan(relative, adapter.language_id, False, "not_a_regular_file")
        if resolved.stat().st_size > max_file_size:
            return FilePlan(relative, adapter.language_id, False, "too_large")
    return FilePlan(relative, adapter.language_id, True, None)


def rules_for_language(language_id: str, configuration: AnalyzerConfig) -> tuple[RuleMetadata, ...]:
    """Enabled built-in rules for one adapter, with configured severity applied."""
    selected = []
    for rule_id in builtin_rule_ids():
        meta = rule_metadata(rule_id)
        if meta.language != language_id:
            continue
        policy = configuration.policy_for(rule_id)
        if not policy.enabled:
            continue
        if policy.severity and policy.severity != meta.default_severity:
            meta = RuleMetadata(
                rule_id=meta.rule_id,
                name=meta.name,
                title=meta.title,
                description=meta.description,
                category=meta.category,
                default_severity=policy.severity,
                confidence=meta.confidence,
                remediation=meta.remediation,
                language=meta.language,
                not_when=meta.not_when,
            )
        selected.append(meta)
    return tuple(selected)


def _rule_dict(meta: RuleMetadata) -> dict:
    return {
        "rule_id": meta.rule_id,
        "title": meta.title,
        "description": meta.description,
        "category": meta.category,
        "severity": meta.default_severity,
        "confidence": meta.confidence,
        "remediation": meta.remediation,
        "not_when": list(meta.not_when),
    }


def _plan_requested_files(
    files: list[str],
    registry: PluginRegistry,
    configuration: AnalyzerConfig,
    root: Path | None,
) -> list[FilePlan]:
    """Normalise, de-duplicate and plan each requested path in request order."""
    plans: list[FilePlan] = []
    seen: set[str] = set()
    for raw in files:
        relative = normalise_relative_path(raw)
        if relative not in seen:
            seen.add(relative)
            plans.append(plan_file(relative, registry, configuration, root=root))
    return plans


def _group_by_rule_set(plans: list[FilePlan], configuration: AnalyzerConfig) -> list[dict]:
    """Bucket selected files by (language, exact enabled rule IDs)."""
    groups: dict[tuple[str, ...], dict] = {}
    for plan in plans:
        if not plan.selected or plan.language is None:
            continue
        rules = rules_for_language(plan.language, configuration)
        key = (plan.language, *(meta.rule_id for meta in rules))
        group = groups.setdefault(
            key,
            {"language": plan.language, "files": [], "rules": [_rule_dict(m) for m in rules]},
        )
        group["files"].append(plan.path)
    ordered = [groups[key] for key in sorted(groups)]
    for group in ordered:
        group["files"].sort()
    return ordered


def rules_for_files(
    root: Path,
    files: list[str],
    *,
    config_path: Path | None = None,
    use_project_config: bool = True,
    check_disk: bool = True,
) -> dict:
    """Resolve the applicable rules for each requested file, grouped by rule set.

    Files that share exactly the same enabled rules land in one group, so a
    host agent reviewing forty files sees each rule once. Unselected files are
    listed with the reason the analyzer would skip them.
    """
    if not isinstance(files, list):
        raise DelegateError("files must be a list of project-relative paths")
    if len(files) > MAX_DELEGATE_FILES:
        raise DelegateError(f"too many files (limit {MAX_DELEGATE_FILES})")
    root = Path(root)
    configuration = load_config(
        root, config_path=config_path, use_project_config=use_project_config
    )
    plans = _plan_requested_files(
        files, create_default_registry(), configuration, root if check_disk else None
    )
    return {
        "schema_version": DELEGATE_SCHEMA_VERSION,
        "config_fingerprint": configuration.fingerprint,
        "requested": len(plans),
        "selected": sum(1 for plan in plans if plan.selected),
        "groups": _group_by_rule_set(plans, configuration),
        "unselected": [
            {"path": plan.path, "language": plan.language, "reason": plan.reason}
            for plan in sorted(plans, key=lambda p: p.path)
            if not plan.selected
        ],
    }


# --- preview: the review plan for a whole project ----------------------------------

# Examples per reason are bounded so a huge tree cannot inflate the response.
MAX_PREVIEW_EXAMPLES = 25


def _stat_reason(path: Path, root: Path, max_file_size: int) -> str | None:
    """Why discovery would refuse ``path`` without reading it, or None."""
    try:
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if root not in resolved.parents:
                return "outside_project"
        info = path.stat()
    except (OSError, RuntimeError):
        return "unreadable"
    if not path.is_file():
        return "not_a_regular_file"
    if info.st_size > max_file_size:
        return "too_large"
    return None


class _PreviewWalker:
    """Accumulates the scan plan for one tree without reading any file."""

    def __init__(
        self,
        root: Path,
        registry: PluginRegistry,
        configuration: AnalyzerConfig,
        max_files: int,
        max_file_size: int,
    ) -> None:
        self.root = root
        self.registry = registry
        self.analysis = configuration.analysis
        self.skip = SKIP_DIRS - set(configuration.analysis.keep_directories)
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.planned: list[dict] = []
        self.excluded_counts: dict[str, int] = {}
        self.excluded_examples: dict[str, list[str]] = {}
        self.pruned_directories = 0
        self.pruned_examples: list[str] = []
        self.truncated = False

    def walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = self._keep_directories(Path(dirpath), dirnames)
            if self.truncated:
                break
            for name in sorted(filenames):
                if self._consider(Path(dirpath) / name):
                    break  # file limit reached

    def _keep_directories(self, parent: Path, names: list[str]) -> list[str]:
        kept = []
        for name in sorted(names):
            if name in self.skip:
                self.pruned_directories += 1
                if len(self.pruned_examples) < MAX_PREVIEW_EXAMPLES:
                    self.pruned_examples.append((parent / name).relative_to(self.root).as_posix())
            else:
                kept.append(name)
        return kept

    def _consider(self, path: Path) -> bool:
        """Plan or exclude one file. Returns True when the file limit was hit."""
        relative = path.relative_to(self.root).as_posix()
        adapter = self.registry.adapter_for_path(relative)
        if adapter is None:
            return False  # not a candidate for any adapter, exactly as discovery
        if not path_is_selected(relative, self.analysis):
            self._exclude("excluded_by_configuration", relative)
            return False
        if len(self.planned) >= self.max_files:
            self.truncated = True
            self._exclude("file_limit", relative)
            return True
        reason = _stat_reason(path, self.root, self.max_file_size)
        if reason is not None:
            self._exclude(reason, relative)
            return False
        self.planned.append({"path": relative, "language": adapter.language_id})
        return False

    def _exclude(self, reason: str, relative: str) -> None:
        self.excluded_counts[reason] = self.excluded_counts.get(reason, 0) + 1
        examples = self.excluded_examples.setdefault(reason, [])
        if len(examples) < MAX_PREVIEW_EXAMPLES:
            examples.append(relative)

    def report(self, config_fingerprint: str) -> dict:
        considered = len(self.planned) + sum(self.excluded_counts.values())
        by_language: dict[str, int] = {}
        for item in self.planned:
            by_language[item["language"]] = by_language.get(item["language"], 0) + 1
        return {
            "schema_version": DELEGATE_SCHEMA_VERSION,
            "config_fingerprint": config_fingerprint,
            "considered": considered,
            "planned_count": len(self.planned),
            "planned_by_language": dict(sorted(by_language.items())),
            "coverage_rate": (len(self.planned) / considered) if considered else 1.0,
            "planned": self.planned,
            "excluded": {
                reason: {
                    "count": self.excluded_counts[reason],
                    "examples": self.excluded_examples[reason],
                }
                for reason in sorted(self.excluded_counts)
            },
            "pruned_directories": self.pruned_directories,
            "pruned_examples": self.pruned_examples,
            "truncated": self.truncated,
        }


def preview(
    root: Path,
    *,
    config_path: Path | None = None,
    use_project_config: bool = True,
    max_files: int = MAX_DELEGATE_FILES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict:
    """List what a scan of ``root`` would consider, and what it would skip and why.

    Walks the tree with the same rules as :mod:`cqa_analyzer.discovery` (skip
    directories, configured include/exclude, gitignore, adapter ownership,
    size cap, file limit) but never reads file contents, so it is cheap enough
    to call before every review. Every source-looking file ends up either in
    ``planned`` or counted under an ``excluded`` reason: nothing is silently
    dropped.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise DelegateError(f"path is not a directory: {root}")
    configuration = load_config(
        root, config_path=config_path, use_project_config=use_project_config
    )
    walker = _PreviewWalker(
        root, create_default_registry(), configuration, max_files, max_file_size
    )
    walker.walk()
    return walker.report(configuration.fingerprint)
