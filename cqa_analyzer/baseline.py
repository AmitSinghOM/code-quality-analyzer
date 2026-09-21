"""Privacy-safe finding baselines for incremental CI adoption."""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding
from .safe_io import SafeReadError, read_bounded_text

BASELINE_SCHEMA_VERSION = "2.0.0"
LEGACY_BASELINE_SCHEMA_VERSION = "1.0.0"
SUPPORTED_BASELINE_SCHEMAS = frozenset({LEGACY_BASELINE_SCHEMA_VERSION, BASELINE_SCHEMA_VERSION})
MAX_BASELINE_SIZE = 5 * 1024 * 1024
MAX_FINGERPRINTS = 100_000


class BaselineError(ValueError):
    """Raised when a baseline cannot be safely read or written."""


@dataclass(frozen=True, slots=True)
class Baseline:
    """Known fingerprints plus the schema that says how they were hashed."""

    fingerprints: frozenset[str]
    schema_version: str = BASELINE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    """Current findings compared with known privacy-safe fingerprints."""

    loaded: bool
    known_count: int
    current_count: int
    new_findings: tuple[Finding, ...]
    written: bool = False
    schema_version: str = BASELINE_SCHEMA_VERSION

    def as_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "loaded": self.loaded,
            "written": self.written,
            "known_fingerprints": self.known_count,
            "current_findings": self.current_count,
            "new_findings": len(self.new_findings),
        }


def _digest(identity: dict) -> str:
    encoded = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identity_path(finding: Finding) -> str:
    return finding.location.identity_path or finding.location.path


def finding_fingerprint_v1(finding: Finding) -> str:
    """Schema 1.0.0 identity: keyed on the line number and message text.

    Kept only so baselines written by earlier releases keep working. A single
    inserted line above a finding, a rename, or a reworded rule message all
    change this hash, which is why 2.0.0 replaced it.
    """
    return _digest(
        {
            "rule_id": finding.rule_id,
            "path": _identity_path(finding),
            "line": finding.location.line,
            "column": finding.location.column,
            "message": finding.message,
        }
    )


def finding_fingerprint(finding: Finding, ordinal: int = 0) -> str:
    """Schema 2.0.0 identity, stable across line shifts.

    Hashes the rule, the (redaction-independent) path, the whitespace-collapsed
    text of the reported line and ``ordinal`` -- the finding's index among
    findings in the same file with the same rule and line text -- so two
    identical offending lines are baselined independently. Findings created
    without scanner context (no line text available) fall back to the line and
    column, which is the best identity that exists for them.
    """
    context = finding.location.context
    identity: dict = {
        "rule_id": finding.rule_id,
        "path": _identity_path(finding),
        "ordinal": ordinal,
    }
    if context is not None:
        identity["context"] = context
    else:
        identity["line"] = finding.location.line
        identity["column"] = finding.location.column
    return _digest(identity)


def fingerprints_for(
    findings: list[Finding],
    schema_version: str = BASELINE_SCHEMA_VERSION,
) -> list[str]:
    """Fingerprint every finding, aligned by index with ``findings``.

    Ordinals follow the scanner's report order (path, line, column, rule), so
    the first of two identical lines is always ordinal 0.
    """
    if schema_version == LEGACY_BASELINE_SCHEMA_VERSION:
        return [finding_fingerprint_v1(item) for item in findings]
    seen: dict[tuple[str, str, str | None], int] = {}
    result: list[str] = []
    for item in findings:
        key = (item.rule_id, _identity_path(item), item.location.context)
        ordinal = seen.get(key, 0)
        seen[key] = ordinal + 1
        result.append(finding_fingerprint(item, ordinal))
    return result


def compare_findings(
    findings: list[Finding],
    known_fingerprints: Baseline | set[str] | frozenset[str] | None,
    *,
    written: bool = False,
) -> BaselineComparison:
    """Report the findings whose fingerprint the baseline does not know.

    A ``Baseline`` is compared with the hashing its own schema used, so a
    1.0.0 file written by an earlier release keeps working unchanged; a bare
    set is treated as current-schema fingerprints.
    """
    if isinstance(known_fingerprints, Baseline):
        known: frozenset[str] = known_fingerprints.fingerprints
        schema_version = known_fingerprints.schema_version
    else:
        known = frozenset(known_fingerprints or ())
        schema_version = BASELINE_SCHEMA_VERSION
    current = fingerprints_for(findings, schema_version)
    new_findings = tuple(
        finding
        for finding, fingerprint in zip(findings, current, strict=True)
        if fingerprint not in known
    )
    return BaselineComparison(
        loaded=known_fingerprints is not None,
        known_count=len(known),
        current_count=len(findings),
        new_findings=new_findings,
        written=written,
        schema_version=schema_version,
    )


def load_baseline(path: Path) -> Baseline:
    """Load and validate a bounded baseline file."""
    try:
        payload = json.loads(read_bounded_text(path, MAX_BASELINE_SIZE))
    except SafeReadError as error:
        if error.reason == "too_large":
            raise BaselineError("Baseline exceeds the 5 MB safety limit.") from error
        raise BaselineError("Baseline is not readable valid JSON.") from error
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise BaselineError("Baseline is not readable valid JSON.") from error

    if not isinstance(payload, dict):
        raise BaselineError("Baseline root must be a JSON object.")
    schema_version = payload.get("schema_version")
    if schema_version not in SUPPORTED_BASELINE_SCHEMAS:
        raise BaselineError(
            "Unsupported baseline schema; expected "
            f"{BASELINE_SCHEMA_VERSION} (or legacy "
            f"{LEGACY_BASELINE_SCHEMA_VERSION})."
        )
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list):
        raise BaselineError("Baseline fingerprints must be a JSON array.")
    if len(fingerprints) > MAX_FINGERPRINTS:
        raise BaselineError("Baseline contains too many fingerprints.")
    if not all(_valid_fingerprint(value) for value in fingerprints):
        raise BaselineError("Baseline contains an invalid fingerprint.")
    return Baseline(frozenset(fingerprints), schema_version)


def write_baseline(path: Path, findings: list[Finding]) -> None:
    """Atomically write only schema metadata and hashed fingerprints."""
    if not path.parent.is_dir():
        raise BaselineError("Baseline parent directory does not exist.")
    fingerprints = sorted(set(fingerprints_for(findings)))
    if len(fingerprints) > MAX_FINGERPRINTS:
        raise BaselineError("Too many findings to write a safe baseline.")

    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "fingerprint_algorithm": "sha256",
        "fingerprints": fingerprints,
    }
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
            temporary = Path(stream.name)
        temporary.replace(path)
    except OSError as error:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:  # cqa: ignore=PY-COR-003 reason="cleanup"
                pass
        raise BaselineError("Baseline could not be written.") from error


def _valid_fingerprint(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
