"""Privacy-safe finding baselines for incremental CI adoption."""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding

BASELINE_SCHEMA_VERSION = "1.0.0"
MAX_BASELINE_SIZE = 5 * 1024 * 1024
MAX_FINGERPRINTS = 100_000


class BaselineError(ValueError):
    """Raised when a baseline cannot be safely read or written."""


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    """Current findings compared with known privacy-safe fingerprints."""

    loaded: bool
    known_count: int
    current_count: int
    new_findings: tuple[Finding, ...]
    written: bool = False

    def as_dict(self) -> dict:
        return {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "loaded": self.loaded,
            "written": self.written,
            "known_fingerprints": self.known_count,
            "current_findings": self.current_count,
            "new_findings": len(self.new_findings),
        }


def finding_fingerprint(finding: Finding) -> str:
    """Hash stable identity fields without storing source identifiers."""
    identity = json.dumps(
        {
            "rule_id": finding.rule_id,
            "path": (
                finding.location.identity_path or finding.location.path
            ),
            "line": finding.location.line,
            "column": finding.location.column,
            "message": finding.message,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()


def compare_findings(
    findings: list[Finding],
    known_fingerprints: set[str] | None,
    *,
    written: bool = False,
) -> BaselineComparison:
    known = known_fingerprints or set()
    new_findings = tuple(
        finding
        for finding in findings
        if finding_fingerprint(finding) not in known
    )
    return BaselineComparison(
        loaded=known_fingerprints is not None,
        known_count=len(known),
        current_count=len(findings),
        new_findings=new_findings,
        written=written,
    )


def load_baseline(path: Path) -> set[str]:
    """Load and validate a bounded baseline file."""
    try:
        if path.stat().st_size > MAX_BASELINE_SIZE:
            raise BaselineError("Baseline exceeds the 5 MB safety limit.")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except BaselineError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BaselineError("Baseline is not readable valid JSON.") from error

    if not isinstance(payload, dict):
        raise BaselineError("Baseline root must be a JSON object.")
    if payload.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise BaselineError(
            f"Unsupported baseline schema; expected {BASELINE_SCHEMA_VERSION}."
        )
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list):
        raise BaselineError("Baseline fingerprints must be a JSON array.")
    if len(fingerprints) > MAX_FINGERPRINTS:
        raise BaselineError("Baseline contains too many fingerprints.")
    if not all(_valid_fingerprint(value) for value in fingerprints):
        raise BaselineError("Baseline contains an invalid fingerprint.")
    return set(fingerprints)


def write_baseline(path: Path, findings: list[Finding]) -> None:
    """Atomically write only schema metadata and hashed fingerprints."""
    if not path.parent.is_dir():
        raise BaselineError("Baseline parent directory does not exist.")
    fingerprints = sorted({finding_fingerprint(item) for item in findings})
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
