"""Language-neutral actionable finding models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Location:
    """One-based source location for an actionable finding."""

    path: str
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None

    def as_dict(self) -> dict:
        payload = {
            "path": self.path,
            "line": self.line,
            "column": self.column,
        }
        if self.end_line is not None:
            payload["end_line"] = self.end_line
        if self.end_column is not None:
            payload["end_column"] = self.end_column
        return payload


@dataclass(frozen=True, slots=True)
class Finding:
    """A deterministic, source-located issue emitted by a rule."""

    rule_id: str
    category: str
    severity: str
    confidence: str
    message: str
    location: Location
    remediation: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "location": self.location.as_dict(),
            "remediation": self.remediation,
        }
