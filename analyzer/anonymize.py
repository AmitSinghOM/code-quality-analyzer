"""Fully anonymized report projections for safe artifact sharing."""

from __future__ import annotations

from copy import deepcopy

from .findings import Finding

ANONYMIZED_PROJECT = "anonymized-project"
ANONYMIZED_REMEDIATION = (
    "Review the local rule documentation for remediation guidance."
)


class ReportAnonymizer:
    """Map source identifiers to deterministic tokens within one report."""

    def __init__(self) -> None:
        self._files: dict[str, str] = {}
        self._functions: dict[tuple[str, str, int], str] = {}

    def file(self, path: str) -> str:
        """Return one stable opaque token for a source path."""
        if path not in self._files:
            self._files[path] = f"file-{len(self._files) + 1:04d}"
        return self._files[path]

    def function(self, name: str, path: str, line: int) -> str:
        """Return one stable opaque token for a function identity."""
        key = (name, path, line)
        if key not in self._functions:
            token = f"function-{len(self._functions) + 1:04d}"
            self._functions[key] = token
        return self._functions[key]

    def finding(self, finding: Finding) -> dict:
        """Remove source-derived text while retaining rule and location facts."""
        location = finding.location
        payload = finding.as_dict()
        payload["message"] = f"Finding reported by {finding.rule_id}."
        payload["remediation"] = ANONYMIZED_REMEDIATION
        payload["location"] = {
            "path": self.file(location.identity_path or location.path),
            "line": location.line,
            "column": location.column,
        }
        if location.end_line is not None:
            payload["location"]["end_line"] = location.end_line
        if location.end_column is not None:
            payload["location"]["end_column"] = location.end_column
        return payload

    def scan_health(self, health: dict) -> dict:
        """Tokenize source paths in health examples."""
        payload = deepcopy(health)
        examples = payload.get("skipped_examples", {})
        payload["skipped_examples"] = {
            reason: [self.file(path) for path in paths]
            for reason, paths in examples.items()
        }
        return payload

    def package(self, package) -> dict:
        """Expose aggregate package facts without metadata or module names."""
        graph = package.import_graph
        return {
            "anonymized": True,
            "pyproject_present": package.pyproject_present,
            "metadata_valid": package.metadata_valid,
            "project_name_declared": package.project_name is not None,
            "requires_python_declared": package.requires_python is not None,
            "build_backend_declared": package.build_backend is not None,
            "dependency_count": len(package.dependencies),
            "optional_dependency_group_count": len(
                package.optional_dependencies
            ),
            "script_count": len(package.scripts),
            "layout": package.layout,
            "source_root_count": len(package.source_roots),
            "module_count": len(package.modules),
            "import_edge_count": sum(
                len(targets) for targets in graph.values()
            ),
            "circular_import_group_count": len(package.circular_imports),
        }

    def patterns(self, found, definitions, evidence, verbose: bool) -> dict:
        """Tokenize files and replace source-derived signals with counts."""
        payload = {}
        for name, files in found.items():
            entry = {
                "files": [self.file(path) for path in files],
                "file_count": len(files),
                "description": definitions[name]["description"],
            }
            if verbose:
                entry["evidence"] = [
                    {
                        "file": self.file(hit.file),
                        "signal_count": len(hit.signals),
                    }
                    for hit in evidence.get(name, [])
                ]
            payload[name] = entry
        return payload

    def complexity(self, summary: dict | None) -> dict | None:
        """Tokenize high-complexity identities and remove detailed reasoning."""
        if summary is None:
            return None
        payload = deepcopy(summary)
        projected = []
        for item in payload.get("high_complexity_functions", []):
            path = item["file"]
            projected.append({
                "name": self.function(item["name"], path, item["line"]),
                "file": self.file(path),
                "line": item["line"],
                "time": item["time"],
                "space": item["space"],
                "confidence": item["confidence"],
                "reasoning": ["Detailed reasoning removed by anonymization."],
            })
        payload["high_complexity_functions"] = projected
        payload["anonymized"] = True
        return payload
