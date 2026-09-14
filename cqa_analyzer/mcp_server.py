"""Model Context Protocol server for coding agents (stdio transport, stdlib only).

Agents such as Claude Code, Kiro, Codex and Cursor discover tools through
MCP. This module exposes the analyzer as four tools — ``scan``, ``gate``,
``explain_rule`` and ``list_rules`` — over newline-delimited JSON-RPC 2.0 on
stdin/stdout, which is the MCP stdio transport.

Design (docs/adr/004):

- **A transport, not a second analysis path.** ``scan`` and ``gate`` run the
  installed CLI in a subprocess with ``--output-format json --offline`` and
  return its report verbatim, so an agent sees exactly what the CI gate
  sees: same ruleset version, same scoring policy, same config fingerprint.
- **No new dependencies.** The protocol surface the analyzer needs
  (``initialize``, ``tools/list``, ``tools/call``, ``ping``) is small enough
  to implement directly; a stdlib server cannot rot with an SDK.
- **Offline is not negotiable.** Every scan passes ``--offline``; the server
  never opens a socket.

Run with ``cqa-mcp`` or ``python -m cqa_analyzer.mcp_server``.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import IO, Any
from collections.abc import Callable

from cqa_analyzer import (
    REPORT_SCHEMA_VERSION,
    RULESET_VERSION,
    SCORING_POLICY_VERSION,
    __version__,
)
from cqa_analyzer.rule_metadata import builtin_rule_ids, rule_metadata

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_NAME = "cqa-analyzer"
DEFAULT_TIMEOUT_SECONDS = 600

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

EXIT_VERDICTS = {
    0: ("pass", "no gate condition tripped"),
    1: ("fail", "architecture signal score below --fail-under"),
    2: ("fail", "nothing analyzed: no source candidates under the path"),
    3: ("fail", "coverage gap: no file analyzed successfully, or --strict and gaps"),
    4: ("fail", "findings at or above --fail-on severity"),
    5: ("fail", "score not applicable to this project, so --fail-under cannot be judged"),
    6: ("fail", "effective configuration does not match --expect-config-fingerprint"),
}

_SCAN_PROPERTIES: dict[str, Any] = {
    "path": {
        "type": "string",
        "description": "Directory to analyze. Must exist. Scans never leave this directory.",
    },
    "changed_lines_manifest": {
        "type": "string",
        "description": "Path to a changed-lines manifest (see docs/CHANGED_LINES.md) to "
        "restrict findings to lines the agent touched.",
    },
    "baseline": {
        "type": "string",
        "description": "Path to a privacy-safe baseline; findings already in it are marked known.",
    },
    "new_findings_only": {
        "type": "boolean",
        "description": "With a baseline: report only findings that are not in it.",
    },
    "config": {
        "type": "string",
        "description": "Explicit config file instead of the project's own.",
    },
    "expect_config_fingerprint": {
        "type": "string",
        "description": "sha256 the effective configuration must match; the gate fails "
        "(exit 6) otherwise, so a change cannot weaken the gate silently.",
    },
    "complexity": {
        "type": "boolean",
        "description": "Include cyclomatic and cognitive complexity.",
    },
    "max_files": {
        "type": "integer",
        "minimum": 1,
        "description": "Upper bound on files scanned.",
    },
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "description": f"Subprocess timeout (default {DEFAULT_TIMEOUT_SECONDS}).",
    },
}

_GATE_PROPERTIES: dict[str, Any] = {
    **_SCAN_PROPERTIES,
    "fail_on": {
        "type": "string",
        "enum": ["warning", "error"],
        "description": "Fail when any finding reaches this severity.",
    },
    "fail_under": {
        "type": "number",
        "minimum": 1.0,
        "maximum": 10.0,
        "description": "Fail when the architecture signal score is below this value.",
    },
    "strict": {
        "type": "boolean",
        "description": "Fail on any coverage gap (unparsed files, unavailable analyzers).",
    },
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan",
        "title": "Scan a project",
        "description": (
            "Run the analyzer offline on a directory and return the full JSON report "
            f"(schema {REPORT_SCHEMA_VERSION}): findings with rule IDs, severities and "
            "locations, recognised DSA and design patterns, scan health, package "
            "intelligence, and the versioned ruleset and scoring policy the report was "
            "produced under. Deterministic: the same input yields the same report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": _SCAN_PROPERTIES,
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "gate",
        "title": "Run the quality gate",
        "description": (
            "Apply the analyzer as a pass/fail gate exactly as CI would, and return the "
            "verdict, the reason, the exit code, a finding summary and the score. Use "
            "changed_lines_manifest to gate only the lines you changed, baseline and "
            "new_findings_only to ignore pre-existing debt, and expect_config_fingerprint "
            "to prove the configuration was not weakened."
        ),
        "inputSchema": {
            "type": "object",
            "properties": _GATE_PROPERTIES,
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "explain_rule",
        "title": "Explain a rule",
        "description": (
            "Return the metadata for one rule ID (for example PY-COR-007 or GO-COR-002): "
            "title, description, category, default severity, confidence, language and "
            "remediation guidance, so a finding can be fixed without leaving the agent."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "Rule ID as reported in a finding."}
            },
            "required": ["rule_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_rules",
        "title": "List rules",
        "description": (
            f"List the {len(builtin_rule_ids())} built-in rules (ruleset {RULESET_VERSION}), "
            "optionally filtered by language, with ID, title, default severity and category."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "description": "Language ID filter, for example python, go, rust.",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "rules_for_files",
        "title": "Resolve rules for files (delegate mode)",
        "description": (
            "Deterministic review planning for a host agent that will do the reasoning "
            "itself. For each project-relative path, decide whether the analyzer would "
            "consider it (built-in skip directories, configured include/exclude and "
            "gitignore, adapter ownership by extension, size cap) and return the enabled "
            "rules with severity, confidence, remediation and not_when clauses, grouped so "
            "files sharing the same rule set list each rule once. Pure: no scan, no "
            "subprocess, no git. Unselected files carry the reason."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project root directory."},
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Project-relative file paths (forward slashes).",
                },
                "config": {
                    "type": "string",
                    "description": "Explicit analyzer configuration file to apply.",
                },
                "check_disk": {
                    "type": "boolean",
                    "description": (
                        "Also check that each file exists inside the project and is "
                        "within the size cap (default true). Set false to plan for "
                        "paths that are not on disk yet."
                    ),
                },
            },
            "required": ["path", "files"],
            "additionalProperties": False,
        },
    },
    {
        "name": "preview",
        "title": "Preview the scan plan (delegate mode)",
        "description": (
            "List what a scan of the project would consider, without scanning: every "
            "source file an adapter owns ends up either planned (with its language) or "
            "counted under an exclusion reason (configuration, gitignore, size cap, file "
            "limit, unreadable), plus pruned directories and a coverage_rate. Never reads "
            "file contents, so it is cheap enough to call before every review."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Project root directory."},
                "config": {
                    "type": "string",
                    "description": "Explicit analyzer configuration file to apply.",
                },
                "max_files": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Stop planning after this many files (default 20000).",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "diff_to_manifest",
        "title": "Convert a unified diff to a changed-lines manifest",
        "description": (
            "Turn unified diff text (the output of `git diff`, which the host agent runs; "
            "the analyzer itself never runs git) into the changed-lines manifest schema "
            "1.0.0 that scan and gate accept via changed_lines_manifest. Line numbers are "
            "post-change. Pure deletions are anchored to the line that now follows them "
            "unless include_deletions is false. Optionally writes the manifest to a file "
            "so it can be passed straight to gate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "diff": {"type": "string", "description": "Unified diff text (max 5 MB)."},
                "include_deletions": {
                    "type": "boolean",
                    "description": "Anchor pure deletions to the following line (default true).",
                },
                "write_to": {
                    "type": "string",
                    "description": (
                        "Optional file path to write the manifest JSON to; the parent "
                        "directory must exist. Returned as manifest_path."
                    ),
                },
            },
            "required": ["diff"],
            "additionalProperties": False,
        },
    },
]


class ToolError(Exception):
    """A tool-level failure reported to the agent as ``isError`` content."""


# --- tool implementations -----------------------------------------------------------


def _cli_args(params: dict[str, Any]) -> list[str]:
    path = Path(str(params["path"])).expanduser()
    if not path.is_dir():
        raise ToolError(f"path is not a directory: {path}")
    args = [str(path.resolve()), "--output-format", "json", "--offline"]
    option_map = {
        "changed_lines_manifest": "--changed-lines-manifest",
        "baseline": "--baseline",
        "config": "--config",
        "expect_config_fingerprint": "--expect-config-fingerprint",
        "max_files": "--max-files",
        "fail_on": "--fail-on",
        "fail_under": "--fail-under",
    }
    for key, flag in option_map.items():
        if params.get(key) is not None:
            args += [flag, str(params[key])]
    for key, flag in (
        ("new_findings_only", "--new-findings-only"),
        ("complexity", "--complexity"),
        ("strict", "--strict"),
    ):
        if params.get(key):
            args.append(flag)
    return args


def _run_cli(params: dict[str, Any]) -> tuple[int, dict[str, Any] | None, str]:
    timeout = int(params.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    command = [sys.executable, "-m", "cqa_analyzer", *_cli_args(params)]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(
            f"analyzer timed out after {timeout}s before producing a report. The scan is "
            "all-or-nothing: raise timeout_seconds, or bound the tree first (call preview to "
            "see how many files are planned, then pass max_files or a config with "
            "analysis.exclude)."
        ) from exc
    report: dict[str, Any] | None
    try:
        report = json.loads(completed.stdout) if completed.stdout.strip() else None
    except json.JSONDecodeError:
        report = None
    return completed.returncode, report, completed.stderr.strip()


def tool_scan(params: dict[str, Any]) -> dict[str, Any]:
    exit_code, report, stderr = _run_cli(params)
    if report is None:
        raise ToolError(
            f"analyzer exited {exit_code} without a JSON report: {stderr or 'no output'}"
        )
    return {"exit_code": exit_code, "report": report}


def tool_gate(params: dict[str, Any]) -> dict[str, Any]:
    exit_code, report, stderr = _run_cli(params)
    verdict, reason = EXIT_VERDICTS.get(exit_code, ("fail", f"unexpected exit code {exit_code}"))
    result: dict[str, Any] = {
        "verdict": verdict,
        "reason": reason,
        "exit_code": exit_code,
        "analyzer_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "scoring_policy_version": SCORING_POLICY_VERSION,
    }
    if report is not None:
        result["architecture_signal_score"] = report.get("architecture_signal_score")
        result["finding_summary"] = report.get("finding_summary")
        result["configuration_fingerprint"] = report.get("configuration_fingerprint")
        findings = report.get("findings") or []
        result["findings"] = [
            {
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "path": (f.get("location") or {}).get("path"),
                "line": (f.get("location") or {}).get("line"),
                "message": f.get("message"),
                "remediation": f.get("remediation"),
            }
            for f in findings
        ]
    elif stderr:
        result["stderr"] = stderr
    return result


def tool_explain_rule(params: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(params.get("rule_id", "")).strip().upper()
    if rule_id not in builtin_rule_ids():
        raise ToolError(f"unknown rule id {rule_id!r}; call list_rules for the catalog")
    meta = rule_metadata(rule_id)
    return {
        "rule_id": meta.rule_id,
        "name": meta.name,
        "title": meta.title,
        "description": meta.description,
        "category": meta.category,
        "default_severity": meta.default_severity,
        "confidence": meta.confidence,
        "language": meta.language,
        "remediation": meta.remediation,
        "not_when": list(meta.not_when),
        "ruleset_version": RULESET_VERSION,
    }


def tool_list_rules(params: dict[str, Any]) -> dict[str, Any]:
    language = params.get("language")
    rules = []
    for rule_id in builtin_rule_ids():
        meta = rule_metadata(rule_id)
        if language and meta.language != language:
            continue
        rules.append(
            {
                "rule_id": meta.rule_id,
                "title": meta.title,
                "default_severity": meta.default_severity,
                "category": meta.category,
                "language": meta.language,
            }
        )
    return {"ruleset_version": RULESET_VERSION, "count": len(rules), "rules": rules}


def _project_root(params: dict[str, Any]) -> Path:
    path = Path(str(params.get("path", ""))).expanduser()
    if not path.is_dir():
        raise ToolError(f"path is not a directory: {path}")
    return path.resolve()


def tool_rules_for_files(params: dict[str, Any]) -> dict[str, Any]:
    from cqa_analyzer.delegate import DelegateError, rules_for_files

    root = _project_root(params)
    files = params.get("files")
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise ToolError("files must be a list of project-relative path strings")
    config = params.get("config")
    try:
        result = rules_for_files(
            root,
            files,
            config_path=Path(str(config)).expanduser() if config else None,
            check_disk=bool(params.get("check_disk", True)),
        )
    except DelegateError as error:
        raise ToolError(str(error)) from error
    except ValueError as error:  # ConfigError and friends: report, never crash the server
        raise ToolError(f"configuration rejected: {error}") from error
    result["ruleset_version"] = RULESET_VERSION
    return result


def tool_preview(params: dict[str, Any]) -> dict[str, Any]:
    from cqa_analyzer.delegate import MAX_DELEGATE_FILES, DelegateError, preview

    root = _project_root(params)
    config = params.get("config")
    max_files = params.get("max_files")
    if max_files is not None and (not isinstance(max_files, int) or max_files < 1):
        raise ToolError("max_files must be a positive integer")
    try:
        result = preview(
            root,
            config_path=Path(str(config)).expanduser() if config else None,
            max_files=min(int(max_files or MAX_DELEGATE_FILES), MAX_DELEGATE_FILES),
        )
    except DelegateError as error:
        raise ToolError(str(error)) from error
    except ValueError as error:
        raise ToolError(f"configuration rejected: {error}") from error
    result["ruleset_version"] = RULESET_VERSION
    return result


def tool_diff_to_manifest(params: dict[str, Any]) -> dict[str, Any]:
    from cqa_analyzer.changed_lines import ChangedLinesError, diff_to_manifest

    diff = params.get("diff")
    if not isinstance(diff, str):
        raise ToolError("diff must be a string of unified diff text")
    try:
        manifest = diff_to_manifest(
            diff, include_deletions=bool(params.get("include_deletions", True))
        )
    except ChangedLinesError as error:
        raise ToolError(str(error)) from error
    result: dict[str, Any] = {
        "manifest": manifest,
        "file_count": len(manifest["files"]),
        "range_count": sum(len(entry["ranges"]) for entry in manifest["files"]),
    }
    write_to = params.get("write_to")
    if write_to:
        target = Path(str(write_to)).expanduser()
        if target.is_dir() or target.is_symlink():
            raise ToolError("write_to must be a regular file path, not a directory or symlink")
        if not target.parent.is_dir():
            raise ToolError(f"write_to parent directory does not exist: {target.parent}")
        encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(encoded, encoding="utf-8")
            os.replace(temporary, target)
        except OSError as error:
            with contextlib.suppress(OSError):  # best-effort cleanup of the temp file
                temporary.unlink()
            raise ToolError(f"could not write manifest: {error}") from error
        result["manifest_path"] = str(target.resolve())
    return result


TOOL_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "scan": tool_scan,
    "gate": tool_gate,
    "explain_rule": tool_explain_rule,
    "list_rules": tool_list_rules,
    "rules_for_files": tool_rules_for_files,
    "preview": tool_preview,
    "diff_to_manifest": tool_diff_to_manifest,
}


# --- JSON-RPC / MCP plumbing -------------------------------------------------------


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _tool_content(payload: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    text = json.dumps(payload, indent=2, sort_keys=True)
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["isError"] = True
    else:
        result["structuredContent"] = payload
    return result


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC message; return the response, or None for notifications."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(
            message.get("id") if isinstance(message, dict) else None,
            INVALID_REQUEST,
            "expected a JSON-RPC 2.0 message",
        )
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    is_notification = "id" not in message

    if method == "initialize":
        requested = str(params.get("protocolVersion", PROTOCOL_VERSION))
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        return _result(
            request_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": __version__},
                "instructions": (
                    "Deterministic, offline code-quality gate. Call `gate` with the "
                    "directory you changed (and a changed_lines_manifest when available) "
                    "before finishing a task; call `explain_rule` to fix a finding; call "
                    "`scan` for the full report. Results are reproducible and versioned."
                ),
            },
        )
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        handler = TOOL_HANDLERS.get(str(name))
        if handler is None:
            return _error(request_id, INVALID_PARAMS, f"unknown tool {name!r}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return _error(request_id, INVALID_PARAMS, "arguments must be an object")
        try:
            return _result(request_id, _tool_content(handler(arguments)))
        except ToolError as exc:
            return _result(request_id, _tool_content({"error": str(exc)}, is_error=True))
        except Exception as exc:  # noqa: BLE001 - report, never crash the transport
            return _result(
                request_id,
                _tool_content({"error": f"{type(exc).__name__}: {exc}"}, is_error=True),
            )
    if is_notification:
        return None
    return _error(request_id, METHOD_NOT_FOUND, f"method not found: {method}")


def serve(reader: IO[str], writer: IO[str]) -> int:
    """Serve newline-delimited JSON-RPC until EOF. Returns the process exit code."""
    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response: dict[str, Any] | None = _error(None, PARSE_ERROR, "invalid JSON")
        else:
            response = handle_message(message)
        if response is not None:
            writer.write(json.dumps(response, separators=(",", ":")) + "\n")
            writer.flush()
    return 0


def main() -> int:
    return serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
