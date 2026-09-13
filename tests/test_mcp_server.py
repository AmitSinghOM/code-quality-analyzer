"""MCP server contract (docs/adr/004): stdio JSON-RPC, four tools, CLI parity."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from cqa_analyzer import RULESET_VERSION, __version__
from cqa_analyzer import mcp_server
from cqa_analyzer.rule_metadata import builtin_rule_ids

SQL_CONCAT = "def q(cur, name):\n" '    cur.execute("SELECT * FROM users WHERE name = " + name)\n'


def _rpc(method: str, params: dict | None = None, request_id: int | None = 1) -> dict:
    message: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    if request_id is not None:
        message["id"] = request_id
    return message


def _call(name: str, arguments: dict) -> dict:
    response = mcp_server.handle_message(_rpc("tools/call", {"name": name, "arguments": arguments}))
    assert response is not None and "result" in response, response
    return response["result"]


def _structured(result: dict) -> dict:
    # Text content mirrors structuredContent so clients without structured
    # support still receive the payload.
    assert result["content"][0]["type"] == "text"
    if result.get("isError"):
        return json.loads(result["content"][0]["text"])
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    return result["structuredContent"]


# --- protocol ---------------------------------------------------------------------


def test_initialize_negotiates_a_supported_protocol_version():
    response = mcp_server.handle_message(
        _rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
    )
    result = response["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert result["serverInfo"] == {"name": "cqa-analyzer", "version": __version__}
    assert "tools" in result["capabilities"]
    assert "gate" in result["instructions"]


def test_initialize_falls_back_to_our_version_for_unknown_requests():
    response = mcp_server.handle_message(_rpc("initialize", {"protocolVersion": "1999-01-01"}))
    assert response["result"]["protocolVersion"] == mcp_server.PROTOCOL_VERSION


def test_notifications_get_no_response_and_ping_is_empty():
    assert mcp_server.handle_message(_rpc("notifications/initialized", request_id=None)) is None
    assert mcp_server.handle_message(_rpc("ping"))["result"] == {}


def test_unknown_method_and_malformed_messages_are_jsonrpc_errors():
    assert mcp_server.handle_message(_rpc("resources/list"))["error"]["code"] == (
        mcp_server.METHOD_NOT_FOUND
    )
    assert mcp_server.handle_message({"id": 1, "method": "ping"})["error"]["code"] == (
        mcp_server.INVALID_REQUEST
    )
    assert (
        mcp_server.handle_message(_rpc("tools/call", {"name": "nope", "arguments": {}}))["error"][
            "code"
        ]
        == mcp_server.INVALID_PARAMS
    )


def test_tools_list_exposes_exactly_four_tools_with_schemas():
    tools = mcp_server.handle_message(_rpc("tools/list"))["result"]["tools"]
    assert [t["name"] for t in tools] == ["scan", "gate", "explain_rule", "list_rules"]
    for tool in tools:
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert tool["description"]


def test_serve_is_newline_delimited_and_survives_bad_json():
    reader = io.StringIO(
        json.dumps(_rpc("ping", request_id=7)) + "\n"
        "this is not json\n"
        "\n" + json.dumps(_rpc("notifications/initialized", request_id=None)) + "\n"
    )
    writer = io.StringIO()
    assert mcp_server.serve(reader, writer) == 0
    lines = [json.loads(line) for line in writer.getvalue().splitlines()]
    assert lines[0] == {"jsonrpc": "2.0", "id": 7, "result": {}}
    assert lines[1]["error"]["code"] == mcp_server.PARSE_ERROR
    assert len(lines) == 2  # the notification produced nothing


# --- tools: metadata ------------------------------------------------------------------


def test_explain_rule_returns_full_metadata_and_normalises_case():
    payload = _structured(_call("explain_rule", {"rule_id": "py-cor-007"}))
    assert payload["rule_id"] == "PY-COR-007"
    assert payload["ruleset_version"] == RULESET_VERSION
    for key in ("title", "description", "category", "default_severity", "remediation", "language"):
        assert payload[key]


def test_explain_rule_unknown_id_is_a_tool_error_not_a_crash():
    result = _call("explain_rule", {"rule_id": "ZZ-XXX-999"})
    assert result["isError"] is True
    assert "unknown rule id" in _structured(result)["error"]


def test_list_rules_covers_the_catalog_and_filters_by_language():
    everything = _structured(_call("list_rules", {}))
    assert everything["count"] == len(builtin_rule_ids())
    rust = _structured(_call("list_rules", {"language": "rust"}))
    assert rust["count"] > 0
    assert {r["language"] for r in rust["rules"]} == {"rust"}
    assert all(r["rule_id"].startswith("RS-") for r in rust["rules"])


# --- tools: scan / gate (subprocess parity with the CLI) -------------------------------


@pytest.fixture
def sql_project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(SQL_CONCAT)
    return tmp_path


def test_scan_returns_the_cli_json_report_verbatim(sql_project: Path):
    payload = _structured(_call("scan", {"path": str(sql_project)}))
    report = payload["report"]
    cli = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "cqa_analyzer", str(sql_project), "-f", "json", "--offline"],
        capture_output=True,
        text=True,
        check=False,
    )
    expected = json.loads(cli.stdout)
    # Timestamps aside, the agent sees exactly what the CI gate sees.
    for key in (
        "findings",
        "ruleset_version",
        "scoring_policy_version",
        "configuration_fingerprint",
    ):
        assert report[key] == expected[key], key
    assert payload["exit_code"] == cli.returncode == 0
    assert report["findings"][0]["rule_id"] == "PY-COR-007"


def test_gate_fails_on_warning_with_reason_and_flat_findings(sql_project: Path):
    payload = _structured(_call("gate", {"path": str(sql_project), "fail_on": "warning"}))
    assert payload["verdict"] == "fail"
    assert payload["exit_code"] == 4
    assert "fail-on" in payload["reason"]
    finding = payload["findings"][0]
    assert finding["rule_id"] == "PY-COR-007"
    assert finding["path"] == "app.py" and finding["line"] == 2
    assert finding["remediation"]
    assert payload["ruleset_version"] == RULESET_VERSION


def test_gate_passes_when_nothing_trips(tmp_path: Path):
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n")
    payload = _structured(_call("gate", {"path": str(tmp_path)}))
    assert payload["verdict"] == "pass" and payload["exit_code"] == 0
    assert payload["findings"] == []


def test_gate_reports_config_fingerprint_mismatch_as_exit_6(sql_project: Path):
    payload = _structured(
        _call("gate", {"path": str(sql_project), "expect_config_fingerprint": "0" * 64})
    )
    assert payload["exit_code"] == 6
    assert "fingerprint" in payload["reason"]


def test_scan_rejects_a_missing_or_file_path(tmp_path: Path):
    result = _call("scan", {"path": str(tmp_path / "missing")})
    assert result["isError"] is True
    (tmp_path / "f.py").write_text("x = 1\n")
    result = _call("scan", {"path": str(tmp_path / "f.py")})
    assert "not a directory" in _structured(result)["error"]


def test_cli_args_always_force_offline_json_and_map_every_option():
    args = mcp_server._cli_args(
        {
            "path": ".",
            "changed_lines_manifest": "m.json",
            "baseline": "b.json",
            "new_findings_only": True,
            "config": "c.toml",
            "expect_config_fingerprint": "abc",
            "complexity": True,
            "max_files": 5,
            "fail_on": "error",
            "fail_under": 7.5,
            "strict": True,
        }
    )
    assert args[1:4] == ["--output-format", "json", "--offline"]
    for flag in (
        "--changed-lines-manifest",
        "--baseline",
        "--new-findings-only",
        "--config",
        "--expect-config-fingerprint",
        "--complexity",
        "--max-files",
        "--fail-on",
        "--fail-under",
        "--strict",
    ):
        assert flag in args, flag


def test_console_script_is_declared():
    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert 'cqa-mcp = "cqa_analyzer.mcp_server:main"' in text
