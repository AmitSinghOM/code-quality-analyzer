"""Adversarial transport and privacy contracts, with no external services."""

from __future__ import annotations

import io
import json
from unittest.mock import Mock

import pytest

from cqa_analyzer import mcp_server as mcp


def _request(method="ping", **changes):
    return {"jsonrpc": "2.0", "id": 1, "method": method, **changes}


def _serve(*messages):
    reader = io.StringIO("\n".join(messages) + "\n")
    writer = io.StringIO()
    code = mcp.serve(reader, writer)
    return code, [json.loads(line) for line in writer.getvalue().splitlines()]


@pytest.mark.parametrize("params", [None, [], ["invalid"], False, 0, "bad"])
@pytest.mark.parametrize("method", ["initialize", "tools/call", "ping"])
def test_non_object_params_do_not_kill_next_request(params, method):
    code, replies = _serve(json.dumps(_request(method, params=params)), json.dumps(_request(id=2)))
    assert code == 0
    assert replies[0]["error"]["code"] == mcp.INVALID_PARAMS
    assert replies[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}


@pytest.mark.parametrize("request_id", [None, True, False, [], {}, 1.5])
def test_invalid_ids_never_dispatch(request_id, monkeypatch):
    handler = Mock()
    monkeypatch.setitem(mcp.TOOL_HANDLERS, "diff_to_manifest", handler)
    response = mcp.handle_message(
        _request(
            "tools/call",
            id=request_id,
            params={"name": "diff_to_manifest", "arguments": {"diff": "x"}},
        )
    )
    assert response["error"]["code"] == mcp.INVALID_REQUEST
    handler.assert_not_called()


@pytest.mark.parametrize("method", ["ping", "initialize", "tools/list", "tools/call", "unknown"])
def test_idless_messages_have_no_response_or_effect(method, monkeypatch):
    handler = Mock()
    monkeypatch.setitem(mcp.TOOL_HANDLERS, "diff_to_manifest", handler)
    message = _request(method, params={"name": "diff_to_manifest", "arguments": {"diff": "x"}})
    del message["id"]
    assert mcp.handle_message(message) is None
    handler.assert_not_called()


@pytest.mark.parametrize("method", [None, [], {}, True, ""])
def test_invalid_methods_are_protocol_errors(method):
    assert mcp.handle_message(_request(method))["error"]["code"] == mcp.INVALID_REQUEST


@pytest.mark.parametrize("request_id", [0, -1, "client-1"])
def test_supported_ids_round_trip(request_id):
    assert mcp.handle_message(_request(id=request_id))["id"] == request_id


def test_initialize_rejects_non_string_version():
    result = mcp.handle_message(_request("initialize", params={"protocolVersion": []}))
    assert result["error"]["code"] == mcp.INVALID_PARAMS


@pytest.mark.parametrize("arguments", [None, [], False, 0, ""])
def test_non_object_arguments_are_not_coerced(arguments):
    result = mcp.handle_message(
        _request("tools/call", params={"name": "list_rules", "arguments": arguments})
    )
    assert result["error"]["code"] == mcp.INVALID_PARAMS


_VALID = {"string": ".", "boolean": True, "integer": 1, "number": 5.0, "array": ["a.py"]}
_WRONG = {"string": 1, "boolean": "false", "integer": True, "number": True, "array": "a.py"}


def _arguments(tool):
    return {
        name: spec.get("enum", [_VALID[spec["type"]]])[0]
        for name, spec in tool["inputSchema"]["properties"].items()
    }


def _key_deviations(valid, key, spec):
    deviations = [{**valid, key: _WRONG[spec["type"]]}, {**valid, key: None}]
    if "minimum" in spec:
        deviations.append({**valid, key: 0})
    if "maximum" in spec:
        deviations.append({**valid, key: spec["maximum"] + 1})
    if "enum" in spec:
        deviations.append({**valid, key: "not-an-enum-value"})
    if spec["type"] == "array":
        deviations.append({**valid, key: [False]})
    if spec["type"] == "number":
        deviations.extend({**valid, key: value} for value in [float("nan"), float("inf")])
    return deviations


def _invalid_arguments(tool, valid):
    """Every single-key deviation from ``valid`` the advertised schema must reject."""
    invalid = [{**valid, "unexpected": True}]
    for required in tool["inputSchema"].get("required", []):
        invalid.append({key: value for key, value in valid.items() if key != required})
    for key, spec in tool["inputSchema"]["properties"].items():
        invalid.extend(_key_deviations(valid, key, spec))
    return invalid


@pytest.mark.parametrize("tool", mcp.TOOLS, ids=lambda tool: tool["name"])
def test_advertised_schema_is_enforced_before_dispatch(tool, monkeypatch):
    name = tool["name"]
    handler = Mock(return_value={"ok": True})
    monkeypatch.setitem(mcp.TOOL_HANDLERS, name, handler)
    valid = _arguments(tool)
    for arguments in _invalid_arguments(tool, valid):
        result = mcp.handle_message(
            _request("tools/call", params={"name": name, "arguments": arguments})
        )
        assert result["result"]["isError"] is True, arguments
    handler.assert_not_called()
    response = mcp.handle_message(_request("tools/call", params={"name": name, "arguments": valid}))
    assert response["result"]["structuredContent"] == {"ok": True}
    handler.assert_called_once_with(valid)


@pytest.mark.parametrize(
    "wire",
    [
        '{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":NaN}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":Infinity}}',
        "not JSON",
        "\ud800",
    ],
)
def test_invalid_json_is_contained(wire):
    code, replies = _serve(wire, json.dumps(_request(id=2)))
    assert code == 0
    assert replies[0]["error"]["code"] == mcp.PARSE_ERROR
    assert replies[1]["id"] == 2 and replies[1]["result"] == {}


@pytest.mark.parametrize("content", ["x" * 65, "é" * 40, " " * 65])
def test_oversized_frame_closes_without_dispatch(content, monkeypatch):
    monkeypatch.setattr(mcp, "MAX_REQUEST_BYTES", 64)
    handler = Mock()
    monkeypatch.setattr(mcp, "handle_message", handler)
    code, replies = _serve(content, json.dumps(_request(id=2)))
    assert code == 1
    assert len(replies) == 1
    assert replies[0]["error"]["code"] == mcp.INVALID_REQUEST
    handler.assert_not_called()


def test_multibyte_frame_without_newline_is_bounded(monkeypatch):
    monkeypatch.setattr(mcp, "MAX_REQUEST_BYTES", 64)
    reader = io.StringIO("🎯" * 1000)
    writer = io.StringIO()
    assert mcp.serve(reader, writer) == 1
    assert reader.tell() < 1000
    assert json.loads(writer.getvalue())["error"]["code"] == mcp.INVALID_REQUEST


def test_frame_exactly_at_limit_is_accepted(monkeypatch):
    wire = json.dumps(_request()) + "\n"
    monkeypatch.setattr(mcp, "MAX_REQUEST_BYTES", len(wire.encode()))
    code, replies = _serve(wire.rstrip("\n"))
    assert code == 0 and replies[0]["result"] == {}


@pytest.mark.parametrize("tool", ["scan", "gate"])
def test_anonymized_tools_remove_identifiers_but_keep_verdict(tmp_path, tool):
    (tmp_path / "private_customer.py").write_text(
        "def q(private_cursor, private_value):\n"
        '    private_cursor.execute("SELECT * FROM clients WHERE name = " + private_value)\n'
    )
    arguments = {"path": str(tmp_path), "anonymize": True}
    if tool == "gate":
        arguments["fail_on"] = "warning"
    response = mcp.handle_message(
        _request("tools/call", params={"name": tool, "arguments": arguments})
    )
    result = response["result"]["structuredContent"]
    encoded = json.dumps(result)
    for secret in [str(tmp_path), "private_customer", "private_cursor", "private_value", "clients"]:
        assert secret not in encoded
    assert "file-0001" in encoded and "PY-COR-007" in encoded
    assert result["exit_code"] == (4 if tool == "gate" else 0)


@pytest.mark.parametrize("tool", ["scan", "gate"])
@pytest.mark.parametrize("failure", ["path", "stderr", "exception"])
def test_anonymized_failure_does_not_echo_private_data(tmp_path, tool, failure, monkeypatch):
    if failure == "stderr":
        monkeypatch.setattr(mcp, "_run_cli", lambda args: (1, None, "private-customer"))
    elif failure == "exception":
        handler = Mock(side_effect=RuntimeError("private-customer"))
        monkeypatch.setitem(mcp.TOOL_HANDLERS, tool, handler)
    response = mcp.handle_message(
        _request(
            "tools/call",
            params={
                "name": tool,
                "arguments": {
                    "path": str(tmp_path / "private-customer"),
                    "anonymize": True,
                },
            },
        )
    )
    assert "private-customer" not in json.dumps(response)
    if failure == "stderr" and tool == "gate":
        assert response["result"]["structuredContent"]["verdict"] == "fail"
    else:
        assert response["result"]["isError"] is True


def test_gate_default_remains_report_only_for_findings(tmp_path):
    (tmp_path / "app.py").write_text("def f(items=[]):\n    return items\n")
    result = mcp.tool_gate({"path": str(tmp_path)})
    assert result["findings"] and result["verdict"] == "pass"
    assert "--anonymize" not in mcp._cli_args({"path": str(tmp_path), "anonymize": False})


def test_deep_json_never_kills_following_request():
    code, replies = _serve("[" * 2000 + "0" + "]" * 2000, json.dumps(_request(id=2)))
    assert code == 0
    # CPython's decoder depth limit varies by interpreter version.
    assert replies[0]["error"]["code"] in (mcp.PARSE_ERROR, mcp.INVALID_REQUEST)
    assert replies[1]["result"] == {}


def test_decoder_recursion_error_is_contained(monkeypatch):
    reader = io.StringIO("{}\n")
    writer = io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(mcp.json, "loads", Mock(side_effect=RecursionError))
        assert mcp.serve(reader, writer) == 0
    assert json.loads(writer.getvalue())["error"]["code"] == mcp.PARSE_ERROR
