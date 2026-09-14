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
from cqa_analyzer.mcp_server import TOOL_HANDLERS
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


def test_tools_list_exposes_exactly_seven_tools_with_schemas():
    tools = mcp_server.handle_message(_rpc("tools/list"))["result"]["tools"]
    assert [t["name"] for t in tools] == [
        "scan",
        "gate",
        "explain_rule",
        "list_rules",
        "rules_for_files",
        "preview",
        "diff_to_manifest",
    ]
    for tool in tools:
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert tool["description"]
    assert set(TOOL_HANDLERS) == {t["name"] for t in tools}


_SAMPLE_DIFF = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,4 +1,5 @@
 import os
-x = 1
+x = 2
+y = 3
 z = 4
 w = 5
@@ -10,3 +11,2 @@ def f():
     a = 1
-    b = 2
     c = 3
diff --git a/new.go b/new.go
new file mode 100644
--- /dev/null
+++ b/new.go
@@ -0,0 +1,2 @@
+package main
+func main() {}
diff --git a/gone.rs b/gone.rs
deleted file mode 100644
--- a/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-fn a() {}
-fn b() {}
diff --git a/old_name.ts b/new_name.ts
similarity index 90%
rename from old_name.ts
rename to new_name.ts
--- a/old_name.ts
+++ b/new_name.ts
@@ -3,2 +3,2 @@
-const a = 1;
+const a = 2;
 const b = 3;
diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"
--- "a/caf\\303\\251.py"
+++ "b/caf\\303\\251.py"
@@ -7 +7 @@
-print(1)
+print(2)
"""


def test_diff_to_manifest_tracks_post_change_lines_across_file_kinds():
    payload = _structured(_call("diff_to_manifest", {"diff": _SAMPLE_DIFF}))
    manifest = payload["manifest"]
    assert manifest["schema_version"] == "1.0.0"
    files = {entry["path"]: entry["ranges"] for entry in manifest["files"]}
    # modified + added lines 2-3; pure deletion of old line 11 anchors to new line 12
    assert files["src/app.py"] == [
        {"start_line": 2, "end_line": 3},
        {"start_line": 12, "end_line": 12},
    ]
    assert files["new.go"] == [{"start_line": 1, "end_line": 2}]
    assert "gone.rs" not in files  # deleted files have no post-change lines
    assert files["new_name.ts"] == [{"start_line": 3, "end_line": 3}]  # rename uses new path
    assert "old_name.ts" not in files
    assert "img.png" not in files  # binary
    assert files["café.py"] == [{"start_line": 7, "end_line": 7}]  # git C-quoting undone
    assert payload["file_count"] == 4
    assert payload["range_count"] == 5

    without = _structured(
        _call("diff_to_manifest", {"diff": _SAMPLE_DIFF, "include_deletions": False})
    )
    files = {entry["path"]: entry["ranges"] for entry in without["manifest"]["files"]}
    assert files["src/app.py"] == [{"start_line": 2, "end_line": 3}]


def test_diff_to_manifest_output_is_consumed_by_gate(sql_project: Path):
    # Touch only a line that has no finding: the gate must then pass.
    source = next(sql_project.rglob("*.py"))
    relative = source.relative_to(sql_project).as_posix()
    manifest_path = sql_project / "changed.json"
    diff = f"--- a/{relative}\n+++ b/{relative}\n@@ -1,1 +1,1 @@\n-# old\n+# new\n"
    written = _structured(_call("diff_to_manifest", {"diff": diff, "write_to": str(manifest_path)}))
    assert written["manifest_path"] == str(manifest_path.resolve())
    assert json.loads(manifest_path.read_text())["files"][0]["path"] == relative
    gate = _structured(
        _call(
            "gate",
            {
                "path": str(sql_project),
                "changed_lines_manifest": str(manifest_path),
                "fail_on": "warning",
            },
        )
    )
    assert gate["exit_code"] == 0, gate


def test_diff_to_manifest_fails_closed(tmp_path: Path):
    for bad in ["", "not a diff", "--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,2 @@\n+a\n"]:
        assert _call("diff_to_manifest", {"diff": bad})["isError"] is True, bad
    assert _call("diff_to_manifest", {"diff": 42})["isError"] is True
    good = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
    assert _call("diff_to_manifest", {"diff": good, "write_to": str(tmp_path)})["isError"]
    assert _call("diff_to_manifest", {"diff": good, "write_to": str(tmp_path / "no" / "m.json")})[
        "isError"
    ]


def test_diff_to_manifest_write_to_has_a_bounded_blast_radius(tmp_path: Path):
    good = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"

    # Only .json names: the tool must not become a generic file writer.
    result = _call("diff_to_manifest", {"diff": good, "write_to": str(tmp_path / "rc")})
    assert result["isError"] and ".json" in _structured(result)["error"]

    # Never clobber an existing file that is not already a manifest.
    precious = tmp_path / "settings.json"
    precious.write_text('{"keep": "me"}')
    result = _call("diff_to_manifest", {"diff": good, "write_to": str(precious)})
    assert result["isError"] and "refusing to overwrite" in _structured(result)["error"]
    assert precious.read_text() == '{"keep": "me"}'

    # Refreshing the tool's own artifact is allowed.
    own = tmp_path / "changed.json"
    first = _structured(_call("diff_to_manifest", {"diff": good, "write_to": str(own)}))
    assert first["manifest_path"] == str(own.resolve())
    again = "--- a/y.py\n+++ b/y.py\n@@ -5 +5 @@\n-a\n+b\n"
    second = _structured(_call("diff_to_manifest", {"diff": again, "write_to": str(own)}))
    assert second["manifest_path"] == str(own.resolve())
    assert json.loads(own.read_text())["files"][0]["path"] == "y.py"

    # A symlinked parent cannot redirect the write outside the intended directory.
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    written = _structured(
        _call("diff_to_manifest", {"diff": good, "write_to": str(link_dir / "m.json")})
    )
    assert written["manifest_path"] == str((real_dir / "m.json").resolve())

    # A symlinked target file is refused; no temp files are left behind anywhere.
    (tmp_path / "victim.json").write_text("{}")
    (tmp_path / "alias.json").symlink_to(tmp_path / "victim.json")
    assert _call("diff_to_manifest", {"diff": good, "write_to": str(tmp_path / "alias.json")})[
        "isError"
    ]
    assert (tmp_path / "victim.json").read_text() == "{}"
    assert not list(tmp_path.rglob(".manifest-*.tmp"))


def _preview_project(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / "src" / "b.go").write_text("package b\n")
    (tmp_path / "src" / "notes.txt").write_text("not source\n")
    (tmp_path / "gen").mkdir()
    (tmp_path / "gen" / "c.py").write_text("y = 2\n")
    (tmp_path / "ignored.py").write_text("z = 3\n")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "huge.rs").write_bytes(b"/" * (2 * 1024 * 1024 + 1))
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.ts").write_text("export {}\n")
    (tmp_path / "cqa.toml").write_text('[analysis]\nexclude = ["gen/**"]\n')
    return tmp_path


def test_preview_accounts_for_every_source_file(tmp_path: Path):
    root = _preview_project(tmp_path)
    payload = _structured(_call("preview", {"path": str(root), "config": str(root / "cqa.toml")}))
    assert payload["schema_version"] == "1.0.0"
    assert [item["path"] for item in payload["planned"]] == ["src/a.py", "src/b.go"]
    assert payload["planned_by_language"] == {"go": 1, "python": 1}
    excluded = {reason: entry["count"] for reason, entry in payload["excluded"].items()}
    assert excluded == {"excluded_by_configuration": 2, "too_large": 1}
    assert payload["excluded"]["excluded_by_configuration"]["examples"] == [
        "ignored.py",  # root-level files are walked before subdirectories
        "gen/c.py",
    ]
    assert payload["considered"] == 5
    assert payload["coverage_rate"] == 2 / 5
    assert payload["pruned_directories"] == 1
    assert payload["pruned_examples"] == ["node_modules"]
    assert payload["truncated"] is False
    assert payload["ruleset_version"] == RULESET_VERSION


def test_preview_matches_the_real_discovery_pass(tmp_path: Path):
    from cqa_analyzer.config import load_config
    from cqa_analyzer.delegate import preview
    from cqa_analyzer.discovery import DiscoveryReport, iter_source_files
    from cqa_analyzer.plugins import create_default_registry

    root = _preview_project(tmp_path)
    configuration = load_config(root, config_path=root / "cqa.toml")
    registry = create_default_registry()
    extensions = tuple(sorted(registry._extensions))
    discovered = {
        path.relative_to(root).as_posix()
        for path, _ in iter_source_files(
            root, extensions, report=DiscoveryReport(), analysis=configuration.analysis
        )
    }
    planned = {item["path"] for item in preview(root, config_path=root / "cqa.toml")["planned"]}
    assert planned == discovered


def test_preview_truncates_honestly_at_the_file_limit(tmp_path: Path):
    for index in range(4):
        (tmp_path / f"f{index}.py").write_text("x = 1\n")
    payload = _structured(_call("preview", {"path": str(tmp_path), "max_files": 2}))
    assert payload["planned_count"] == 2
    assert payload["truncated"] is True
    assert payload["excluded"]["file_limit"]["count"] == 1
    assert _call("preview", {"path": str(tmp_path), "max_files": 0})["isError"] is True
    assert _call("preview", {"path": str(tmp_path / "missing")})["isError"] is True


def test_rules_for_files_groups_by_rule_set_and_explains_unselected(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n")
    (tmp_path / "pkg" / "b.py").write_text("y = 2\n")
    (tmp_path / "main.go").write_text("package main\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.ts").write_text("export {}\n")
    (tmp_path / "README.md").write_text("# hi\n")
    (tmp_path / "big.rs").write_bytes(b"/" * (2 * 1024 * 1024 + 1))

    payload = _structured(
        _call(
            "rules_for_files",
            {
                "path": str(tmp_path),
                "files": [
                    "pkg/a.py",
                    "pkg\\b.py",  # backslashes normalise
                    "pkg/a.py",  # duplicates collapse
                    "main.go",
                    "node_modules/dep.ts",
                    "README.md",
                    "big.rs",
                    "ghost.py",
                ],
            },
        )
    )
    assert payload["schema_version"] == "1.0.0"
    assert payload["requested"] == 7
    assert payload["selected"] == 3
    languages = [group["language"] for group in payload["groups"]]
    assert languages == ["go", "python"]
    python_group = payload["groups"][1]
    assert python_group["files"] == ["pkg/a.py", "pkg/b.py"]
    rule_ids = [rule["rule_id"] for rule in python_group["rules"]]
    assert rule_ids == [r for r in builtin_rule_ids() if r.startswith("PY-")]
    assert all(rule["not_when"] for rule in python_group["rules"])
    reasons = {item["path"]: item["reason"] for item in payload["unselected"]}
    assert reasons == {
        "node_modules/dep.ts": "skipped_directory:node_modules",
        "README.md": "unsupported_extension",
        "big.rs": "too_large",
        "ghost.py": "missing",
    }
    assert payload["ruleset_version"] == RULESET_VERSION
    assert len(payload["config_fingerprint"]) == 64


def test_rules_for_files_applies_project_rule_policy(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "cqa.toml").write_text(
        '[rules."PY-MAINT-003"]\nenabled = false\n[rules."PY-COR-007"]\nseverity = "error"\n'
    )
    payload = _structured(
        _call(
            "rules_for_files",
            {"path": str(tmp_path), "files": ["a.py"], "config": str(tmp_path / "cqa.toml")},
        )
    )
    rules = {rule["rule_id"]: rule for rule in payload["groups"][0]["rules"]}
    assert "PY-MAINT-003" not in rules
    assert rules["PY-COR-007"]["severity"] == "error"


def test_rules_for_files_rejects_hostile_paths_as_tool_errors(tmp_path: Path):
    for bad in ["/etc/passwd", "../up.py", "http://x/y.py", "C:/x.py", "", "a\x00.py"]:
        result = _call("rules_for_files", {"path": str(tmp_path), "files": [bad]})
        assert result["isError"] is True, bad
    result = _call("rules_for_files", {"path": str(tmp_path), "files": "a.py"})
    assert result["isError"] is True
    result = _call("rules_for_files", {"path": str(tmp_path / "nope"), "files": ["a.py"]})
    assert result["isError"] is True


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
    # Negative conditions ride along so a consumer can judge precision.
    assert isinstance(payload["not_when"], list)
    assert any("interpolation" in clause for clause in payload["not_when"])


def test_every_builtin_rule_declares_negative_conditions():
    from cqa_analyzer.rule_metadata import rule_metadata

    missing = [rule_id for rule_id in builtin_rule_ids() if not rule_metadata(rule_id).not_when]
    assert missing == [], f"rules without not_when: {missing}"
    for rule_id in builtin_rule_ids():
        for clause in rule_metadata(rule_id).not_when:
            assert clause.strip() == clause and clause.endswith((".", ")")), (rule_id, clause)


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
