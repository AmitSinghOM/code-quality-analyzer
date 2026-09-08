"""Bounded TypeScript/JavaScript pilot adapter, rules, and provider."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cqa_analyzer.__main__ import main
from cqa_analyzer.languages.typescript import (
    TypeScriptLanguageAdapter,
    TypeScriptRulePack,
    _strip_ts_comments_and_strings,
)
from cqa_analyzer.protocols import SourceFile


def parse_ts(source: str, name: str = "service.ts"):
    source_file = SourceFile(
        path=Path(name),
        display_path=name,
        identity_path=f"src/{name}",
        content=source,
    )
    return TypeScriptLanguageAdapter().parse(source_file)


def test_adapter_extracts_import_specifiers():
    parsed = parse_ts(
        "import express from 'express';\n"
        "import { z } from \"zod\";\n"
        "import './globals.css';\n"
        "const lazy = await import('lodash/fp');\n"
        "const legacy = require('left-pad');\n"
        "export { helper } from './helper';\n"
    )

    assert parsed.complete
    assert set(parsed.facts.imports) == {
        "express", "zod", "./globals.css", "lodash/fp",
        "left-pad", "./helper",
    }


def test_adapter_extracts_bounded_identifiers():
    parsed = parse_ts(
        "export function normalizePhone(raw: string) {\n"
        "  const digits = raw.trim();\n"
        "  return digits;\n"
        "}\n"
        "class ApiClient {}\n"
        "interface Config {}\n"
        "let counter = 0;\n"
        "console.log(counter);\n"
    )
    identifiers = set(parsed.facts.identifiers)

    assert {
        "normalizePhone", "digits", "ApiClient", "Config", "counter",
        "raw", "trim", "raw.trim", "console", "log", "console.log",
    } <= identifiers
    assert "function" not in identifiers
    assert "const" not in identifiers


def test_comments_strings_and_template_interpolations_are_blanked():
    source = (
        "// dijkstra := shortestPath\n"
        "/* new HeapQueue() */\n"
        "const label = 'bloomFilter.check()';\n"
        "const msg = `use ${backtrack('x')} here`;\n"
    )
    blanked, complete = _strip_ts_comments_and_strings(source)

    assert complete
    assert "dijkstra" not in blanked
    assert "HeapQueue" not in blanked
    assert "bloomFilter" not in blanked
    # Template interpolations are conservatively blanked whole.
    assert "backtrack" not in blanked
    assert len(blanked.splitlines()) == len(source.splitlines())


def test_unterminated_block_comment_marks_file_incomplete():
    parsed = parse_ts("const a = 1;\n/* unterminated\n")

    assert parsed.complete is False


def test_empty_catch_is_reported_with_location():
    parsed = parse_ts(
        "export async function save() {\n"
        "  try {\n"
        "    await persist();\n"
        "  } catch (error) {}\n"
        "}\n"
    )

    findings = list(TypeScriptRulePack().evaluate(parsed))

    assert [f.rule_id for f in findings] == ["TS-COR-001"]
    assert findings[0].location.line == 4
    assert findings[0].location.path == "service.ts"


def test_handled_catch_is_not_reported():
    parsed = parse_ts(
        "try {\n"
        "  run();\n"
        "} catch (error) {\n"
        "  console.error(error);\n"
        "}\n"
    )

    assert list(TypeScriptRulePack().evaluate(parsed)) == []


def test_comment_only_catch_is_still_reported():
    # A catch whose body is only a comment still swallows the failure.
    parsed = parse_ts(
        "try {\n"
        "  run();\n"
        "} catch {\n"
        "  // ignore\n"
        "}\n"
    )

    assert [
        f.rule_id for f in TypeScriptRulePack().evaluate(parsed)
    ] == ["TS-COR-001"]


def test_cache_codec_round_trips_facts():
    adapter = TypeScriptLanguageAdapter()
    source_file = SourceFile(
        path=Path("service.ts"),
        display_path="service.ts",
        identity_path="src/service.ts",
        content="import express from 'express';\nconst app = express();\n",
    )
    parsed = adapter.parse(source_file)

    payload = adapter.serialize_parsed(parsed)
    restored = adapter.deserialize_parsed(source_file, payload)

    assert restored.facts == parsed.facts
    assert restored.complete == parsed.complete


def test_undeclared_bare_import_is_reported(project):
    root = project({
        "package.json": json.dumps({
            "name": "demo",
            "dependencies": {"express": "^5.0.0"},
        }),
        "src/app.ts": (
            "import express from 'express';\n"
            "import { z } from 'zod';\n"
            "import helper from './helper';\n"
            "import fs from 'node:fs';\n"
            "import path from 'path';\n"
            "import local from '@/components/button';\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    pkg_findings = [
        f for f in payload["findings"] if f["rule_id"] == "TS-PKG-001"
    ]

    assert len(pkg_findings) == 1
    assert "'zod'" in pkg_findings[0]["message"]
    package = payload["project_analyses"]["typescript:package"]["result"]
    assert package["undeclared_imports"] == ["zod"]
    assert package["name"] == "demo"


def test_workspaces_manifest_skips_drift_analysis(project):
    root = project({
        "package.json": json.dumps({
            "name": "monorepo",
            "workspaces": ["packages/*"],
        }),
        "src/app.ts": "import { z } from 'zod';\n",
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert not [
        f for f in payload["findings"] if f["rule_id"] == "TS-PKG-001"
    ]


def test_invalid_package_json_is_an_error_finding(project):
    root = project({
        "package.json": "{not json",
        "src/app.ts": "export const value = 1;\n",
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert [
        f["rule_id"]
        for f in payload["findings"]
        if f["rule_id"].startswith("TS-PKG")
    ] == ["TS-PKG-002"]


def test_missing_manifest_produces_no_package_findings(project):
    root = project({"src/app.ts": "import { z } from 'zod';\n"})

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert not [
        f for f in payload["findings"] if f["rule_id"].startswith("TS-PKG")
    ]


def test_directive_strings_and_artifacts_are_not_packages(project):
    root = project({
        "package.json": json.dumps({"name": "demo", "dependencies": {}}),
        "src/app.ts": (
            "import weird from '$2';\n"
            "import directive from 'use server';\n"
            "import real from 'server-only';\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    package = payload["project_analyses"]["typescript:package"]["result"]

    assert package["undeclared_imports"] == ["server-only"]


def test_ts_only_project_now_earns_a_real_score(project):
    root = project({
        "src/app.ts": (
            "import express from 'express';\n"
            "export function run() {\n"
            "  try {\n"
            "    work();\n"
            "  } catch {}\n"
            "}\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert result.exit_code == 0
    assert isinstance(payload["architecture_signal_score"], float)
    assert payload["architecture_signal_scope"] == {
        "languages": ["go", "python", "typescript"],
        "applicable": True,
    }
    assert [f["rule_id"] for f in payload["findings"]] == ["TS-COR-001"]
    assert "api_design" in payload["design_patterns"]


def test_javascript_files_are_analyzed_too(project):
    root = project({
        "app.js": "try { run(); } catch (e) {}\n",
        "worker.mjs": "try { run(); } catch {}\n",
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert payload["scan_health"]["languages"] == {"typescript": 2}
    assert [f["rule_id"] for f in payload["findings"]] == [
        "TS-COR-001", "TS-COR-001",
    ]
