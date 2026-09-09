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


def test_nested_template_literal_content_never_leaks():
    # Regression: the first backtick inside ${...} used to close the
    # outer template, leaking the nested literal's content into code_text.
    source = "const a = `outer ${ `inner secret` } tail`;\nrun();\n"
    blanked, complete = _strip_ts_comments_and_strings(source)

    assert complete
    assert "inner" not in blanked
    assert "secret" not in blanked
    assert "outer" not in blanked
    assert "tail" not in blanked
    assert "run" in blanked
    assert len(blanked) == len(source)


def test_interpolation_string_containing_brace_does_not_close_early():
    source = "const a = `x ${ f('}') } y`; visited();\n"
    blanked, complete = _strip_ts_comments_and_strings(source)

    assert complete
    assert "visited" in blanked
    assert " y`" not in blanked


def test_interpolation_with_object_literal_braces():
    source = "const a = `v ${ JSON.stringify({depth: {inner: 1}}) } w`; ok();\n"
    blanked, complete = _strip_ts_comments_and_strings(source)

    assert complete
    assert "stringify" not in blanked
    assert "ok" in blanked


def test_escaped_backtick_and_dollar_do_not_end_template():
    source = "const a = `uses \\` and \\${ literally`; after();\n"
    blanked, complete = _strip_ts_comments_and_strings(source)

    assert complete
    assert "literally" not in blanked
    assert "after" in blanked


def test_metadata_pass_keeps_content_with_same_structure():
    source = "const a = `x ${ `y` } z`;\nimport w from 'zod';\n"
    kept, complete = _strip_ts_comments_and_strings(source, blank_strings=False)

    assert complete
    assert kept == source


def test_unterminated_interpolation_marks_incomplete():
    _, complete = _strip_ts_comments_and_strings("const a = `x ${ 1 + ;\n")

    assert complete is False


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


def test_nested_manifest_drift_is_discovered(project):
    root = project({
        "backend/main.go.txt": "not scanned\n",
        "frontend/package.json": json.dumps({
            "name": "web",
            "dependencies": {"react": "^19.0.0"},
        }),
        "frontend/src/app.ts": (
            "import react from 'react';\n"
            "import only from 'server-only';\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    drift = [
        f for f in payload["findings"] if f["rule_id"] == "TS-PKG-001"
    ]

    assert len(drift) == 1
    assert drift[0]["location"]["path"] == "frontend/package.json"
    assert "'server-only'" in drift[0]["message"]
    package = payload["project_analyses"]["typescript:package"]["result"]
    assert package["manifest_present"] is False
    assert package["undeclared_imports"] == ["server-only"]
    assert [m["path"] for m in package["manifests"]] == [
        "frontend/package.json",
    ]


def test_ancestor_declarations_satisfy_nested_imports(project):
    root = project({
        "package.json": json.dumps({
            "name": "root",
            "dependencies": {"zod": "^4.0.0"},
        }),
        "app/package.json": json.dumps({
            "name": "app",
            "dependencies": {"express": "^5.0.0"},
        }),
        "app/src/main.ts": (
            "import express from 'express';\n"
            "import { z } from 'zod';\n"
        ),
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert not [
        f for f in payload["findings"] if f["rule_id"] == "TS-PKG-001"
    ]


def test_workspace_root_skips_nested_manifest_drift(project):
    root = project({
        "package.json": json.dumps({
            "name": "monorepo",
            "workspaces": ["packages/*"],
        }),
        "packages/a/package.json": json.dumps({"name": "a"}),
        "packages/a/src/main.ts": "import { z } from 'zod';\n",
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)

    assert not [
        f for f in payload["findings"] if f["rule_id"] == "TS-PKG-001"
    ]


def test_invalid_nested_manifest_reports_and_skips_drift(project):
    root = project({
        "frontend/package.json": "{broken",
        "frontend/src/app.ts": "import { z } from 'zod';\n",
    })

    result = CliRunner().invoke(main, [str(root), "-f", "json"])
    payload = json.loads(result.output)
    rules = [
        f["rule_id"]
        for f in payload["findings"]
        if f["rule_id"].startswith("TS-PKG")
    ]

    assert rules == ["TS-PKG-002"]
    invalid = [
        f for f in payload["findings"] if f["rule_id"] == "TS-PKG-002"
    ][0]
    assert invalid["location"]["path"] == "frontend/package.json"


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
        "languages": ["csharp", "go", "java", "kotlin", "python", "typescript"],
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
