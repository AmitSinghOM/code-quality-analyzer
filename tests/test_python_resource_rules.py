"""Conservative async-blocking and resource-ownership rules."""

import ast

from analyzer.python_rules import PythonRuleAnalyzer
from analyzer.scanner import CodeScanner


def findings(source: str):
    return PythonRuleAnalyzer().analyze(ast.parse(source), "module.py")


def test_blocking_allowlist_and_aliases_in_async_functions():
    source = (
        "import time as clock\n"
        "from subprocess import run as execute\n"
        "from pathlib import Path as P\n"
        "async def load(path):\n"
        "    clock.sleep(1)\n"
        "    execute(['task'])\n"
        "    P(path).read_text()\n"
        "    with open(path) as stream:\n"
        "        return stream.read()\n"
    )

    result = [item for item in findings(source) if item.rule_id == "PY-COR-005"]

    assert [item.location.line for item in result] == [5, 6, 7, 8]
    assert [item.location.column for item in result] == [5, 5, 5, 10]


def test_blocking_rule_skips_sync_scopes_shadowing_and_offloading():
    source = (
        "import asyncio\nimport time\n"
        "def sync():\n    time.sleep(1)\n"
        "async def shadowed(time, open):\n"
        "    time.sleep(1)\n    open('x')\n"
        "async def offloaded():\n"
        "    await asyncio.to_thread(time.sleep, 1)\n"
        "    def deferred():\n        time.sleep(1)\n"
    )

    assert [item for item in findings(source) if item.rule_id == "PY-COR-005"] == []


def test_unmanaged_local_and_chained_resources_are_reported():
    source = (
        "def load(first, second):\n"
        "    handle = open(first)\n"
        "    content = open(second).read()\n"
        "    return handle, content\n"
    )

    result = [item for item in findings(source) if item.rule_id == "PY-COR-006"]

    assert [item.location.line for item in result] == [2, 3]


def test_context_manager_exit_stack_and_finally_are_compliant():
    source = (
        "from contextlib import ExitStack\n"
        "def load(first, second, third):\n"
        "    with open(first) as stream:\n        stream.read()\n"
        "    stack = ExitStack()\n"
        "    other = stack.enter_context(open(second))\n"
        "    final = open(third)\n"
        "    try:\n        final.read()\n"
        "    finally:\n        final.close()\n"
    )

    result = [item for item in findings(source) if item.rule_id == "PY-COR-006"]

    assert result == []


def test_escaped_resource_ownership_is_not_judged_locally():
    source = (
        "def returned(path):\n    return open(path)\n"
        "def passed(path):\n    consume(open(path))\n"
        "def stored(self, path):\n    self.handle = open(path)\n"
    )

    result = [item for item in findings(source) if item.rule_id == "PY-COR-006"]

    assert result == []


def test_resource_aliases_and_unknown_receiver_boundary():
    source = (
        "import tempfile as temp\n"
        "from pathlib import Path as P\n"
        "def load(path, unknown):\n"
        "    first = temp.NamedTemporaryFile()\n"
        "    second = P(path).open()\n"
        "    third = unknown.open()\n"
    )

    result = [item for item in findings(source) if item.rule_id == "PY-COR-006"]

    assert [item.location.line for item in result] == [4, 5]


def test_async_open_can_emit_both_findings_and_be_suppressed(project):
    root = project({
        "module.py": (
            "async def load(path):\n"
            "    handle = open(path)  "
            "# cqa: ignore=PY-COR-005,PY-COR-006 reason='legacy adapter'\n"
            "    return handle.read()\n"
        ),
    })
    scanner = CodeScanner(root)

    scanner.scan()

    assert scanner.findings == []
