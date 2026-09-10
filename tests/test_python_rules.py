"""Python rule behaviours checked end to end through the CLI."""

from __future__ import annotations

import json

from click.testing import CliRunner

from cqa_analyzer.__main__ import main


def test_documented_silent_handler_is_a_note_like_other_languages(project):
    # Round 2, C1: `except: pass  # intentional` matches the regex languages'
    # documented-empty-catch behaviour (note, not warning).
    root = project(
        {
            "a.py": (
                "def f():\n"
                "    try:\n        g()\n    except Exception:\n        pass\n\n"
                "def h():\n"
                "    try:\n        g()\n"
                "    except Exception:  # best effort: cache warm-up\n        pass\n"
            ),
        }
    )
    payload = json.loads(CliRunner().invoke(main, [str(root), "-f", "json"]).output)
    by_line = {
        f["location"]["line"]: f for f in payload["findings"] if f["rule_id"] == "PY-COR-003"
    }
    assert by_line[4]["severity"] == "warning"
    assert by_line[10]["severity"] == "note" and "documenting" in by_line[10]["message"]
