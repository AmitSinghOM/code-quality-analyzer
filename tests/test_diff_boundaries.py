"""Git diff records use LF, not Python's broader Unicode line boundaries."""

import pytest

from cqa_analyzer.changed_lines import ChangedLinesError, diff_to_manifest


@pytest.mark.parametrize(
    "separator", ["\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
@pytest.mark.parametrize("ending", ["\n", "\r\n", ""])
def test_content_separators_do_not_change_hunk_counts(separator, ending):
    diff = (
        "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n"
        f"-before{separator}text\n+after{separator}text\n unchanged"
    )
    if ending == "\r\n":
        diff = diff.replace("\n", "\r\n")
    manifest = diff_to_manifest(diff + ending)
    assert manifest["files"] == [{"path": "x.py", "ranges": [{"start_line": 1, "end_line": 1}]}]


def test_terminal_lf_does_not_supply_missing_context_line():
    diff = "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n-before\n+after\n"
    with pytest.raises(ChangedLinesError, match="ends inside a hunk"):
        diff_to_manifest(diff)
