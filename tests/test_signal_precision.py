"""Cross-language precision: ordinary code must not fire algorithmic patterns."""

from __future__ import annotations

from pathlib import Path

import pytest

from cqa_analyzer.languages.csharp import (
    CSharpArchitectureSignalProvider,
    CSharpLanguageAdapter,
)
from cqa_analyzer.languages.go import GoArchitectureSignalProvider, GoLanguageAdapter
from cqa_analyzer.languages.java import (
    JavaArchitectureSignalProvider,
    JavaLanguageAdapter,
)
from cqa_analyzer.languages.typescript import (
    TsArchitectureSignalProvider,
    TypeScriptLanguageAdapter,
)
from cqa_analyzer.protocols import SourceFile

# A plain binary tree node with parent links and find/union helper names —
# the shape that used to fire two_pointers and union_find in the pilots.
_TREE_SOURCES = {
    "go": (
        GoLanguageAdapter,
        GoArchitectureSignalProvider,
        "node.go",
        "package tree\n\ntype Node struct {\n\tleft, right, parent *Node\n}\n\n"
        "func (n *Node) find() *Node { return n.parent }\n"
        "func (n *Node) union(o *Node) { n.left = o; n.right = o }\n",
    ),
    "typescript": (
        TypeScriptLanguageAdapter,
        TsArchitectureSignalProvider,
        "node.ts",
        "export class Node { left: Node | null = null; right: Node | null = null;"
        " parent: Node | null = null;\n"
        "  find() { return this.parent; }\n  union(o: Node) { this.left = o; }\n}\n",
    ),
    "java": (
        JavaLanguageAdapter,
        JavaArchitectureSignalProvider,
        "Node.java",
        "class Node { Node left; Node right; Node parent;\n"
        "  Node find() { return parent; }\n  void union(Node o) { left = o; }\n}\n",
    ),
    "csharp": (
        CSharpLanguageAdapter,
        CSharpArchitectureSignalProvider,
        "Node.cs",
        "class Node { Node left; Node right; Node parent;\n"
        "  Node Find() { return parent; }\n  void Union(Node o) { left = o; }\n}\n",
    ),
}


@pytest.mark.parametrize("language", sorted(_TREE_SOURCES))
def test_tree_shaped_code_fires_no_algorithmic_dsa_pattern(language):
    adapter_cls, provider_cls, name, source = _TREE_SOURCES[language]
    parsed = adapter_cls().parse(SourceFile(Path(name), name, name, source))
    fired = {
        o.signal_id for o in provider_cls().evaluate(parsed) if o.category == "architecture.dsa"
    }
    assert not fired & {"two_pointers", "union_find", "graph_traversal"}, fired


def test_explicit_two_pointer_and_union_find_still_fire_in_java():
    source = (
        "class Solver {\n"
        "  int[] findParent; int[] unionByRank;\n"
        "  int findRoot(int x) { return findParent[x]; }\n"
        "  boolean twoPointers(int[] a) { int leftPointer = 0, rightPointer = 1; return true; }\n"
        "}\n"
    )
    parsed = JavaLanguageAdapter().parse(SourceFile(Path("S.java"), "S.java", "S.java", source))
    fired = {o.signal_id for o in JavaArchitectureSignalProvider().evaluate(parsed)}
    assert {"two_pointers", "union_find"} <= fired


def test_text_anchors_respect_word_boundaries_at_their_edges():
    # Staff review C10.
    from pathlib import Path

    from cqa_analyzer.signals import FileSignals

    def has(text, fragment):
        return FileSignals(Path("x"), 1, text.lower(), set(), set()).has_text(fragment)

    assert not has("foo(hello, hi)", "lo, hi")
    assert has("search(lo, hi)", "lo, hi")
    assert not has("x = y >> 10", ">> 1")
    assert has("x = y >> 1;", ">> 1")
    assert has("self.stack.append(v)", "stack.append")
    assert not has("humid = 3", "mid =")
    assert has("mid = (lo + hi) // 2", "mid =")
    assert has("seen := map[string]struct{}{}", "]struct{}{")
    assert has("if (x) { try { f() } }", "try {")
