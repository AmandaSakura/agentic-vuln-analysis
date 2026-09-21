"""Tree-sitter traversal and guard recognition shared by AST adapters."""
from __future__ import annotations

import re

from tree_sitter import Node


GUARD_RE = re.compile(
    r"(?:^|[._])(?:auth(?:enticate|orize|orization)?|check_?permission|"
    r"has_?permission|require_?(?:role|auth)|guard|policy|tenant|principal|owner)(?:$|[._])",
    re.IGNORECASE,
)


def _node_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _descendants(root: Node):
    yield root
    for child in root.children:
        yield from _descendants(child)
