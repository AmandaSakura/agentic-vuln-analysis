"""Go source parsing, import resolution, calls, and route annotations."""
from __future__ import annotations

import re
from collections import defaultdict

import tree_sitter_go
from tree_sitter import Language, Node, Parser

from cv_agent.domain.types import CodeDocument
from cv_agent.code_adapters.common import GUARD_RE, _descendants, _node_text
from cv_agent.code_adapters.models import ParsedSource, SourceDocumentSpan


GO_LANGUAGE = Language(tree_sitter_go.language())


def _go_imports(
    source: bytes,
    root: Node,
) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
    aliases: dict[str, set[str]] = defaultdict(set)
    imports: set[str] = set()
    for node in _descendants(root):
        if node.type != "import_spec":
            continue
        path_node = next(
            (
                child
                for child in node.named_children
                if child.type in {"interpreted_string_literal", "raw_string_literal"}
            ),
            None,
        )
        if path_node is None:
            continue
        imported = _node_text(source, path_node).strip("`\"")
        imports.add(imported)
        alias_node = next(
            (
                child
                for child in node.named_children
                if not (
                    child.start_byte == path_node.start_byte
                    and child.end_byte == path_node.end_byte
                    and child.type == path_node.type
                )
            ),
            None,
        )
        alias = (
            _node_text(source, alias_node).strip()
            if alias_node is not None
            else imported.rsplit("/", 1)[-1]
        )
        if alias in {"_", "."}:
            continue
        dotted = imported.replace("/", ".")
        aliases[alias].update({dotted, imported.rsplit("/", 1)[-1]})
    return (
        {name: tuple(sorted(targets)) for name, targets in aliases.items()},
        tuple(sorted(imports)),
    )


def _go_receiver_type(text: str) -> str | None:
    match = re.search(r"\bfunc\s*\(\s*\w+\s+\*?([A-Za-z_]\w*)", text)
    return match.group(1) if match else None


def _go_local_types(text: str) -> dict[str, str]:
    types: dict[str, str] = {}
    header = text.split("{", 1)[0]
    for name, type_name in re.findall(
        r"\b([A-Za-z_]\w*)\s+\*?(?:[A-Za-z_]\w*\.)?"
        r"([A-Z][A-Za-z0-9_]*)\b",
        header,
    ):
        types[name] = type_name
    for name, type_name in re.findall(
        r"\bvar\s+([A-Za-z_]\w*)\s+\*?(?:[A-Za-z_]\w*\.)?"
        r"([A-Z][A-Za-z0-9_]*)",
        text,
    ):
        types[name] = type_name
    for name, constructor in re.findall(
        r"\b([A-Za-z_]\w*)\s*:=\s*(?:[A-Za-z_]\w*\.)?New"
        r"([A-Z][A-Za-z0-9_]*)\s*\(",
        text,
    ):
        types[name] = constructor
    return types


def _go_calls(
    source: bytes,
    root: Node,
    aliases: dict[str, tuple[str, ...]],
    local_types: dict[str, str],
) -> tuple[str, ...]:
    calls: set[str] = set()

    def visit(node: Node, *, is_root: bool = False) -> None:
        if not is_root and node.type in {
            "function_declaration",
            "method_declaration",
            "func_literal",
        }:
            return
        if node.type != "call_expression":
            for child in node.children:
                visit(child)
            return
        function = node.child_by_field_name("function")
        if function is not None:
            if function.type == "identifier":
                calls.add(_node_text(source, function))
            elif function.type == "selector_expression":
                operand = _node_text(source, function.child_by_field_name("operand"))
                field = _node_text(source, function.child_by_field_name("field"))
                if operand in aliases:
                    calls.update(f"{target}.{field}" for target in aliases[operand])
                elif operand in local_types:
                    calls.add(f"{local_types[operand]}.{field}")
                else:
                    calls.update({field, f"{operand}.{field}"})
        for child in node.children:
            visit(child)

    visit(root, is_root=True)
    return tuple(sorted(calls - {""}))


def _go_annotations(
    text: str,
    calls: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    routes: set[str] = set()
    for match in re.finditer(
        r"\.(?P<method>GET|POST|PUT|PATCH|DELETE|HandleFunc)\s*\(\s*"
        r"['\"](?P<path>[^'\"]*)['\"]",
        text,
    ):
        method = "ANY" if match.group("method") == "HandleFunc" else match.group("method")
        routes.add(f"{method}:{match.group('path')}")
    guards = {call for call in calls if GUARD_RE.search(call)}
    return tuple(sorted(routes)), tuple(sorted(guards))


def parse_go_source(
    repository_id: str,
    relative_path: str,
    text: str,
) -> ParsedSource:
    source = text.encode("utf-8")
    root = Parser(GO_LANGUAGE).parse(source).root_node
    package = ""
    for node in root.named_children:
        if node.type == "package_clause":
            package = _node_text(source, node).split()[-1]
            break
    aliases, imports = _go_imports(source, root)
    spans: list[SourceDocumentSpan] = []
    for node in _descendants(root):
        if node.type not in {"function_declaration", "method_declaration"}:
            continue
        name = _node_text(source, node.child_by_field_name("name"))
        snippet = _node_text(source, node)
        receiver = _go_receiver_type(snippet) if node.type == "method_declaration" else None
        qualified = f"{receiver}.{name}" if receiver else name
        definitions = {name, qualified}
        if package:
            definitions.update({f"{package}.{name}", f"{package}.{qualified}"})
        calls = _go_calls(source, node, aliases, _go_local_types(snippet))
        routes, guards = _go_annotations(snippet, calls)
        start_line = node.start_point.row + 1
        end_line = node.end_point.row + 1
        document = CodeDocument(
            repository_id=repository_id,
            path=f"{relative_path}::{qualified}@{start_line}-{end_line}",
            text=snippet,
            language="go",
            adapter_tier="ast",
            defines=tuple(sorted(definitions - {""})),
            calls=calls,
            imports=imports,
            routes=routes,
            guards=guards,
        )
        spans.append(
            SourceDocumentSpan(
                relative_path=relative_path,
                start_line=start_line,
                end_line=end_line,
                document=document,
                language="go",
                adapter_tier="ast",
            )
        )
    return ParsedSource(spans=tuple(spans), has_error=root.has_error)
