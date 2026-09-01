from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Node, Parser

from .types import CodeDocument


JAVA_LANGUAGE = Language(tree_sitter_java.language())
METHOD_NODES = {"method_declaration", "constructor_declaration"}
TYPE_NODES = {"class_declaration", "enum_declaration", "interface_declaration", "record_declaration"}
LOCALLY_SCOPED_METHODS = {"doGet", "doPost", "service"}


@dataclass(frozen=True)
class JavaParseResult:
    documents: tuple[CodeDocument, ...]
    has_error: bool


def _node_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _descendants(root: Node):
    yield root
    for child in root.children:
        yield from _descendants(child)


def _simple_type(text: str) -> str:
    return text.rsplit(".", 1)[-1].split("<", 1)[0].strip()


def _method_calls(source: bytes, method: Node, class_name: str) -> tuple[str, ...]:
    calls: set[str] = set()
    for node in _descendants(method):
        if node.type == "method_invocation":
            name = _node_text(source, node.child_by_field_name("name"))
            if not name:
                continue
            receiver = _node_text(source, node.child_by_field_name("object"))
            receiver_type = _simple_type(receiver)
            if receiver_type and receiver_type[:1].isupper():
                calls.add(f"{receiver_type}.{name}")
            elif not receiver:
                calls.add(f"{class_name}.{name}")
            elif name not in LOCALLY_SCOPED_METHODS:
                calls.add(name)
        elif node.type == "object_creation_expression":
            created_type = _simple_type(_node_text(source, node.child_by_field_name("type")))
            if created_type:
                calls.add(f"{created_type}.<init>")
    return tuple(sorted(calls))


def _method_document(
    repository_id: str,
    relative_path: str,
    source: bytes,
    method: Node,
    class_name: str,
) -> CodeDocument:
    declared_name = _node_text(source, method.child_by_field_name("name"))
    is_constructor = method.type == "constructor_declaration"
    symbol_name = "<init>" if is_constructor else declared_name
    definitions = {f"{class_name}.{symbol_name}"}
    if not is_constructor and declared_name not in LOCALLY_SCOPED_METHODS:
        definitions.add(declared_name)
    line = method.start_point.row + 1
    return CodeDocument(
        repository_id=repository_id,
        path=f"{relative_path}::{class_name}.{symbol_name}@{line}",
        text=_node_text(source, method),
        language="java",
        adapter_tier="ast",
        defines=tuple(sorted(definitions)),
        calls=_method_calls(source, method, class_name),
    )


def parse_java_source(repository_id: str, relative_path: str, text: str) -> JavaParseResult:
    source = text.encode("utf-8")
    tree = Parser(JAVA_LANGUAGE).parse(source)
    root = tree.root_node
    documents: list[CodeDocument] = []

    def visit(node: Node, enclosing_type: str | None = None) -> None:
        current_type = enclosing_type
        if node.type in TYPE_NODES:
            declared_type = _node_text(source, node.child_by_field_name("name"))
            if declared_type:
                current_type = declared_type
        if node.type in METHOD_NODES and current_type:
            documents.append(_method_document(repository_id, relative_path, source, node, current_type))
            return
        for child in node.children:
            visit(child, current_type)

    visit(root)
    return JavaParseResult(documents=tuple(documents), has_error=root.has_error)


def load_java_repository(repository_id: str, source_root: Path) -> tuple[list[CodeDocument], list[str]]:
    documents: list[CodeDocument] = []
    parse_error_paths: list[str] = []
    for source_file in sorted(source_root.rglob("*.java")):
        relative_path = source_file.relative_to(source_root).as_posix()
        result = parse_java_source(repository_id, relative_path, source_file.read_text(encoding="utf-8"))
        documents.extend(result.documents)
        if result.has_error:
            parse_error_paths.append(relative_path)
    return documents, parse_error_paths


def profile_owasp_java_ast(raw_root: Path) -> dict[str, int | list[str] | str]:
    source_root = raw_root / "BenchmarkJava" / "src" / "main" / "java"
    if not source_root.is_dir():
        raise ValueError(f"OWASP Java source root not found: {source_root}")
    source_file_count = sum(1 for _ in source_root.rglob("*.java"))
    documents, parse_error_paths = load_java_repository("OWASP-BenchmarkJava-1.2beta", source_root)
    definitions = {symbol for document in documents for symbol in document.defines}
    calls = sum(len(document.calls) for document in documents)
    return {
        "dataset": "OWASP BenchmarkJava 1.2beta",
        "source_file_count": source_file_count,
        "method_document_count": len(documents),
        "definition_count": len(definitions),
        "call_reference_count": calls,
        "parse_error_count": len(parse_error_paths),
        "parse_error_paths": parse_error_paths,
    }
