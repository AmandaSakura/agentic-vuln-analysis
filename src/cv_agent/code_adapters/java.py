from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import tree_sitter_java
from tree_sitter import Language, Node, Parser

from cv_agent.domain.types import CodeDocument
from cv_agent.code_adapters.source_files import read_source_bytes


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


def _receiver_types(source: bytes, method: Node) -> dict[str, str]:
    receiver_types: dict[str, str] = {}
    for node in _descendants(method):
        if node.type in {
            "formal_parameter",
            "catch_formal_parameter",
            "spread_parameter",
        }:
            declared_type = _simple_type(
                _node_text(source, node.child_by_field_name("type"))
            )
            name = _node_text(source, node.child_by_field_name("name"))
            if declared_type and name:
                receiver_types[name] = declared_type
        elif node.type == "local_variable_declaration":
            declared_type = _simple_type(
                _node_text(source, node.child_by_field_name("type"))
            )
            if not declared_type:
                continue
            for child in node.named_children:
                if child.type != "variable_declarator":
                    continue
                name = _node_text(source, child.child_by_field_name("name"))
                if name:
                    receiver_types[name] = declared_type
        elif node.type == "enhanced_for_statement":
            declared_type = _simple_type(
                _node_text(source, node.child_by_field_name("type"))
            )
            name = _node_text(source, node.child_by_field_name("name"))
            if declared_type and name:
                receiver_types[name] = declared_type
    return receiver_types


def _dispatch_types(source: bytes, declaration: Node) -> tuple[str, ...]:
    dispatch: set[str] = set()
    for field in ("interfaces", "superclass"):
        relation = declaration.child_by_field_name(field)
        if relation is None:
            continue
        for node in _descendants(relation):
            if node.type in {"type_identifier", "scoped_type_identifier"}:
                declared_type = _simple_type(_node_text(source, node))
                if declared_type:
                    dispatch.add(declared_type)
    return tuple(sorted(dispatch))


def _direct_nested_types(source: bytes, declaration: Node) -> tuple[str, ...]:
    body = declaration.child_by_field_name("body")
    if body is None:
        return ()
    names = {
        _node_text(source, child.child_by_field_name("name"))
        for child in body.named_children
        if child.type in TYPE_NODES
    }
    return tuple(sorted(name for name in names if name))


def _parameter_types(source: bytes, method: Node) -> tuple[str, ...]:
    parameters = method.child_by_field_name("parameters")
    if parameters is None:
        return ()
    result: list[str] = []
    for parameter in parameters.named_children:
        declared_type = _simple_type(
            _node_text(source, parameter.child_by_field_name("type"))
        )
        if declared_type:
            result.append(declared_type)
    return tuple(result)


def _argument_type(
    source: bytes,
    argument: Node,
    receiver_types: dict[str, str],
) -> str | None:
    text = _node_text(source, argument)
    if argument.type == "identifier":
        return receiver_types.get(text)
    if argument.type in {"string_literal", "character_literal"}:
        return "String" if argument.type == "string_literal" else "char"
    if argument.type in {
        "decimal_integer_literal",
        "hex_integer_literal",
        "octal_integer_literal",
        "binary_integer_literal",
    }:
        return "int"
    if argument.type in {"true", "false"}:
        return "boolean"
    if argument.type in {"object_creation_expression", "array_creation_expression"}:
        declared_type = _simple_type(
            _node_text(source, argument.child_by_field_name("type"))
        )
        if argument.type == "array_creation_expression" and declared_type:
            return f"{declared_type}[]"
        return declared_type or None
    if argument.type == "cast_expression":
        declared_type = _simple_type(
            _node_text(source, argument.child_by_field_name("type"))
        )
        return declared_type or None
    return None


def _call_symbols(
    base: str,
    source: bytes,
    arguments: Node | None,
    receiver_types: dict[str, str],
) -> set[str]:
    symbols = {base}
    nodes = tuple(arguments.named_children) if arguments is not None else ()
    types = tuple(_argument_type(source, node, receiver_types) for node in nodes)
    if all(value is not None for value in types):
        symbols.add(f"{base}({','.join(value for value in types if value is not None)})")
    else:
        symbols.add(f"{base}#{len(nodes)}")
    return symbols


def _method_calls(
    source: bytes,
    method: Node,
    class_name: str,
    nested_types: tuple[str, ...],
) -> tuple[str, ...]:
    calls: set[str] = set()
    receiver_types = _receiver_types(source, method)
    for node in _descendants(method):
        if node.type == "method_invocation":
            name = _node_text(source, node.child_by_field_name("name"))
            if not name:
                continue
            receiver_node = node.child_by_field_name("object")
            receiver = _node_text(source, receiver_node)
            receiver_type = _simple_type(receiver)
            base: str | None = None
            if receiver_node is not None and receiver_node.type == "object_creation_expression":
                created_type = _simple_type(
                    _node_text(source, receiver_node.child_by_field_name("type"))
                )
                if created_type:
                    owner = (
                        f"{class_name}.{created_type}"
                        if created_type in nested_types
                        else created_type
                    )
                    base = f"{owner}.{name}"
            elif receiver in receiver_types:
                declared_type = receiver_types[receiver]
                owner = (
                    f"{class_name}.{declared_type}"
                    if declared_type in nested_types
                    else declared_type
                )
                base = f"{owner}.{name}"
            elif receiver_type and receiver_type[:1].isupper():
                base = f"{receiver_type}.{name}"
            elif not receiver:
                base = f"{class_name}.{name}"
            if base:
                calls.update(
                    _call_symbols(
                        base,
                        source,
                        node.child_by_field_name("arguments"),
                        receiver_types,
                    )
                )
        elif node.type == "object_creation_expression":
            created_type = _simple_type(_node_text(source, node.child_by_field_name("type")))
            if created_type:
                owner = (
                    f"{class_name}.{created_type}"
                    if created_type in nested_types
                    else created_type
                )
                calls.update(
                    _call_symbols(
                        f"{owner}.<init>",
                        source,
                        node.child_by_field_name("arguments"),
                        receiver_types,
                    )
                )
    return tuple(sorted(calls))


def _method_document(
    repository_id: str,
    relative_path: str,
    source: bytes,
    method: Node,
    class_name: str,
    dispatch_types: tuple[str, ...],
    nested_types: tuple[str, ...],
) -> CodeDocument:
    declared_name = _node_text(source, method.child_by_field_name("name"))
    is_constructor = method.type == "constructor_declaration"
    symbol_name = "<init>" if is_constructor else declared_name
    definitions = {f"{class_name}.{symbol_name}"}
    parameter_types = _parameter_types(source, method)
    definitions.add(f"{class_name}.{symbol_name}#{len(parameter_types)}")
    definitions.add(
        f"{class_name}.{symbol_name}({','.join(parameter_types)})"
    )
    if not is_constructor:
        for dispatch_type in dispatch_types:
            definitions.add(f"{dispatch_type}.{symbol_name}")
            definitions.add(
                f"{dispatch_type}.{symbol_name}#{len(parameter_types)}"
            )
            definitions.add(
                f"{dispatch_type}.{symbol_name}({','.join(parameter_types)})"
            )
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
        calls=_method_calls(source, method, class_name, nested_types),
    )


def parse_java_source(repository_id: str, relative_path: str, text: str) -> JavaParseResult:
    source = text.encode("utf-8")
    tree = Parser(JAVA_LANGUAGE).parse(source)
    root = tree.root_node
    documents: list[CodeDocument] = []

    def visit(
        node: Node,
        enclosing_type: str | None = None,
        enclosing_dispatch_types: tuple[str, ...] = (),
        enclosing_nested_types: tuple[str, ...] = (),
    ) -> None:
        current_type = enclosing_type
        current_dispatch_types = enclosing_dispatch_types
        current_nested_types = enclosing_nested_types
        if node.type in TYPE_NODES:
            declared_type = _node_text(source, node.child_by_field_name("name"))
            if declared_type:
                current_type = (
                    f"{enclosing_type}.{declared_type}"
                    if enclosing_type
                    else declared_type
                )
                current_dispatch_types = _dispatch_types(source, node)
                current_nested_types = _direct_nested_types(source, node)
        if node.type in METHOD_NODES and current_type:
            documents.append(
                _method_document(
                    repository_id,
                    relative_path,
                    source,
                    node,
                    current_type,
                    current_dispatch_types,
                    current_nested_types,
                )
            )
            return
        for child in node.children:
            visit(
                child,
                current_type,
                current_dispatch_types,
                current_nested_types,
            )

    visit(root)
    return JavaParseResult(documents=tuple(documents), has_error=root.has_error)


def load_java_repository(repository_id: str, source_root: Path) -> tuple[list[CodeDocument], list[str]]:
    documents: list[CodeDocument] = []
    parse_error_paths: list[str] = []
    for source_file in sorted(source_root.rglob("*.java")):
        relative_path = source_file.relative_to(source_root).as_posix()
        try:
            text = read_source_bytes(source_root, relative_path).decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            parse_error_paths.append(relative_path)
            continue
        result = parse_java_source(repository_id, relative_path, text)
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
