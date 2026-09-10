from __future__ import annotations

import posixpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

import tree_sitter_go
import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from .harness import FULL_SYSTEM_HARNESS
from .python_ast import parse_python_source
from .source_files import read_source_bytes
from .types import CodeDocument


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())
TYPESCRIPT_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())
GO_LANGUAGE = Language(tree_sitter_go.language())

JAVASCRIPT_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})
TYPESCRIPT_SUFFIXES = frozenset({".ts", ".tsx", ".mts", ".cts"})
FALLBACK_SUFFIXES = frozenset(FULL_SYSTEM_HARNESS.fallback_suffixes)
SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", "node_modules", "vendor", "dist", "build"}
)

JS_FUNCTION_NODES = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function_declaration",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
JS_NAMED_FUNCTION_NODES = frozenset(
    {"function_declaration", "generator_function_declaration", "method_definition"}
)
JS_CLASS_NODES = frozenset({"class", "class_declaration"})
JS_ROUTE_METHODS = frozenset(
    {"all", "delete", "get", "patch", "post", "put", "route", "use"}
)
GUARD_RE = re.compile(
    r"(?:^|[._])(?:auth(?:enticate|orize|orization)?|check_?permission|"
    r"has_?permission|require_?(?:role|auth)|guard|policy|tenant|principal|owner)(?:$|[._])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SourceDocumentSpan:
    relative_path: str
    start_line: int
    end_line: int
    document: CodeDocument
    language: str
    adapter_tier: Literal["ast", "fallback"]


@dataclass(frozen=True)
class ParsedSource:
    spans: tuple[SourceDocumentSpan, ...]
    has_error: bool


@dataclass(frozen=True)
class CodeRepositoryDocuments:
    documents: tuple[CodeDocument, ...]
    spans: tuple[SourceDocumentSpan, ...]
    parse_error_paths: tuple[str, ...]
    source_file_count: int
    language_file_counts: dict[str, int]
    adapter_tier_file_counts: dict[str, int]

    def locate(self, relative_path: str, line: int) -> SourceDocumentSpan | None:
        normalized = PurePosixPath(relative_path.removeprefix("./")).as_posix()
        matches = [
            span
            for span in self.spans
            if span.relative_path == normalized
            and span.start_line <= line <= span.end_line
        ]
        if not matches:
            return None
        return min(
            matches,
            key=lambda span: (span.end_line - span.start_line, span.start_line),
        )


def _node_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _descendants(root: Node):
    yield root
    for child in root.children:
        yield from _descendants(child)


def _module_variants(relative_path: str) -> tuple[str, ...]:
    path = PurePosixPath(relative_path)
    without_suffix = path.with_suffix("").as_posix()
    if without_suffix.endswith("/index"):
        without_suffix = without_suffix.removesuffix("/index")
    dotted = without_suffix.replace("/", ".").strip(".")
    names = {dotted}
    if dotted.startswith("src."):
        names.add(dotted.removeprefix("src."))
    return tuple(sorted(name for name in names if name))


def _resolved_module_variants(
    relative_path: str,
    imported: str,
) -> tuple[str, ...]:
    if imported.startswith("."):
        joined = posixpath.normpath(
            posixpath.join(PurePosixPath(relative_path).parent.as_posix(), imported)
        )
        return _module_variants(joined)
    dotted = imported.replace("/", ".").strip(".")
    return (dotted,) if dotted else ()


def _js_imports(
    relative_path: str,
    text: str,
) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...]]:
    aliases: dict[str, set[str]] = defaultdict(set)
    imports: set[str] = set()
    for match in re.finditer(
        r"\bimport\s+(?P<clause>[^;\n]+?)\s+from\s+['\"](?P<source>[^'\"]+)['\"]",
        text,
    ):
        clause = match.group("clause").strip()
        imported = match.group("source")
        imports.add(imported)
        modules = _resolved_module_variants(relative_path, imported)
        namespace = re.search(r"\*\s+as\s+(\w+)", clause)
        if namespace:
            aliases[namespace.group(1)].update(modules)
        named = re.search(r"\{([^}]*)\}", clause)
        if named:
            for entry in named.group(1).split(","):
                parts = re.split(r"\s+as\s+", entry.strip())
                if not parts or not parts[0]:
                    continue
                imported_name = parts[0].strip()
                local_name = parts[-1].strip()
                aliases[local_name].update(
                    f"{module}.{imported_name}" for module in modules
                )
        default_clause = clause.split(",", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", default_clause):
            for module in modules:
                aliases[default_clause].update({module, f"{module}.default"})

    for match in re.finditer(
        r"\b(?:const|let|var)\s+(?P<binding>\{[^}]+\}|[A-Za-z_$][\w$]*)\s*=\s*"
        r"require\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)(?!\s*\.)",
        text,
    ):
        binding = match.group("binding")
        imported = match.group("source")
        imports.add(imported)
        modules = _resolved_module_variants(relative_path, imported)
        if binding.startswith("{"):
            for entry in binding.strip("{}").split(","):
                parts = [part.strip() for part in entry.split(":", 1)]
                imported_name = parts[0]
                local_name = parts[-1]
                aliases[local_name].update(
                    f"{module}.{imported_name}" for module in modules
                )
        else:
            aliases[binding].update(modules)

    for match in re.finditer(
        r"\b(?:const|let|var)\s+(?P<binding>[A-Za-z_$][\w$]*)\s*=\s*"
        r"require\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)\s*\.\s*"
        r"(?P<member>[A-Za-z_$][\w$]*)",
        text,
    ):
        imported = match.group("source")
        imports.add(imported)
        modules = _resolved_module_variants(relative_path, imported)
        aliases[match.group("binding")].update(
            f"{module}.{match.group('member')}" for module in modules
        )

    for match in re.finditer(r"\bimport\s+['\"]([^'\"]+)['\"]", text):
        imports.add(match.group(1))
    return (
        {name: tuple(sorted(targets)) for name, targets in aliases.items()},
        tuple(sorted(imports)),
    )


def _js_expression_parts(source: bytes, node: Node | None) -> list[str]:
    if node is None:
        return []
    if node.type in {
        "identifier",
        "private_property_identifier",
        "property_identifier",
        "this",
    }:
        return [_node_text(source, node)]
    if node.type in {"member_expression", "optional_member_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        return [
            *_js_expression_parts(source, object_node),
            *_js_expression_parts(source, property_node),
        ]
    if node.type == "parenthesized_expression":
        named = node.named_children
        return _js_expression_parts(source, named[0] if named else None)
    return []


def _js_route_call(source: bytes, node: Node) -> tuple[str, Node | None] | None:
    if node.type != "call_expression":
        return None
    parts = _js_expression_parts(source, node.child_by_field_name("function"))
    verb = parts[-1].casefold() if parts else ""
    if verb not in JS_ROUTE_METHODS:
        return None
    arguments = node.child_by_field_name("arguments")
    path_match = re.search(
        r"['\"]([^'\"]*)['\"]",
        _node_text(source, arguments),
    )
    return f"{verb.upper()}:{path_match.group(1) if path_match else ''}", arguments


def _js_named_route_bindings(source: bytes, root: Node) -> dict[str, tuple[str, ...]]:
    bindings: dict[str, set[str]] = defaultdict(set)
    for node in _descendants(root):
        route_call = _js_route_call(source, node)
        if route_call is None:
            continue
        route, arguments = route_call
        if arguments is None:
            continue
        for child in arguments.named_children:
            if child.type == "identifier":
                bindings[_node_text(source, child)].add(route)
    return {
        name: tuple(sorted(routes)) for name, routes in bindings.items()
    }


def _js_default_export_names(text: str) -> set[str]:
    names = {
        match.group(1)
        for match in re.finditer(
            r"\bexport\s+default\s+(?:async\s+)?(?:function|class)\s+"
            r"([A-Za-z_$][\w$]*)",
            text,
        )
    }
    names.update(
        match.group(1)
        for match in re.finditer(
            r"\bexport\s+default\s+([A-Za-z_$][\w$]*)\s*;",
            text,
        )
    )
    names.update(
        match.group(1)
        for match in re.finditer(
            r"\bmodule\.exports\s*=\s*([A-Za-z_$][\w$]*)\s*;",
            text,
        )
    )
    return names


def _is_default_export_node(source: bytes, node: Node) -> bool:
    parent = node.parent
    while parent is not None and parent.start_point.row == node.start_point.row:
        if parent.type == "export_statement":
            return bool(re.match(r"\s*export\s+default\b", _node_text(source, parent)))
        parent = parent.parent
    return False


def _js_calls(
    source: bytes,
    root: Node,
    *,
    aliases: dict[str, tuple[str, ...]],
    class_name: str | None,
) -> tuple[str, ...]:
    calls: set[str] = set()

    def visit(node: Node, *, is_root: bool = False) -> None:
        if not is_root and node.type in JS_FUNCTION_NODES:
            return
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            parts = _js_expression_parts(source, function)
            if parts:
                if len(parts) == 1 and parts[0] in aliases:
                    calls.update(aliases[parts[0]])
                elif parts[0] in aliases:
                    for target in aliases[parts[0]]:
                        calls.add(".".join([target, *parts[1:]]))
                elif parts[0] == "this" and class_name and len(parts) == 2:
                    calls.add(f"{class_name}.{parts[-1]}")
                else:
                    calls.add(".".join(parts))
                    calls.add(parts[-1])
                    if len(parts) > 1:
                        calls.add(".".join(parts[-2:]))
        for child in node.children:
            visit(child)

    visit(root, is_root=True)
    return tuple(sorted(calls))


def _js_annotations(text: str, calls: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    routes: set[str] = set()
    for match in re.finditer(
        r"@(?P<method>Get|Post|Put|Patch|Delete|All)\s*\(\s*"
        r"(?P<path>['\"][^'\"]*['\"])?",
        text,
    ):
        routes.add(
            f"{match.group('method').upper()}:{(match.group('path') or '').strip(chr(39) + chr(34))}"
        )
    for match in re.finditer(
        r"\b(?:app|router|server|fastify)\s*\.\s*"
        r"(?P<method>get|post|put|patch|delete|all|use)\s*\(\s*"
        r"(?P<path>['\"][^'\"]*['\"])?",
        text,
        flags=re.IGNORECASE,
    ):
        routes.add(
            f"{match.group('method').upper()}:{(match.group('path') or '').strip(chr(39) + chr(34))}"
        )
    guards = {call for call in calls if GUARD_RE.search(call)}
    guards.update(
        match.group(0)
        for match in re.finditer(
            r"@(?:UseGuards|Roles|Permissions?|Authorize)\b[^\n]*",
            text,
            flags=re.IGNORECASE,
        )
    )
    return tuple(sorted(routes)), tuple(sorted(guards))


def _js_function_name(source: bytes, node: Node) -> str:
    if node.type == "method_definition":
        return _node_text(source, node.child_by_field_name("name"))
    return _node_text(source, node.child_by_field_name("name"))


def _js_definition_symbols(
    relative_path: str,
    scope: tuple[str, ...],
    name: str,
    *,
    default_export: bool,
) -> tuple[str, ...]:
    qualified = ".".join([*scope, name])
    definitions = {name, qualified}
    for module in _module_variants(relative_path):
        definitions.add(f"{module}.{qualified}")
        definitions.add(f"{module}.{name}")
        if default_export:
            definitions.add(f"{module}.default")
    return tuple(sorted(definitions - {""}))


def _parse_javascript_like(
    repository_id: str,
    relative_path: str,
    text: str,
    *,
    language: Literal["javascript", "typescript"],
    grammar: Language,
) -> ParsedSource:
    source = text.encode("utf-8")
    root = Parser(grammar).parse(source).root_node
    aliases, imports = _js_imports(relative_path, text)
    named_routes = _js_named_route_bindings(source, root)
    default_export_names = _js_default_export_names(text)
    spans: list[SourceDocumentSpan] = []
    emitted: set[tuple[int, int, str]] = set()

    def add_function(
        span_node: Node,
        call_root: Node,
        name: str,
        scope: tuple[str, ...],
        class_name: str | None,
        extra_routes: tuple[str, ...] = (),
        default_export: bool = False,
    ) -> None:
        if not name:
            return
        start_line = span_node.start_point.row + 1
        end_line = span_node.end_point.row + 1
        display = ".".join([*scope, name])
        identity = (span_node.start_byte, span_node.end_byte, display)
        if identity in emitted:
            return
        emitted.add(identity)
        snippet = _node_text(source, span_node)
        calls = _js_calls(
            source,
            call_root,
            aliases=aliases,
            class_name=class_name,
        )
        routes, guards = _js_annotations(snippet, calls)
        document = CodeDocument(
            repository_id=repository_id,
            path=(
                f"{relative_path}::{display}@{start_line}-{end_line}"
                f"#{span_node.start_byte}-{span_node.end_byte}"
            ),
            text=snippet,
            language=language,
            adapter_tier="ast",
            defines=_js_definition_symbols(
                relative_path,
                scope,
                name,
                default_export=default_export,
            ),
            calls=calls,
            imports=imports,
            routes=tuple(sorted({*routes, *extra_routes})),
            guards=guards,
        )
        spans.append(
            SourceDocumentSpan(
                relative_path=relative_path,
                start_line=start_line,
                end_line=end_line,
                document=document,
                language=language,
                adapter_tier="ast",
            )
        )

    def visit(
        node: Node,
        scope: tuple[str, ...] = (),
        class_name: str | None = None,
    ) -> None:
        if node.type == "export_statement" and re.match(
            r"\s*export\s+default\b",
            _node_text(source, node),
        ):
            value = node.child_by_field_name("value")
            if value is None:
                value = next(
                    (
                        child
                        for child in node.named_children
                        if child.type in {"arrow_function", "function_expression"}
                    ),
                    None,
                )
            if value is not None and value.type in {
                "arrow_function",
                "function_expression",
            }:
                add_function(
                    node,
                    value,
                    "default",
                    scope,
                    class_name,
                    (),
                    True,
                )
                for child in value.children:
                    visit(child, (*scope, "default"), class_name)
                return
        if node.type in JS_CLASS_NODES:
            name = _node_text(source, node.child_by_field_name("name"))
            next_scope = (*scope, name) if name else scope
            for child in node.children:
                visit(child, next_scope, name or class_name)
            return
        if node.type in JS_NAMED_FUNCTION_NODES:
            name = _js_function_name(source, node)
            is_default = _is_default_export_node(source, node)
            if not name and is_default:
                name = "default"
            add_function(
                node,
                node,
                name,
                scope,
                class_name,
                named_routes.get(name, ()),
                is_default or name in default_export_names,
            )
            next_scope = (*scope, name) if name else scope
            for child in node.children:
                visit(child, next_scope, class_name)
            return
        if node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in {"arrow_function", "function_expression"}:
                name = _node_text(source, node.child_by_field_name("name"))
                add_function(
                    node,
                    value,
                    name,
                    scope,
                    class_name,
                    named_routes.get(name, ()),
                    name in default_export_names,
                )
                for child in value.children:
                    visit(child, (*scope, name), class_name)
                return
        if node.type in {"pair", "field_definition", "public_field_definition"}:
            value = node.child_by_field_name("value")
            if value is not None and value.type in {"arrow_function", "function_expression"}:
                name_node = node.child_by_field_name("key")
                if name_node is None:
                    name_node = node.child_by_field_name("name")
                if name_node is None and node.named_children:
                    name_node = node.named_children[0]
                name = _node_text(source, name_node).strip("'\"")
                add_function(
                    node,
                    value,
                    name,
                    scope,
                    class_name,
                    named_routes.get(name, ()),
                    name in default_export_names,
                )
                for child in value.children:
                    visit(child, (*scope, name), class_name)
                return
        if node.type == "assignment_expression":
            right = node.child_by_field_name("right")
            if right is not None and right.type in {"arrow_function", "function_expression"}:
                left = _node_text(source, node.child_by_field_name("left"))
                name = left.rsplit(".", 1)[-1]
                add_function(
                    node,
                    right,
                    name,
                    scope,
                    class_name,
                    named_routes.get(name, ()),
                    left == "module.exports" or name in default_export_names,
                )
                for child in right.children:
                    visit(child, (*scope, name), class_name)
                return
        if node.type == "call_expression":
            route_call = _js_route_call(source, node)
            if route_call is not None:
                route, arguments = route_call
                for child in (
                    arguments.named_children if arguments is not None else ()
                ):
                    if child.type in {"arrow_function", "function_expression"}:
                        verb = route.split(":", 1)[0].casefold()
                        name = f"route_{verb}_{child.start_point.row + 1}"
                        add_function(child, child, name, scope, class_name, (route,))
        for child in node.children:
            visit(child, scope, class_name)

    visit(root)
    return ParsedSource(
        spans=tuple(sorted(spans, key=lambda span: (span.relative_path, span.start_line, span.document.path))),
        has_error=root.has_error,
    )


def parse_javascript_source(
    repository_id: str,
    relative_path: str,
    text: str,
) -> ParsedSource:
    grammar = JAVASCRIPT_LANGUAGE
    return _parse_javascript_like(
        repository_id,
        relative_path,
        text,
        language="javascript",
        grammar=grammar,
    )


def parse_typescript_source(
    repository_id: str,
    relative_path: str,
    text: str,
) -> ParsedSource:
    grammar = TSX_LANGUAGE if PurePosixPath(relative_path).suffix == ".tsx" else TYPESCRIPT_LANGUAGE
    return _parse_javascript_like(
        repository_id,
        relative_path,
        text,
        language="typescript",
        grammar=grammar,
    )


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


def _fallback_language(suffix: str) -> str:
    return {
        ".yml": "yaml",
        ".yaml": "yaml",
        ".sh": "shell",
    }.get(suffix, suffix.removeprefix(".") or "unknown")


def _language_for_suffix(suffix: str) -> str:
    if suffix == ".py":
        return "python"
    if suffix in JAVASCRIPT_SUFFIXES:
        return "javascript"
    if suffix in TYPESCRIPT_SUFFIXES:
        return "typescript"
    if suffix == ".go":
        return "go"
    return _fallback_language(suffix)


def parse_fallback_source(
    repository_id: str,
    relative_path: str,
    text: str,
) -> ParsedSource:
    suffix = PurePosixPath(relative_path).suffix.casefold()
    language = _fallback_language(suffix)
    lines = text.splitlines()
    end_line = max(1, len(lines))
    definitions = set(
        re.findall(
            r"(?m)^\s*(?:class|def|function|func)\s+([A-Za-z_]\w*)|"
            r"^\s*([A-Za-z_][\w.-]*)\s*:",
            text,
        )
    )
    flattened_definitions = {
        value for pair in definitions for value in pair if value
    }
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", text))
    document = CodeDocument(
        repository_id=repository_id,
        path=f"{relative_path}::file@1-{end_line}",
        text=text,
        language=language,
        adapter_tier="fallback",
        defines=tuple(sorted(flattened_definitions)),
        calls=tuple(sorted(calls)),
    )
    return ParsedSource(
        spans=(
            SourceDocumentSpan(
                relative_path=relative_path,
                start_line=1,
                end_line=end_line,
                document=document,
                language=language,
                adapter_tier="fallback",
            ),
        ),
        has_error=False,
    )


def _parse_file(
    repository_id: str,
    relative_path: str,
    text: str,
) -> ParsedSource | None:
    suffix = PurePosixPath(relative_path).suffix.casefold()
    if suffix == ".py":
        spans = parse_python_source(repository_id, relative_path, text)
        return ParsedSource(
            spans=tuple(
                SourceDocumentSpan(
                    relative_path=span.relative_path,
                    start_line=span.start_line,
                    end_line=span.end_line,
                    document=span.document,
                    language="python",
                    adapter_tier="ast",
                )
                for span in spans
            ),
            has_error=False,
        )
    if suffix in JAVASCRIPT_SUFFIXES:
        return parse_javascript_source(repository_id, relative_path, text)
    if suffix in TYPESCRIPT_SUFFIXES:
        return parse_typescript_source(repository_id, relative_path, text)
    if suffix == ".go":
        return parse_go_source(repository_id, relative_path, text)
    if suffix in FALLBACK_SUFFIXES:
        return parse_fallback_source(repository_id, relative_path, text)
    return None


def load_code_repository(
    repository_id: str,
    source_root: Path,
) -> CodeRepositoryDocuments:
    spans: list[SourceDocumentSpan] = []
    parse_errors: list[str] = []
    language_counts: Counter[str] = Counter()
    tier_counts: Counter[str] = Counter()
    source_file_count = 0
    for source_file in sorted(path for path in source_root.rglob("*") if path.is_file()):
        if any(part in SKIPPED_DIRECTORIES for part in source_file.parts):
            continue
        relative_path = source_file.relative_to(source_root).as_posix()
        suffix = source_file.suffix.casefold()
        if suffix not in (
            {".py", ".go"}
            | JAVASCRIPT_SUFFIXES
            | TYPESCRIPT_SUFFIXES
            | FALLBACK_SUFFIXES
        ):
            continue
        source_file_count += 1
        language_counts[_language_for_suffix(suffix)] += 1
        tier_counts[
            "fallback" if suffix in FALLBACK_SUFFIXES else "ast"
        ] += 1
        try:
            text = read_source_bytes(source_root, relative_path).decode("utf-8")
            parsed = _parse_file(repository_id, relative_path, text)
        except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
            parse_errors.append(relative_path)
            continue
        if parsed is None:
            continue
        if parsed.has_error:
            parse_errors.append(relative_path)
        spans.extend(parsed.spans)
    ordered = tuple(
        sorted(spans, key=lambda span: (span.relative_path, span.start_line, span.document.path))
    )
    return CodeRepositoryDocuments(
        documents=tuple(span.document for span in ordered),
        spans=ordered,
        parse_error_paths=tuple(sorted(set(parse_errors))),
        source_file_count=source_file_count,
        language_file_counts=dict(sorted(language_counts.items())),
        adapter_tier_file_counts=dict(sorted(tier_counts.items())),
    )
