"""JavaScript and TypeScript source parsing, imports, calls, and routes."""
from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Literal

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from cv_agent.domain.types import CodeDocument
from cv_agent.code_adapters.common import GUARD_RE, _descendants, _node_text
from cv_agent.code_adapters.models import ParsedSource, SourceDocumentSpan


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())


TYPESCRIPT_LANGUAGE = Language(tree_sitter_typescript.language_typescript())


TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())


JAVASCRIPT_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})


TYPESCRIPT_SUFFIXES = frozenset({".ts", ".tsx", ".mts", ".cts"})


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
