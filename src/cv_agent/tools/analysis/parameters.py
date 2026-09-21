"""Extract non-Python formal parameters without confusing types or decorators."""

from __future__ import annotations

from pathlib import PurePosixPath

from tree_sitter import Language, Parser
import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_typescript

from cv_agent.domain.types import CodeDocument


LANGUAGES = {
    "go": Language(tree_sitter_go.language()),
    "java": Language(tree_sitter_java.language()),
    "javascript": Language(tree_sitter_javascript.language()),
    "typescript": Language(tree_sitter_typescript.language_typescript()),
}
FUNCTIONS = {
    "method_declaration", "constructor_declaration", "function_declaration",
    "function_expression", "arrow_function", "method_definition",
}


def ast_parameters(document: CodeDocument) -> tuple[str, ...] | None:
    language = document.language
    if language not in LANGUAGES:
        suffix = PurePosixPath(document.path.split("::", 1)[0]).suffix
        language = {".java": "java", ".go": "go", ".js": "javascript", ".ts": "typescript"}.get(suffix, "")
    if language not in LANGUAGES:
        return None
    parser = Parser(LANGUAGES[language])
    candidates = [document.text]
    if language in {"java", "javascript", "typescript"}:
        candidates.insert(0, "class ParameterProbe {\n" + document.text + "\n}")
    for candidate in candidates:
        source = candidate.encode("utf-8")
        root = parser.parse(source).root_node
        if root.has_error:
            continue
        pending = [root]
        while pending:
            node = pending.pop()
            if node.type not in FUNCTIONS:
                pending.extend(reversed(node.named_children))
                continue
            parameters = node.child_by_field_name("parameters")
            if parameters is None:
                parameter = node.child_by_field_name("parameter")
                return (source[parameter.start_byte:parameter.end_byte].decode(),) if parameter else ()
            names: list[str] = []
            for parameter in parameters.named_children:
                named = list(parameter.children_by_field_name("name"))
                if not named:
                    pattern = parameter.child_by_field_name("pattern")
                    if pattern is not None and pattern.type == "identifier":
                        named = [pattern]
                    elif parameter.type == "identifier":
                        named = [parameter]
                if not named:
                    names.append("")  # Preserve positions for unsupported destructuring.
                names.extend(source[item.start_byte:item.end_byte].decode() for item in named)
            return tuple(names)
    return ()
