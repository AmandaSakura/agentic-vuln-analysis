from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .types import CodeDocument


@dataclass(frozen=True)
class PythonDocumentSpan:
    relative_path: str
    start_line: int
    end_line: int
    document: CodeDocument


@dataclass(frozen=True)
class PythonRepositoryDocuments:
    documents: tuple[CodeDocument, ...]
    spans: tuple[PythonDocumentSpan, ...]
    parse_error_paths: tuple[str, ...]
    source_file_count: int

    def locate(self, relative_path: str, line: int) -> PythonDocumentSpan | None:
        normalized = PurePosixPath(relative_path.removeprefix("./")).as_posix()
        matches = [
            span
            for span in self.spans
            if span.relative_path == normalized and span.start_line <= line <= span.end_line
        ]
        if not matches:
            return None
        return min(matches, key=lambda span: (span.end_line - span.start_line, span.start_line))


def _module_names(relative_path: str) -> tuple[str, ...]:
    module = relative_path.removesuffix(".py").replace("/", ".")
    if module.endswith(".__init__"):
        module = module.removesuffix(".__init__")
    names = {module}
    if module.startswith("src."):
        names.add(module.removeprefix("src."))
    return tuple(sorted(name for name in names if name))


def _attribute_parts(node: ast.expr) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [*_attribute_parts(node.value), node.attr]
    return []


def _import_aliases(tree: ast.AST, canonical_module: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    # Only module-level imports are globally valid. Function-local imports are
    # deliberately left unresolved rather than leaking one scope into another.
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                package = canonical_module.split(".")[:-1]
                keep = max(0, len(package) - (node.level - 1))
                prefix = package[:keep]
                module = ".".join([*prefix, *([module] if module else [])])
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = ".".join(part for part in (module, alias.name) if part)
                aliases[alias.asname or alias.name] = target
    return aliases


class _CallCollector(ast.NodeVisitor):
    def __init__(
        self,
        aliases: dict[str, str],
        modules: tuple[str, ...],
        class_name: str | None,
    ) -> None:
        self.aliases = aliases
        self.modules = modules
        self.class_name = class_name
        self.calls: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        parts = _attribute_parts(node.func)
        if parts:
            if parts[0] in self.aliases:
                parts = [*self.aliases[parts[0]].split("."), *parts[1:]]
            if parts[0] in {"self", "cls"} and self.class_name and len(parts) > 1:
                method = parts[-1]
                self.calls.add(f"{self.class_name}.{method}")
                for module in self.modules:
                    self.calls.add(f"{module}.{self.class_name}.{method}")
            else:
                self.calls.add(".".join(parts))
                self.calls.add(parts[-1])
                if len(parts) > 1:
                    self.calls.add(".".join(parts[-2:]))
        self.generic_visit(node)


class _FunctionDocumentBuilder(ast.NodeVisitor):
    def __init__(
        self,
        repository_id: str,
        relative_path: str,
        text: str,
        tree: ast.AST,
    ) -> None:
        self.repository_id = repository_id
        self.relative_path = relative_path
        self.text = text
        self.lines = text.splitlines(keepends=True)
        self.modules = _module_names(relative_path)
        self.aliases = _import_aliases(tree, self.modules[0])
        self.scope: list[str] = []
        self.class_scope: list[str] = []
        self.spans: list[PythonDocumentSpan] = []

    def _add_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        start_line = min(
            [node.lineno, *(decorator.lineno for decorator in node.decorator_list)]
        )
        end_line = node.end_lineno or node.lineno
        qualified_parts = [*self.scope, node.name]
        definitions = {node.name}
        for module in self.modules:
            definitions.add(".".join([module, *qualified_parts]))
        if self.class_scope:
            definitions.add(f"{self.class_scope[-1]}.{node.name}")

        collector = _CallCollector(
            self.aliases,
            self.modules,
            self.class_scope[-1] if self.class_scope else None,
        )
        for decorator in node.decorator_list:
            collector.visit(decorator)
        for statement in node.body:
            collector.visit(statement)
        source = "".join(self.lines[start_line - 1 : end_line])
        display_name = ".".join(qualified_parts)
        document = CodeDocument(
            repository_id=self.repository_id,
            path=f"{self.relative_path}::{display_name}@{start_line}-{end_line}",
            text=source,
            defines=tuple(sorted(definitions)),
            calls=tuple(sorted(collector.calls)),
        )
        self.spans.append(
            PythonDocumentSpan(
                relative_path=self.relative_path,
                start_line=start_line,
                end_line=end_line,
                document=document,
            )
        )

        self.scope.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._add_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._add_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.class_scope.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.class_scope.pop()
        self.scope.pop()


def parse_python_source(
    repository_id: str,
    relative_path: str,
    text: str,
) -> tuple[PythonDocumentSpan, ...]:
    tree = ast.parse(text, filename=relative_path)
    builder = _FunctionDocumentBuilder(repository_id, relative_path, text, tree)
    builder.visit(tree)
    return tuple(builder.spans)


def load_python_repository(
    repository_id: str,
    source_root: Path,
) -> PythonRepositoryDocuments:
    spans: list[PythonDocumentSpan] = []
    parse_errors: list[str] = []
    source_files = [
        path
        for path in sorted(source_root.rglob("*.py"))
        if not any(part in {".git", ".venv", "node_modules"} for part in path.parts)
    ]
    for source_file in source_files:
        relative_path = source_file.relative_to(source_root).as_posix()
        try:
            with tokenize.open(source_file) as handle:
                text = handle.read()
            spans.extend(parse_python_source(repository_id, relative_path, text))
        except (SyntaxError, UnicodeDecodeError):
            parse_errors.append(relative_path)
    return PythonRepositoryDocuments(
        documents=tuple(span.document for span in spans),
        spans=tuple(spans),
        parse_error_paths=tuple(parse_errors),
        source_file_count=len(source_files),
    )
