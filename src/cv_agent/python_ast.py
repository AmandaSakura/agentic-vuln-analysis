from __future__ import annotations

import ast
import io
import re
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .types import CodeDocument
from .source_files import read_source_bytes


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


def _annotation_types(
    node: ast.expr | None,
    aliases: dict[str, str],
) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _annotation_types(node.left, aliases) | _annotation_types(
            node.right,
            aliases,
        )
    if isinstance(node, ast.Subscript):
        return _annotation_types(node.slice, aliases)
    if isinstance(node, (ast.Tuple, ast.List)):
        return {
            name
            for element in node.elts
            for name in _annotation_types(element, aliases)
        }
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            parsed = ast.parse(node.value, mode="eval").body
        except SyntaxError:
            return set()
        return _annotation_types(parsed, aliases)
    parts = _attribute_parts(node)
    if not parts:
        return set()
    raw = ".".join(parts)
    resolved_parts = parts
    if parts[0] in aliases:
        resolved_parts = [*aliases[parts[0]].split("."), *parts[1:]]
    resolved = ".".join(resolved_parts)
    return {
        name
        for name in (raw, parts[-1], resolved, resolved_parts[-1])
        if name not in {"None", "NoneType"}
    }


def _self_field_name(node: ast.expr) -> str | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ):
        return node.attr
    return None


class _FieldTypeCollector(ast.NodeVisitor):
    def __init__(
        self,
        parameter_types: dict[str, set[str]],
        aliases: dict[str, str],
    ) -> None:
        self.parameter_types = parameter_types
        self.aliases = aliases
        self.field_types: dict[str, set[str]] = defaultdict(set)

    def _value_types(self, value: ast.expr | None) -> set[str]:
        if isinstance(value, ast.Name):
            return self.parameter_types.get(value.id, set())
        if isinstance(value, ast.Call):
            return _annotation_types(value.func, self.aliases)
        return set()

    def visit_Assign(self, node: ast.Assign) -> None:
        value_types = self._value_types(node.value)
        for target in node.targets:
            field = _self_field_name(target)
            if field:
                self.field_types[field].update(value_types)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        field = _self_field_name(node.target)
        if field:
            self.field_types[field].update(
                _annotation_types(node.annotation, self.aliases)
            )
            self.field_types[field].update(self._value_types(node.value))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return


def _class_field_types(
    node: ast.ClassDef,
    aliases: dict[str, str],
) -> dict[str, tuple[str, ...]]:
    collected: dict[str, set[str]] = defaultdict(set)
    for statement in node.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target,
            ast.Name,
        ):
            collected[statement.target.id].update(
                _annotation_types(statement.annotation, aliases)
            )
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if statement.name != "__init__":
            continue
        arguments = [
            *statement.args.posonlyargs,
            *statement.args.args,
            *statement.args.kwonlyargs,
        ]
        parameter_types = {
            argument.arg: _annotation_types(argument.annotation, aliases)
            for argument in arguments
        }
        collector = _FieldTypeCollector(parameter_types, aliases)
        for body_statement in statement.body:
            collector.visit(body_statement)
        for field, types in collector.field_types.items():
            collected[field].update(types)
    return {
        field: tuple(sorted(types))
        for field, types in collected.items()
        if types
    }


def _import_aliases(tree: ast.AST, canonical_module: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    # Only module-level imports are globally valid. Function-local imports are
    # deliberately left unresolved rather than leaking one scope into another.
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import pkg.service` binds `pkg`, while `as service` binds
                # the complete imported module. Do not duplicate the suffix.
                bound = alias.asname or alias.name.split(".", 1)[0]
                aliases[bound] = alias.name if alias.asname else bound
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


def _module_bindings(tree: ast.AST, *, assignments_only: bool = False) -> tuple[str, ...]:
    """Bindings in module control-flow blocks, without entering function bodies."""
    names: set[str] = set()
    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not assignments_only:
                names.add(node.name)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        if isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        if not assignments_only and isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        for child in ast.iter_child_nodes(node):
            visit(child)
    visit(tree)
    return tuple(sorted(names))


class _CallCollector(ast.NodeVisitor):
    def __init__(
        self,
        aliases: dict[str, str],
        modules: tuple[str, ...],
        class_name: str | None,
        field_types: dict[str, tuple[str, ...]],
        module_rebindings: tuple[str, ...],
    ) -> None:
        self.aliases = aliases
        self.modules = modules
        self.class_name = class_name
        self.field_types = field_types
        self.module_rebindings = module_rebindings
        self.calls: set[str] = set()
        self.local_aliases: dict[str, tuple[str, ...]] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def _alias_targets(self, node: ast.expr) -> tuple[str, ...]:
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return (self.aliases[node.id],)
            return self.local_aliases.get(node.id, ())
        if isinstance(node, ast.IfExp):
            return tuple(
                sorted({
                    *self._alias_targets(node.body),
                    *self._alias_targets(node.orelse),
                })
            )
        return ()

    def _record_assignment_alias(self, target: ast.expr, value: ast.expr | None) -> None:
        if not isinstance(target, ast.Name):
            return
        aliases = self._alias_targets(value) if value is not None else ()
        if aliases:
            self.local_aliases[target.id] = aliases
        else:
            self.local_aliases.pop(target.id, None)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._record_assignment_alias(target, node.value)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._record_assignment_alias(node.target, node.value)
        if node.value is not None:
            self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        parts = _attribute_parts(node.func)
        if parts:
            if parts[0] in self.local_aliases and len(parts) > 1:
                for alias in self.local_aliases[parts[0]]:
                    resolved = [*alias.split("."), *parts[1:]]
                    self.calls.add(".".join(resolved))
                    self.calls.add(".".join(resolved[-2:]))
                self.generic_visit(node)
                return
            if parts[0] in self.module_rebindings:
                self.generic_visit(node)
                return
            if parts[0] in self.aliases:
                parts = [*self.aliases[parts[0]].split("."), *parts[1:]]
                # A known qualified import must not also emit a bare-name edge.
                self.calls.add(".".join(parts))
                self.generic_visit(node)
                return
            if parts[0] in {"self", "cls"} and self.class_name and len(parts) > 1:
                method = parts[-1]
                if len(parts) == 2:
                    self.calls.add(f"{self.class_name}.{method}")
                    for module in self.modules:
                        self.calls.add(f"{module}.{self.class_name}.{method}")
                elif parts[0] == "self" and len(parts) == 3:
                    for receiver_type in self.field_types.get(parts[1], ()):
                        self.calls.add(f"{receiver_type}.{method}")
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
        module_path: str | None = None,
    ) -> None:
        self.repository_id = repository_id
        self.relative_path = relative_path
        self.text = text
        self.lines = text.splitlines(keepends=True)
        self.modules = _module_names(module_path if module_path is not None else relative_path)
        self.aliases = _import_aliases(tree, self.modules[0])
        self.module_bindings = _module_bindings(tree)
        self.module_rebindings = _module_bindings(tree, assignments_only=True)
        self.scope: list[str] = []
        self.class_scope: list[str] = []
        self.class_bases: list[tuple[str, ...]] = []
        self.class_field_types: list[dict[str, tuple[str, ...]]] = []
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
            for base in self.class_bases[-1]:
                definitions.add(f"{base}.{node.name}")

        collector = _CallCollector(
            self.aliases,
            self.modules,
            self.class_scope[-1] if self.class_scope else None,
            self.class_field_types[-1] if self.class_field_types else {},
            self.module_rebindings,
        )
        for decorator in node.decorator_list:
            collector.visit(decorator)
        for statement in node.body:
            collector.visit(statement)
        source = "".join(self.lines[start_line - 1 : end_line])
        routes = {
            f"{match.group(1).upper()}:{match.group(2)}"
            for match in re.finditer(
                r"@(?:[A-Za-z_]\w*\.)?(get|post|put|patch|delete)\(\s*"
                r"['\"]([^'\"]*)['\"]",
                source,
                flags=re.IGNORECASE,
            )
        }
        guards = {
            call
            for call in collector.calls
            if re.search(
                r"(?:^|[._])(?:auth(?:enticate|orize|orization)?|"
                r"check_?permission|has_?permission|require_?(?:role|auth)|"
                r"guard|policy|tenant|principal|owner)(?:$|[._])",
                call,
                flags=re.IGNORECASE,
            )
        }
        display_name = ".".join(qualified_parts)
        document = CodeDocument(
            repository_id=self.repository_id,
            path=f"{self.relative_path}::{display_name}@{start_line}-{end_line}",
            text=source,
            language="python",
            adapter_tier="ast",
            defines=tuple(sorted(definitions)),
            calls=tuple(sorted(collector.calls)),
            imports=tuple(sorted(set(self.aliases.values()))),
            routes=tuple(sorted(routes)),
            guards=tuple(sorted(guards)),
            import_aliases=dict(self.aliases),
            module_bindings=self.module_bindings,
            module_rebindings=self.module_rebindings,
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
        self.class_bases.append(
            tuple(
                sorted(
                    {
                        base
                        for expression in node.bases
                        for base in _annotation_types(expression, self.aliases)
                    }
                )
            )
        )
        self.class_field_types.append(_class_field_types(node, self.aliases))
        for statement in node.body:
            self.visit(statement)
        self.class_field_types.pop()
        self.class_bases.pop()
        self.class_scope.pop()
        self.scope.pop()


def parse_python_source(
    repository_id: str,
    relative_path: str,
    text: str,
    *,
    module_path: str | None = None,
) -> tuple[PythonDocumentSpan, ...]:
    tree = ast.parse(text, filename=relative_path)
    builder = _FunctionDocumentBuilder(repository_id, relative_path, text, tree, module_path)
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
            raw = read_source_bytes(source_root, relative_path)
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            text = raw.decode(encoding)
            spans.extend(parse_python_source(repository_id, relative_path, text))
        except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
            parse_errors.append(relative_path)
    return PythonRepositoryDocuments(
        documents=tuple(span.document for span in spans),
        spans=tuple(spans),
        parse_error_paths=tuple(parse_errors),
        source_file_count=len(source_files),
    )
