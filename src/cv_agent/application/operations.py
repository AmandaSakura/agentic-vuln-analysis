"""Exact operation identities for the explicitly selected v2 static profile.

The legacy scanner and its line-level historical IDs deliberately stay intact.
These AST heuristics propose properties; they do not confirm those properties.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import re
import textwrap

from cv_agent.agents.discovery import RepositoryDiscovery
from cv_agent.agents.scanner import StaticScanner
from cv_agent.application.identity import canonical_digest
from cv_agent.application.source_snapshot import SourceSnapshot
from cv_agent.domain.types import Candidate, CodeDocument


OPERATION_RULE_VERSION = "static-operation-rules-v2"
OPERATION_ID_VERSION = "source-operation-id-v2"


@dataclass(frozen=True)
class OperationLocator:
    source_path: str
    start_line: int
    end_line: int
    start_col_utf8: int
    end_col_utf8: int
    node_kind: str
    rule_version: str
    file_sha256: str
    source_digest: str


def _symbol(node: ast.expr, aliases: dict[str, str]) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.insert(0, node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.insert(0, aliases.get(node.id, node.id))
    return ".".join(parts)


def _rules(node: ast.Call, aliases: dict[str, str], *, route_decorator: bool) -> set[str]:
    symbol = _symbol(node.func, aliases)
    found = set()
    if symbol in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        found.add("dynamic-evaluation")
    if symbol in {"getattr", "setattr", "delattr", "builtins.getattr", "builtins.setattr", "builtins.delattr"}:
        if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            found.add("dynamic-attribute-access")
    if symbol in {"os._exit", "os.kill", "os.killpg", "sys.exit", "signal.raise_signal"}:
        found.add("process-control")
    if symbol in {"os.system", "os.popen"} or symbol in {
        f"subprocess.{name}" for name in
        ("run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput")
    }:
        found.add("command-execution")
    if symbol in {"os.chmod", "posix.chmod"}:
        found.add("permission-mode")
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in {"execute", "executemany", "executescript", "executeQuery", "delete"}:
            found.add("database-operation")
        if node.func.attr in {"format", "format_map", "vformat", "render", "render_async", "from_template"}:
            found.add("template-operation")
        if (route_decorator and node.func.attr in {"get", "post", "put", "patch", "delete", "route", "api_route"}
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            found.add("authorization-boundary")
    if isinstance(node.func, ast.Subscript) and any(
        word in ast.unparse(node.func.value).lower() for word in ("format", "render", "template")
    ):
        found.add("template-operation")
    return found


class _OperationCollector(ast.NodeVisitor):
    def __init__(self):
        self.aliases: dict[str, str] = {}
        self.operations: list[tuple[ast.Call, str]] = []
        self._route_decorators: set[int] = set()

    def visit_Import(self, node: ast.Import):
        for item in node.names:
            self.aliases[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for item in node.names:
                self.aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        self._route_decorators.update(id(item) for item in node.decorator_list if isinstance(item, ast.Call))
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *[d for d in node.args.kw_defaults if d is not None]):
            self.visit(default)
        # Inventory annotation syntax too. These are review leads, not claims
        # that deferred annotations or type bounds are executed at runtime.
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        for parameter in node.type_params:
            self.visit(parameter)
        saved = self.aliases
        self.aliases = dict(saved)
        for statement in node.body:
            self.visit(statement)
        self.aliases = saved

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef):
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for parameter in node.type_params:
            self.visit(parameter)
        saved = self.aliases
        self.aliases = dict(saved)
        for statement in node.body:
            self.visit(statement)
        self.aliases = saved

    def visit_Call(self, node: ast.Call):
        for rule in sorted(_rules(node, self.aliases, route_decorator=id(node) in self._route_decorators)):
            self.operations.append((node, rule))
        self.generic_visit(node)


def registered_calls_on_line(document: CodeDocument, line: int) -> tuple[ast.Call, ...]:
    """Inventory distinct registered operations, not every nested argument call.

    This uses the same syntax/alias rules as discovery. It grants no proof:
    validators still interpret the complete slice and its unresolved effects.
    """
    collector = _OperationCollector()
    collector.aliases.update(document.import_aliases)
    collector.visit(ast.parse(textwrap.dedent(document.text)))
    return tuple(dict.fromkeys(node for node, _ in collector.operations if node.lineno == line))


def _document_bounds(document: CodeDocument) -> tuple[int, int]:
    match = re.search(r"@(\d+)-(\d+)$", document.path)
    if match is None:
        raise ValueError("operation discovery requires original-source document spans")
    return tuple(map(int, match.groups()))


def _validate_discovery(snapshot: SourceSnapshot, discovery: RepositoryDiscovery) -> None:
    expected = {path: entry.sha256 for path, entry in snapshot.files.items() if entry.sha256 is not None}
    if discovery.report.get("source_sha256") != expected:
        raise ValueError("discovery byte hashes do not match the sealed snapshot")
    if discovery.report.get("source_snapshot_digest", snapshot.source_digest) != snapshot.source_digest:
        raise ValueError("discovery identity does not match the sealed snapshot")
    errors = {row["path"] for row in discovery.report["parse_errors"]}
    for path, entry in snapshot.files.items():
        if entry.error_type is not None or path in errors:
            continue
        if entry.text is None:
            raise ValueError("discovery contains unavailable snapshot source")
        lines = entry.text.splitlines(keepends=True)
        documents = [doc for doc in discovery.index.documents.values() if doc.path.split("::", 1)[0] == path]
        if not any("::<module>@" in doc.path and doc.text == entry.text for doc in documents):
            raise ValueError("discovery module text does not match the sealed snapshot")
        for document in documents:
            first, last = _document_bounds(document)
            if document.text != "".join(lines[first - 1:last]):
                raise ValueError("discovery span text does not match the sealed snapshot")


def discover_operations(snapshot: SourceSnapshot, discovery: RepositoryDiscovery) -> tuple[Candidate, ...]:
    """Enumerate full-file AST operations once; slices supply only enclosing context."""
    _validate_discovery(snapshot, discovery)
    candidates = []
    seen = set()
    errors = {row["path"] for row in discovery.report["parse_errors"]}
    repository_id = discovery.report["repository_id"]
    digest = snapshot.source_digest
    for path, entry in sorted(snapshot.files.items()):
        if entry.error_type is not None or path in errors:
            continue
        assert entry.text is not None and entry.sha256 is not None
        tree = ast.parse(entry.text, filename=path)
        collector = _OperationCollector()
        collector.visit(tree)
        documents = [doc for doc in discovery.index.documents.values() if doc.path.split("::", 1)[0] == path]
        for node, rule in collector.operations:
            assert node.end_lineno is not None and node.end_col_offset is not None
            locator = OperationLocator(path, node.lineno, node.end_lineno, node.col_offset, node.end_col_offset,
                type(node).__name__, OPERATION_RULE_VERSION, entry.sha256, digest)
            payload = {"repository_id": repository_id, "rule": rule, **asdict(locator)}
            identity = "operation-" + canonical_digest(OPERATION_ID_VERSION, payload)[:32]
            if identity in seen:
                continue
            seen.add(identity)
            enclosing = [doc for doc in documents
                         if _document_bounds(doc)[0] <= node.lineno <= node.end_lineno <= _document_bounds(doc)[1]]
            if not enclosing:
                raise ValueError("operation has no enclosing sealed source document")
            document = min(enclosing, key=lambda doc: (
                _document_bounds(doc)[1] - _document_bounds(doc)[0], "::<module>@" in doc.path, doc.path))
            snippet = ast.get_source_segment(entry.text, node)
            if snippet is None:
                raise ValueError("operation has no exact sealed source snippet")
            property_id = "chmod-mode-others-write" if rule == "permission-mode" else rule
            candidates.append(Candidate(candidate_id=identity, case_id=identity, repository_id=repository_id,
                path=document.path, line=node.lineno, query=f"{rule} {snippet}",
                analysis_scope=StaticScanner.scopes[rule], property_id=property_id,
                metadata={"rule": rule, "span_relative_line": node.lineno - _document_bounds(document)[0] + 1,
                    "evidence_kind": "static_candidate", "candidate_protocol": OPERATION_ID_VERSION,
                    "operation_locator": asdict(locator), "source_snippet": snippet}))
    return tuple(sorted(candidates, key=lambda candidate: (
        candidate.metadata["operation_locator"]["source_path"], candidate.line,
        candidate.metadata["operation_locator"]["start_col_utf8"],
        candidate.metadata["operation_locator"]["end_line"],
        candidate.metadata["operation_locator"]["end_col_utf8"], candidate.metadata["rule"])))
