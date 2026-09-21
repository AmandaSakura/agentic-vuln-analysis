from __future__ import annotations

import hashlib
import json
import io
import re
import subprocess
import tokenize
from pathlib import Path

from .python_ast import parse_python_source
from .python_heldout_pair_config import (
    PythonHeldoutPair,
    PythonHeldoutPairCase,
    is_supported_heldout_source_path,
)
from .retrieval import RepositoryIndex
from .source_files import read_source_bytes
from .types import Candidate, CodeDocument

SPAN_RE = re.compile(r"^(.+)::(.+)@([0-9]+)-([0-9]+)(?:#[0-9]+-[0-9]+)?$")
MAX_FALLBACK_SOURCE_BYTES = 64_000


def git_commit(checkout: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


def require_clean_checkout(checkout: Path, expected_commit: str) -> None:
    if git_commit(checkout) != expected_commit:
        raise ValueError("Held-out pair checkout commit changed")
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    if result.stdout.strip():
        raise ValueError("Held-out pair checkout is not clean")


def build_package_index(
    root: Path,
    pair: PythonHeldoutPair,
    case: PythonHeldoutPairCase,
) -> tuple[RepositoryIndex, dict[str, str]]:
    checkout = root / case.checkout
    source_root = checkout / pair.source_root
    if not source_root.is_dir():
        raise FileNotFoundError(source_root)
    documents: list[CodeDocument] = []
    source_sha256: dict[str, str] = {}
    excluded = set(pair.exclude_path_parts) | {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "vendor",
        "build",
        "dist",
    }
    for path in sorted(item for item in source_root.rglob("*") if item.is_file()):
        relative_parts = path.relative_to(checkout).parts
        if set(relative_parts) & excluded:
            continue
        relative = path.relative_to(checkout).as_posix()
        if not is_supported_heldout_source_path(relative):
            continue
        try:
            raw = read_source_bytes(checkout, relative)
            if not relative.endswith(".py") and len(raw) > MAX_FALLBACK_SOURCE_BYTES:
                continue
            source_sha256[relative] = hashlib.sha256(raw).hexdigest()
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            text = raw.decode(encoding)
        except (SyntaxError, UnicodeError, LookupError, OSError, ValueError):
            continue
        if relative.endswith(".py"):
            module_path = None
            if pair.python_import_root is not None:
                import_root = checkout / pair.python_import_root
                if path.is_relative_to(import_root):
                    module_path = path.relative_to(import_root).as_posix()
            try:
                spans = parse_python_source(case.case_id, relative, text, module_path=module_path)
            except SyntaxError:
                continue
            documents.extend(span.document for span in spans)
            language = "python"
            adapter_tier = "ast"
            symbol = "module"
        else:
            language = "text"
            adapter_tier = "fallback"
            symbol = "file"
        documents.append(
            CodeDocument(
                repository_id=case.case_id,
                path=f"{relative}::<{symbol}>@1-{max(1, len(text.splitlines()))}",
                text=text,
                language=language,
                adapter_tier=adapter_tier,
            )
        )
    if not documents:
        raise ValueError("No Python documents indexed for held-out pair case")
    return RepositoryIndex(documents), source_sha256


def document_symbol(document_path: str) -> str:
    match = SPAN_RE.match(document_path)
    if not match:
        raise ValueError(f"Unsupported document path: {document_path}")
    return match.group(2)


def _span(document_path: str) -> tuple[int, int]:
    match = SPAN_RE.match(document_path)
    if not match:
        raise ValueError(f"Unsupported document path: {document_path}")
    return int(match.group(3)), int(match.group(4))


def _span_size(document_path: str) -> int:
    start, end = _span(document_path)
    return end - start


def _contains_line(document_path: str, line: int) -> bool:
    start, end = _span(document_path)
    return start <= line <= end


def select_candidate_document(
    index: RepositoryIndex,
    file_path: str,
    line_hint: int,
    *,
    preferred_symbol: str | None = None,
) -> CodeDocument:
    same_file = [
        document
        for document in index.documents.values()
        if document.path.startswith(f"{file_path}::")
    ]
    if not same_file:
        raise ValueError(f"Held-out candidate file was not indexed: {file_path}")
    if preferred_symbol is not None:
        matching_symbol = [
            document for document in same_file
            if document_symbol(document.path) == preferred_symbol
        ]
        if matching_symbol:
            return min(matching_symbol, key=lambda document: (_span_size(document.path), document.path))
    containing = [document for document in same_file if _contains_line(document.path, line_hint)]
    if containing:
        return min(
            containing,
            key=lambda document: (
                document.path.endswith("::<module>@1-999999"),
                _span_size(document.path),
                document.path,
            ),
        )
    return min(same_file, key=lambda document: (abs(_span(document.path)[0] - line_hint), document.path))


def model_visible_analysis_scope(pair: PythonHeldoutPair) -> str:
    entry = pair.entry_point
    critical = pair.critical_operation
    conditions = ""
    if pair.input_parameters or pair.entry_boolean_arguments:
        conditions = (
            f" Declared externally supplied entry parameters: {json.dumps(pair.input_parameters)}."
            f" Scenario entry boolean arguments: {json.dumps(pair.entry_boolean_arguments, sort_keys=True)}."
            " Conclusions apply only to this scenario; these declarations are assumptions, not validation witnesses."
        )
    return (
        "Assess only this exact source snapshot and candidate span. "
        "Use the candidate.path and retrieved_code.path values as the only exact "
        "tool-readable paths. "
        f"Declared entry code marker: {entry['code']}. "
        f"Scoped operation code marker: {critical['code']}. "
        "Use repository evidence for checks, transformations and data/control flow; "
        "do not infer the answer from case identity or commit ordering."
    ) + conditions


def build_pair_input(
    root: Path,
    pair: PythonHeldoutPair,
    case: PythonHeldoutPairCase,
    *,
    preferred_symbol: str | None = None,
) -> tuple[RepositoryIndex, Candidate, dict[str, str]]:
    index, source_sha256 = build_package_index(root, pair, case)
    if case.file_path not in source_sha256:
        raise ValueError(f"Held-out candidate source was not hashed: {case.file_path}")
    entry = select_candidate_document(
        index,
        case.file_path,
        case.line_hint,
        preferred_symbol=preferred_symbol,
    )
    start, _ = _span(entry.path)
    candidate = Candidate(
        candidate_id=case.case_id,
        case_id=case.case_id,
        repository_id=case.case_id,
        path=entry.path,
        line=start,
        query=f"{pair.vulnerability_title} {pair.source_scope} {pair.analysis_scope}",
        analysis_scope=model_visible_analysis_scope(pair),
        input_parameters=pair.input_parameters,
        entry_boolean_arguments=pair.entry_boolean_arguments,
    )
    return index, candidate, source_sha256


def case_identity(
    root: Path,
    pair: PythonHeldoutPair,
    case: PythonHeldoutPairCase,
    source_sha256: dict[str, str],
) -> dict:
    checkout = root / case.checkout
    return {
        "case_id": case.case_id,
        "pair_id": pair.pair_id,
        "entry_id": pair.entry_id,
        "revision_role": case.revision_role,
        "commit": git_commit(checkout),
        "configured_commit": case.commit,
        "checkout": case.checkout,
        "source_root": pair.source_root,
        "python_import_root": pair.python_import_root,
        "file_path": case.file_path,
        "entry_file_sha256": source_sha256[case.file_path],
        "source_sha256": source_sha256,
    }
