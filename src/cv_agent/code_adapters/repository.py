"""Repository traversal and dispatch to the supported source adapters."""
from __future__ import annotations

from collections import Counter
from pathlib import Path, PurePosixPath

from ..python_ast import parse_python_source
from ..source_files import read_source_bytes
from .fallback import FALLBACK_SUFFIXES, _fallback_language, parse_fallback_source
from .go import parse_go_source
from .javascript import (
    JAVASCRIPT_SUFFIXES,
    TYPESCRIPT_SUFFIXES,
    parse_javascript_source,
    parse_typescript_source,
)
from .models import CodeRepositoryDocuments, ParsedSource, SourceDocumentSpan


SKIPPED_DIRECTORIES = frozenset(
    {".git", ".venv", "node_modules", "vendor", "dist", "build"}
)


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
