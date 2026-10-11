"""Label-free Python source inventory and deterministic candidate discovery."""
from __future__ import annotations

import hashlib
import io
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cv_agent.code_adapters.python import parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.retrieval.index import FrozenRepositoryIndex
from cv_agent.agents.scanner import StaticScanner
from cv_agent.code_adapters.source_files import read_source_bytes
from cv_agent.domain.types import Candidate, CodeDocument

if TYPE_CHECKING:
    from cv_agent.application.source_snapshot import SourceSnapshot


@dataclass(frozen=True)
class RepositoryDiscovery:
    index: RepositoryIndex
    candidates: tuple[Candidate, ...]
    report: dict


def discover_python_repository(root: Path, repository_id: str, *,
                               exclude_dirs: frozenset[str] = frozenset(),
                               snapshot: SourceSnapshot | None = None) -> RepositoryDiscovery:
    if not root.is_dir():
        raise FileNotFoundError(root)
    documents = []
    source_sha256 = {}
    errors = []
    if snapshot is not None and (root.is_symlink() or root.resolve(strict=True) != snapshot.root):
        raise ValueError('discovery root does not match the authorized snapshot root')
    paths = ([root / relative for relative in sorted(snapshot.files)] if snapshot is not None else
             sorted(path for path in root.rglob('*.py')
                   if not set(path.relative_to(root).parts) &
                   ({'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'}
                    | exclude_dirs)))
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            if snapshot is None:
                raw = read_source_bytes(root, relative)
                source_sha256[relative] = hashlib.sha256(raw).hexdigest()
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                text = raw.decode(encoding)
            else:
                entry = snapshot.files[relative]
                if entry.sha256 is not None:
                    source_sha256[relative] = entry.sha256
                if entry.error_type is not None:
                    errors.append({'path': relative, 'error_type': entry.error_type})
                    continue
                if entry.text is None:
                    raise ValueError('snapshot contains no decoded source text')
                text = entry.text
            spans = parse_python_source(repository_id, relative, text)
        except (SyntaxError, UnicodeError, LookupError, OSError, ValueError) as error:
            errors.append({'path': relative, 'error_type': type(error).__name__})
            continue
        documents.extend(span.document for span in spans)
        # The full module also covers import-time operations and class bodies.
        # Scanner span deduplication assigns function operations to their smallest span.
        documents.append(CodeDocument(
            repository_id=repository_id,
            path=f'{relative}::<module>@1-{max(1, len(text.splitlines()))}',
            text=text, language='python', adapter_tier='ast',
        ))
    scanner = StaticScanner()
    candidates = []
    for candidate in scanner.scan(repository_id, documents):
        operation = f'{repository_id}:{candidate.path.split("::", 1)[0]}:{candidate.line}:{candidate.metadata["rule"]}'
        identity = 'candidate-' + hashlib.sha256(operation.encode()).hexdigest()[:24]
        candidates.append(candidate.model_copy(update={'candidate_id': identity, 'case_id': identity}))
    return RepositoryDiscovery(
        index=(RepositoryIndex(documents) if snapshot is None else FrozenRepositoryIndex(documents)),
        candidates=tuple(candidates),
        report={'repository_id': repository_id, 'source_files': len(paths),
                'parsed_files': len(paths) - len(errors), 'parse_errors': errors,
                'source_sha256': source_sha256, 'documents': len(documents),
                'candidate_count': len(candidates), 'scanner_rules': list(scanner.rule_names),
                'candidate_protocol': 'source_only_static_discovery',
                'discovery_is_validation': False,
                **({'source_snapshot_digest': snapshot.source_digest,
                    'inventory_complete': snapshot.inventory_complete,
                    'resource_reason': snapshot.resource_reason,
                    'enumerated_files': snapshot.enumerated_files,
                    'read_files': snapshot.read_files,
                    'not_read_files': snapshot.not_read_files,
                    'source_bytes': snapshot.source_bytes,
                    'ast_nodes': snapshot.ast_nodes,
                    'excluded_paths': list(snapshot.excluded_paths),
                    'inventory_errors': [{'path': error.path, 'error_type': error.error_type}
                                         for error in snapshot.inventory_errors]} if snapshot is not None else {})},
    )


def select_pilot_candidates(candidates: tuple[Candidate, ...], limit: int) -> tuple[Candidate, ...]:
    if type(limit) is not int or limit < 1:
        raise ValueError('Candidate limit must be a positive integer')
    return candidates[:limit]
