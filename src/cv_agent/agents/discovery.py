"""Label-free Python source inventory and deterministic candidate discovery."""
from __future__ import annotations

import hashlib
import io
import tokenize
from dataclasses import dataclass
from pathlib import Path

from cv_agent.code_adapters.python import parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.agents.scanner import StaticScanner
from cv_agent.code_adapters.source_files import read_source_bytes
from cv_agent.domain.types import Candidate, CodeDocument


@dataclass(frozen=True)
class RepositoryDiscovery:
    index: RepositoryIndex
    candidates: tuple[Candidate, ...]
    report: dict


def discover_python_repository(root: Path, repository_id: str) -> RepositoryDiscovery:
    if not root.is_dir():
        raise FileNotFoundError(root)
    documents = []
    source_sha256 = {}
    errors = []
    paths = sorted(path for path in root.rglob('*.py')
                   if not set(path.relative_to(root).parts) &
                   {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'vendor', 'build', 'dist'})
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            raw = read_source_bytes(root, relative)
            source_sha256[relative] = hashlib.sha256(raw).hexdigest()
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            text = raw.decode(encoding)
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
        index=RepositoryIndex(documents), candidates=tuple(candidates),
        report={'repository_id': repository_id, 'source_files': len(paths),
                'parsed_files': len(paths) - len(errors), 'parse_errors': errors,
                'source_sha256': source_sha256, 'documents': len(documents),
                'candidate_count': len(candidates), 'scanner_rules': list(scanner.rule_names),
                'candidate_protocol': 'source_only_static_discovery',
                'discovery_is_validation': False},
    )


def select_pilot_candidates(candidates: tuple[Candidate, ...], limit: int) -> tuple[Candidate, ...]:
    if type(limit) is not int or limit < 1:
        raise ValueError('Candidate limit must be a positive integer')
    return candidates[:limit]
