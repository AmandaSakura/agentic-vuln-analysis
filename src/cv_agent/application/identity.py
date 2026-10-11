"""Product identities are versioned separately from the legacy index digest."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath
from pathlib import Path
import importlib.metadata
import platform


def canonical_digest(algorithm: str, payload) -> str:
    encoded = json.dumps({"algorithm": algorithm, "payload": payload}, ensure_ascii=False,
                         sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_relative_path(path: str) -> None:
    parsed = PurePosixPath(path)
    if (not path or parsed.is_absolute() or "\\" in path or ".." in parsed.parts
            or path != parsed.as_posix()):
        raise ValueError("identity path must be a canonical relative source path")


def source_digest(file_hashes: Mapping[str, str | None]) -> str:
    for path, digest in file_hashes.items():
        validate_relative_path(path)
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Source file digest must be SHA-256 or explicitly unavailable")
    return canonical_digest("source-bytes-v1", sorted(file_hashes.items()))


def view_revision(spans: Iterable[tuple[str, int, int]]) -> str:
    normalized = set()
    for path, start, end in spans:
        validate_relative_path(path)
        if type(start) is not int or type(end) is not int or not 1 <= start <= end:
            raise ValueError("View span must be an inclusive positive line range")
        normalized.add((path, start, end))
    return canonical_digest("retrieval-view-v1", sorted(normalized))


def execution_digest(approved_environment: Mapping) -> str:
    """Only explicit trusted manifests; the static product has no execution identity."""
    return canonical_digest("approved-execution-v1", dict(approved_environment))


def analysis_implementation_digest() -> str:
    """Bind analysis code and installed parser/model versions, never evaluation data."""
    package = Path(__file__).resolve().parents[1]
    relative_files = set()
    for directory in ("application", "domain", "code_adapters", "retrieval", "harness", "tools"):
        relative_files.update(path.relative_to(package).as_posix() for path in (package/directory).rglob("*.py"))
    relative_files.update({"agents/discovery.py", "agents/scanner.py", "agents/evidence_policy.py",
        "tools/registry.py", "tools/validation/permissions.py", "tools/validation/commands.py",
        "tools/validation/probes.py", "tools/validation/scope.py"})
    code = [(path, hashlib.sha256((package/path).read_bytes()).hexdigest()) for path in sorted(relative_files)]
    versions = {name: importlib.metadata.version(name) for name in ("pydantic", "tree-sitter")}
    return canonical_digest("product-analysis-implementation-v1", {
        "code": code, "versions": versions, "python": platform.python_version()})
