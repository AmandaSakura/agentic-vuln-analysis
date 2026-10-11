"""Seal authorized per-file bytes before parsing; no global atomicity claim."""
from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
from types import MappingProxyType
import tokenize

from cv_agent.application.identity import source_digest, validate_relative_path
from cv_agent.code_adapters.source_files import SourceReadLimitError, read_source_bytes


DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", "vendor", "build", "dist",
})


@dataclass(frozen=True)
class SourceFile:
    path: str
    raw: bytes | None
    sha256: str | None
    encoding: str | None
    text: str | None
    error_type: str | None = None
    error_stage: str | None = None


@dataclass(frozen=True)
class SourceInventoryError:
    path: str
    error_type: str


@dataclass(frozen=True)
class SourceSnapshot:
    root: Path
    files: Mapping[str, SourceFile]
    excluded_dirs: frozenset[str]
    inventory_complete: bool = True
    resource_reason: str | None = None
    source_bytes: int = 0
    ast_nodes: int = 0
    excluded_paths: tuple[str, ...] = ()
    inventory_errors: tuple[SourceInventoryError, ...] = ()

    def __post_init__(self):
        files = dict(self.files)
        for path, entry in files.items():
            validate_relative_path(path)
            if entry.path != path:
                raise ValueError("snapshot file key does not match its source path")
        object.__setattr__(self, "files", MappingProxyType(files))

    @property
    def file_hashes(self) -> dict[str, str | None]:
        return {path: entry.sha256 for path, entry in self.files.items()}

    @property
    def source_digest(self) -> str:
        return source_digest(self.file_hashes)

    @property
    def enumerated_files(self) -> int:
        return len(self.files)

    @property
    def read_files(self) -> int:
        return sum(entry.raw is not None for entry in self.files.values())

    @property
    def not_read_files(self) -> int:
        return self.enumerated_files - self.read_files


def _positive_limit(name: str, value: int | None) -> None:
    if value is not None and (type(value) is not int or value < 1):
        raise ValueError(f"{name} must be an explicit positive integer")


def freeze_source_snapshot(
    root: Path, *, exclude_dirs: frozenset[str] = frozenset(),
    max_files: int | None = None, max_source_bytes: int | None = None,
    max_ast_nodes: int | None = None, cancelled: Callable[[], bool] | None = None,
) -> SourceSnapshot:
    """Read each admitted file once, preserving errors and bounded inventory state.

    This freezes file versions as encountered. It does not assert that an active
    working tree was captured atomically across files. A later live read must
    still check the corresponding byte hash before exposing sealed source.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("snapshot requires a real authorized source root")
    for name, limit in (("max_files", max_files), ("max_source_bytes", max_source_bytes),
                        ("max_ast_nodes", max_ast_nodes)):
        _positive_limit(name, limit)
    root = root.resolve(strict=True)
    excluded = DEFAULT_EXCLUDED_DIRS | frozenset(exclude_dirs)
    files: dict[str, SourceFile] = {}
    total_bytes = total_nodes = 0
    resource_reason = None
    inventory_complete = True
    walk_errors = []
    excluded_paths = []

    if cancelled is not None and cancelled():
        return SourceSnapshot(root=root, files={}, excluded_dirs=excluded,
            inventory_complete=False, resource_reason="CANCELLED")

    def walk_error(error):
        walk_errors.append(error)

    for directory, subdirs, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        excluded_paths.extend((Path(directory) / name).relative_to(root).as_posix()
                              for name in subdirs if name in excluded)
        subdirs[:] = sorted(name for name in subdirs if name not in excluded)
        for name in sorted(names):
            if not name.endswith(".py") or name in excluded:
                continue
            path = (Path(directory) / name).relative_to(root).as_posix()
            if cancelled is not None and cancelled():
                resource_reason = "CANCELLED"
                inventory_complete = False
                break
            if max_files is not None and len(files) >= max_files:
                files[path] = SourceFile(path, None, None, None, None, "SourceFileLimitError", "limit")
                resource_reason = "SOURCE_FILE_LIMIT"
                inventory_complete = False
                break
            limit = None if max_source_bytes is None else max_source_bytes - total_bytes
            try:
                raw = read_source_bytes(root, path, max_bytes=limit)
            except SourceReadLimitError:
                files[path] = SourceFile(path, None, None, None, None, "SourceReadLimitError", "limit")
                resource_reason = "SOURCE_BYTE_LIMIT"
                inventory_complete = False
                break
            except (OSError, ValueError) as error:
                files[path] = SourceFile(path, None, None, None, None, type(error).__name__, "read")
                continue
            total_bytes += len(raw)
            digest = hashlib.sha256(raw).hexdigest()
            try:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                text = raw.decode(encoding)
            except (SyntaxError, UnicodeError, LookupError) as error:
                files[path] = SourceFile(path, raw, digest, None, None, type(error).__name__, "decode")
                continue
            if max_ast_nodes is not None:
                try:
                    tree = ast.parse(text, filename=path)
                except (SyntaxError, ValueError) as error:
                    files[path] = SourceFile(path, raw, digest, encoding, text, type(error).__name__, "parse")
                    continue
                count = 0
                for _ in ast.walk(tree):
                    count += 1
                    if total_nodes + count > max_ast_nodes:
                        break
                if total_nodes + count > max_ast_nodes:
                    files[path] = SourceFile(path, raw, digest, encoding, text, "SourceASTLimitError", "limit")
                    resource_reason = "SOURCE_AST_LIMIT"
                    inventory_complete = False
                    break
                total_nodes += count
            files[path] = SourceFile(path, raw, digest, encoding, text)
        if resource_reason is not None:
            break
    if walk_errors:
        inventory_complete = False
        resource_reason = resource_reason or "SOURCE_INVENTORY_READ_ERROR"
    return SourceSnapshot(root=root, files=files, excluded_dirs=excluded,
        inventory_complete=inventory_complete, resource_reason=resource_reason,
        source_bytes=total_bytes, ast_nodes=total_nodes,
        excluded_paths=tuple(sorted(excluded_paths)),
        inventory_errors=tuple(SourceInventoryError(
            Path(error.filename).relative_to(root).as_posix() if error.filename else ".",
            type(error).__name__) for error in walk_errors))
