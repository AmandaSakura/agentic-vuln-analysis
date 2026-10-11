"""Explicit, billed source spans for product review; legacy retrieval is unchanged."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal
from typing import TYPE_CHECKING

from pydantic import Field, model_validator

from cv_agent.application.identity import source_digest, validate_relative_path, view_revision
from cv_agent.code_adapters.source_files import SourceReadLimitError, read_source_bytes
from cv_agent.domain.product_result import ScopeAdmission
from cv_agent.domain.types import FrozenModel
from cv_agent.runtime.redaction import redact_public_text

if TYPE_CHECKING:
    from cv_agent.application.source_snapshot import SourceSnapshot


class ContextAdmissionError(ValueError):
    pass


class ReadGrant(FrozenModel):
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def check(self):
        validate_relative_path(self.path)
        if self.start_line > self.end_line:
            raise ValueError("grant span must be an inclusive ordered range")
        return self


class ContextManifest(FrozenModel):
    version: Literal["source-grants-v1"] = "source-grants-v1"
    initial: tuple[ReadGrant, ...] = ()
    extensions: tuple[ReadGrant, ...] = ()


class SourceReadView:
    def __init__(self, root: Path, file_hashes: dict[str, str | None], *, byte_budget: int,
                 snapshot: SourceSnapshot | None = None):
        if root.is_symlink() or type(byte_budget) is not int or byte_budget < 0:
            raise ValueError("Source view requires an explicit root and finite byte budget")
        self.root = root
        self._hashes = dict(file_hashes)
        self._snapshot = snapshot
        if snapshot is not None and (root.resolve(strict=True) != snapshot.root
                                     or self._hashes != snapshot.file_hashes):
            raise ValueError("Source view root and hashes must match its sealed snapshot")
        self.source_digest = source_digest(self._hashes)
        self.byte_budget = byte_budget
        self.used_bytes = 0
        self._grants: list[ReadGrant] = []
        self._receipts: list[ScopeAdmission] = []

    @property
    def receipts(self):
        return tuple(self._receipts)

    @property
    def revision(self):
        return view_revision((g.path, g.start_line, g.end_line) for g in self._grants)

    def _source(self, path):
        if path not in self._hashes or self._hashes[path] is None:
            raise ContextAdmissionError("path is absent from the authorized source snapshot")
        if self._snapshot is None:
            raw = read_source_bytes(self.root, path)
        else:
            original = self._snapshot.files[path]
            try:
                raw = read_source_bytes(self.root, path, max_bytes=len(original.raw or b""))
            except SourceReadLimitError as error:
                raise ContextAdmissionError("source bytes no longer match the authorized snapshot") from error
        if hashlib.sha256(raw).hexdigest() != self._hashes[path]:
            raise ContextAdmissionError("source bytes no longer match the authorized snapshot")
        if self._snapshot is not None:
            entry = self._snapshot.files[path]
            if entry.text is None or entry.error_type is not None:
                raise ContextAdmissionError("source text is unavailable in the authorized snapshot")
            return entry.text.splitlines(keepends=True)
        # Discovery accepted Python encodings; use the same declared encoding.
        import io
        import tokenize
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding).splitlines(keepends=True)

    def _record(self, grant, state, reason, size=0):
        self._receipts.append(ScopeAdmission(admission_id=f"scope/{len(self._receipts)+1}",
            path=grant.path, start_line=grant.start_line, end_line=grant.end_line, reason=redact_public_text(grant.reason),
            state=state, reason_code=reason, delivered_bytes=size))

    def admit(self, grant: ReadGrant) -> None:
        lines = self._source(grant.path)
        if grant.end_line > max(1, len(lines)):
            self._record(grant, "REJECTED", "span_outside_file")
            raise ContextAdmissionError("requested span is outside the source file")
        self._grants.append(grant)
        self._record(grant, "ADMITTED", "explicit_source_grant")

    def covers(self, path: str, start: int, end: int) -> bool:
        return any(g.path == path and g.start_line <= start <= end <= g.end_line for g in self._grants)

    def extend(self, grant: ReadGrant) -> dict:
        """Admit an extension only after its full delivery can be paid for."""
        lines = self._source(grant.path)
        if grant.end_line > max(1, len(lines)):
            self._record(grant, "REJECTED", "span_outside_file")
            raise ContextAdmissionError("requested span is outside the source file")
        revision = view_revision((g.path, g.start_line, g.end_line) for g in [*self._grants, grant])
        payload = {"path": grant.path, "start_line": grant.start_line, "end_line": grant.end_line,
            "text": "".join(lines[grant.start_line-1:grant.end_line]), "source_digest": self.source_digest,
            "view_revision": revision}
        size = len(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False).encode("utf-8"))
        if self.used_bytes + size > self.byte_budget:
            self._record(grant, "REJECTED", "context_budget_exhausted")
            raise ContextAdmissionError("source context byte budget is exhausted")
        self._grants.append(grant)
        self.used_bytes += size
        self._record(grant, "ADMITTED", "complete_extension_delivered", size)
        return payload

    def read(self, path: str, start: int, end: int) -> dict:
        requested = ReadGrant(path=path, start_line=start, end_line=end, reason="explicit span delivery")
        if not self.covers(path, start, end):
            self._record(requested, "REJECTED", "span_not_admitted")
            raise ContextAdmissionError("source span has not been explicitly admitted")
        lines = self._source(path)
        payload = {"path": path, "start_line": start, "end_line": end,
                   "text": "".join(lines[start-1:end]), "source_digest": self.source_digest,
                   "view_revision": self.revision}
        size = len(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False).encode("utf-8"))
        if self.used_bytes + size > self.byte_budget:
            self._record(requested, "REJECTED", "context_budget_exhausted")
            raise ContextAdmissionError("source context byte budget is exhausted")
        self.used_bytes += size
        self._record(requested, "ADMITTED", "complete_span_delivered", size)
        return payload
