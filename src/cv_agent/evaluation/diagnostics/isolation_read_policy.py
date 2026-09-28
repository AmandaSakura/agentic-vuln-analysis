"""Explicit, identity-bound leaf read grants for offline diagnostics."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from cv_agent.domain.types import FrozenModel


class IsolationReadGrant(FrozenModel):
    requested_path: Path
    path: Path
    reason: str = Field(min_length=1, max_length=1000)
    file_kind: Literal["regular", "character_device"]
    sha256: str | None = None
    device_major: int | None = None
    device_minor: int | None = None

    @model_validator(mode="after")
    def check_leaf(self) -> IsolationReadGrant:
        if not self.requested_path.is_absolute() or not self.path.is_absolute():
            raise ValueError("read grant paths must be absolute")
        if not self.reason.strip():
            raise ValueError("read grants need an explicit reason")
        if self.file_kind == "regular":
            if (self.sha256 is None or len(self.sha256) != 64
                    or any(c not in "0123456789abcdef" for c in self.sha256)
                    or self.device_major is not None or self.device_minor is not None):
                raise ValueError("regular read grant needs only its full SHA256")
        elif self.sha256 is not None or self.device_major is None or self.device_minor is None:
            raise ValueError("character device grant needs its device identity")
        return self

    @classmethod
    def from_path(cls, path: Path, reason: str) -> IsolationReadGrant:
        requested = path.absolute()
        canonical = requested.resolve(strict=True)
        info = canonical.stat()
        values = {"requested_path": requested, "path": canonical, "reason": reason}
        if stat.S_ISREG(info.st_mode):
            if info.st_size > 8_000_000:
                raise ValueError("read grant file is too large to bind")
            return cls(**values, file_kind="regular",
                       sha256=hashlib.sha256(canonical.read_bytes()).hexdigest())
        if stat.S_ISCHR(info.st_mode):
            import os
            return cls(**values, file_kind="character_device",
                       device_major=os.major(info.st_rdev), device_minor=os.minor(info.st_rdev))
        raise ValueError("read grants must name individual regular files or character devices")

    def is_current(self) -> bool:
        try:
            return self == self.from_path(self.requested_path, self.reason)
        except (OSError, ValueError):
            return False
