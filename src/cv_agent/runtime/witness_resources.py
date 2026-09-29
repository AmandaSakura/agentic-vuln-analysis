"""Explicit finite resource budgets for disposable witness processes."""

from __future__ import annotations

import sys
from typing import Any

from pydantic import Field, model_validator

from cv_agent.domain.types import FrozenModel


_FIXTURE_VALUES = {
    "name": "fixture_default",
    "cpu_soft_seconds": 5,
    "cpu_hard_seconds": 5,
    "address_space_bytes": 1_500_000_000,
    "file_size_bytes": 1_000_000,
    "open_files": 64,
    "wall_seconds": 12.0,
}


class WitnessResourceProfile(FrozenModel):
    """A named budget; selecting it never establishes candidate evidence.

    The default reproduces the existing fixture limits exactly. New diagnostic
    budgets must leave a gap between CPU soft and hard limits so that CPU
    exhaustion can be observed before the kernel's hard-limit termination.
    Wall time is enforced by the launcher, not by ``resource.setrlimit``.
    """

    name: str = Field(default="fixture_default", strict=True, min_length=1, max_length=80,
                      pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    cpu_soft_seconds: int = Field(default=5, strict=True, gt=0, le=sys.maxsize)
    cpu_hard_seconds: int = Field(default=5, strict=True, gt=0, le=sys.maxsize)
    address_space_bytes: int = Field(default=1_500_000_000, strict=True, gt=0, le=sys.maxsize)
    file_size_bytes: int = Field(default=1_000_000, strict=True, gt=0, le=sys.maxsize)
    open_files: int = Field(default=64, strict=True, gt=0, le=sys.maxsize)
    wall_seconds: float = Field(default=12.0, strict=True, gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def check_budget(self) -> WitnessResourceProfile:
        if self.name == "fixture_default":
            if self.model_dump() != _FIXTURE_VALUES:
                raise ValueError("fixture_default resource limits are fixed")
        elif self.cpu_soft_seconds >= self.cpu_hard_seconds:
            raise ValueError("diagnostic CPU soft limit must be less than its hard limit")
        return self

    @classmethod
    def fixture_default(cls) -> WitnessResourceProfile:
        return cls()

    def _limits(self, resource: Any) -> tuple[tuple[str, int, tuple[int, int]], ...]:
        return (
            ("cpu", resource.RLIMIT_CPU, (self.cpu_soft_seconds, self.cpu_hard_seconds)),
            ("address_space", resource.RLIMIT_AS,
             (self.address_space_bytes, self.address_space_bytes)),
            ("file_size", resource.RLIMIT_FSIZE, (self.file_size_bytes, self.file_size_bytes)),
            ("open_files", resource.RLIMIT_NOFILE, (self.open_files, self.open_files)),
        )

    def apply(self) -> None:
        """Install declared limits only in a disposable child.

        A partial failure is an error, not an enforced-profile result. Revalidate
        the serialized fields because Pydantic's ``model_copy(update=...)`` does
        not validate updates.
        """
        validated = type(self).model_validate(self.model_dump())
        try:
            import resource
        except ImportError as error:
            raise RuntimeError("witness resource limits are unavailable") from error
        failures: list[str] = []
        for name, kind, values in validated._limits(resource):
            try:
                resource.setrlimit(kind, values)
            except (OSError, ValueError, OverflowError) as error:
                failures.append(f"{name}: {type(error).__name__}: {error}")
        if failures:
            raise RuntimeError("could not apply witness resource limits: " + "; ".join(failures))

    def actual_limits(self) -> dict[str, tuple[int, int]]:
        """Read the process's effective kernel limits without changing them."""
        try:
            import resource
        except ImportError as error:
            raise RuntimeError("witness resource limits are unavailable") from error
        return {name: resource.getrlimit(kind) for name, kind, _ in self._limits(resource)}
