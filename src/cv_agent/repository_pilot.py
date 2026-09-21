"""Strict detector-only configuration for bounded repository experiments."""
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .harness import AgentSystemVersion
from .heldout_manifest import repository_key
from .types import FrozenModel


class RepositorySubject(FrozenModel):
    repository_id: Annotated[str, Field(pattern=r'^subject-[0-9]+$')]
    repository_url: str
    commit: Annotated[str, Field(pattern=r'^[a-f0-9]{40}$')]
    checkout: str
    source_prefix: str

    @model_validator(mode='after')
    def validate_source(self):
        repository_key(self.repository_url)
        for value in (self.checkout, self.source_prefix):
            path = PurePosixPath(value)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Source paths must remain within their configured root')
        return self


class RepositoryPilotConfig(FrozenModel):
    dataset_role: Literal['development_pilot', 'heldout_pilot']
    model_config_path: str
    systems: tuple[AgentSystemVersion, ...]
    candidate_limit_per_subject: Annotated[int, Field(ge=1)]
    max_requests: Annotated[int, Field(ge=1)]
    max_seconds: Annotated[int, Field(ge=1)]
    subjects: tuple[RepositorySubject, ...]

    @model_validator(mode='after')
    def validate_pilot(self):
        cells = len(self.subjects) * len(self.systems) * self.candidate_limit_per_subject
        if not self.subjects or not self.systems or cells > 10:
            raise ValueError('Pilot must contain between 1 and 10 candidate/system cells')
        if len(set(self.systems)) != len(self.systems):
            raise ValueError('Duplicate systems')
        if len({subject.repository_id for subject in self.subjects}) != len(self.subjects):
            raise ValueError('Duplicate repository identity')
        if len({(repository_key(s.repository_url), s.commit) for s in self.subjects}) != len(self.subjects):
            raise ValueError('Duplicate repository/commit subject')
        return self


def validate_heldout_membership(config: RepositoryPilotConfig, frozen_inputs: dict) -> None:
    admitted = {(repository_key(s['repository_url']), s['commit']) for s in frozen_inputs['subjects']}
    if any((repository_key(s.repository_url), s.commit) not in admitted for s in config.subjects):
        raise ValueError('Subject is not in the frozen independent input manifest')
