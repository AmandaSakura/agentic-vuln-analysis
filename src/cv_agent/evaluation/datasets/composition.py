"""Explicit dataset/profile composition for advisory experiments.

Frozen historical configurations remain valid standalone inputs. Composition
produces the same existing validated experiment contract, with no implicit
inheritance, environment handling or override precedence.
"""
from pathlib import Path
from typing import Literal

from pydantic import Field

from cv_agent.domain.types import FrozenModel
from cv_agent.harness import AgentSystemVersion
from cv_agent.evaluation.datasets.advisory_config import (
    PythonHeldoutPair, PythonHeldoutPairCell, PythonHeldoutPairExperimentConfig,
    PythonHeldoutPairLimits,
)


class AdvisoryDataset(FrozenModel):
    dataset_role: Literal['paired_heldout_advisory']
    claim_eligible: Literal[False]
    source_manifest: str
    pairs: tuple[PythonHeldoutPair, ...]


class AdvisoryRunProfile(FrozenModel):
    dataset_name: str
    model_config_path: str = Field(alias='model_config')
    systems: tuple[AgentSystemVersion, ...]
    concurrency: Literal[1, 2]
    graph_direction: Literal['forward', 'reverse', 'both'] = 'forward'
    graph_ranking: Literal['lexical', 'distance'] = 'lexical'
    limits: PythonHeldoutPairLimits
    selected_cells: tuple[PythonHeldoutPairCell, ...] = ()
    expected_abstentions: tuple[PythonHeldoutPairCell, ...] = ()


def compose_advisory_config(
    dataset: AdvisoryDataset, profile: AdvisoryRunProfile,
) -> PythonHeldoutPairExperimentConfig:
    return PythonHeldoutPairExperimentConfig.model_validate({
        **dataset.model_dump(mode='json'),
        **profile.model_dump(mode='json', by_alias=True),
    })


def load_advisory_config(root: Path, profile_path: str) -> PythonHeldoutPairExperimentConfig:
    dataset = AdvisoryDataset.model_validate_json(
        (root / "configs/datasets/advisory_pairs_v4.json").read_text()
    )
    profile = AdvisoryRunProfile.model_validate_json((root / profile_path).read_text())
    return compose_advisory_config(dataset, profile)
