"""Run the frozen Python held-out advisory pair matrix."""
from __future__ import annotations

from pathlib import Path

from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
from cv_agent.evaluation.datasets.composition import load_advisory_config


from cv_agent.evaluation.lifecycle import run_advisory_experiment


def load_config(root: Path) -> PythonHeldoutPairExperimentConfig:
    return load_advisory_config(root, "configs/profiles/advisory_matrix_v4.json")


def run(root: Path = project_root, output: Path | None = None) -> Path:
    return run_advisory_experiment(
        root, output, load_config(root),
        run_root="artifacts/python_heldout_pair_matrix_v4", latest_pointer=None,
    )


if __name__ == "__main__":
    run()
