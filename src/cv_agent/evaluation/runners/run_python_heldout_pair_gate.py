"""Run the fixed 10-cell Python held-out advisory pair gate."""
from __future__ import annotations

from pathlib import Path

from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.evaluation.lifecycle import run_advisory_experiment
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
from cv_agent.evaluation.datasets.composition import load_advisory_config


RUN_ROOT = "artifacts/python_heldout_pair_gate_v4"
LATEST_POINTER = "artifacts/python_heldout_pair_gate_v4.json"


def load_config(root: Path) -> PythonHeldoutPairExperimentConfig:
    return load_advisory_config(root, "configs/profiles/advisory_gate_v4.json")


def run(root: Path = project_root, output: Path | None = None) -> Path:
    return run_advisory_experiment(
        root, output, load_config(root), run_root=RUN_ROOT, latest_pointer=LATEST_POINTER,
    )


if __name__ == "__main__":
    run()
