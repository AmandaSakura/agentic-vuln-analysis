"""Run the hp003 diagnosis 6-cell pilot (hp003_a, hp003_b x E3, E4, E5)."""
from __future__ import annotations

import argparse
from pathlib import Path

from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.evaluation.lifecycle import run_advisory_experiment
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
from cv_agent.evaluation.datasets.composition import load_advisory_config


RUN_ROOT = "artifacts/hp003_diagnosis_2026-09-25/real_runs"


def load_config(root: Path) -> PythonHeldoutPairExperimentConfig:
    return load_advisory_config(root, "configs/profiles/advisory_hp003_diagnosis_v4.json")


def run(root: Path = project_root, output: Path | None = None) -> Path:
    return run_advisory_experiment(
        root, output, load_config(root), run_root=RUN_ROOT, latest_pointer=None,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run hp003 diagnosis pilot")
    parser.add_argument("--output", type=Path, default=None, help="Output directory path")
    args = parser.parse_args()
    run(output=args.output)
