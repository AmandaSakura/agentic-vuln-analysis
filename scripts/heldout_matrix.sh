#!/usr/bin/env bash
set -euo pipefail
cd /home/joker/AAA_NUS_SEM3/cv_agent
set -a
source .env.experiments
set +a
export PYTHONUNBUFFERED=1
uv run --no-sync python scripts/run_python_heldout_pair_matrix.py
