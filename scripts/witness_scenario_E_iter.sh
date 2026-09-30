#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
set -a
source .env.experiments
set +a
export CV_AGENT_PROVIDER=deepseek
export DEEPSEEK_MODEL=deepseek-flash
export PYTHONUNBUFFERED=1

# Completed once: 61ccd871658f48988e78ee038816292c, 26 requests, 166482 reported tokens.
# uv run --no-sync python -m cv_agent.evaluation.runners.run_witness_scenario_matrix --live --configuration configs/experiments/witness_scenario_E_iter.json
