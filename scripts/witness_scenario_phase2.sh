#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
set -a
source .env.experiments
set +a
export CV_AGENT_PROVIDER=deepseek
export DEEPSEEK_MODEL=deepseek-flash
export PYTHONUNBUFFERED=1

# Completed once: d735d835e8af451cbd8b260de12e2f4c, 14 requests, 90153 reported tokens.
# uv run --no-sync python -m cv_agent.evaluation.runners.run_witness_scenario_matrix --live --configuration configs/experiments/witness_scenario_phase2.json
