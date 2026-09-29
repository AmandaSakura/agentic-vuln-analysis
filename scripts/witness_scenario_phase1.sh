#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
set -a
source .env.experiments
set +a
export CV_AGENT_PROVIDER=deepseek
export DEEPSEEK_MODEL=deepseek-flash
export PYTHONUNBUFFERED=1

# Completed once: 90428b956f2b44e885c6e4461958dab5, 32 requests, 191177 reported tokens.
# uv run --no-sync python -m cv_agent.evaluation.runners.run_witness_scenario_matrix --live
