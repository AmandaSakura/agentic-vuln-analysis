#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
set -a
source .env.experiments
set +a
export PYTHONUNBUFFERED=1
uv run --no-sync python -m cv_agent.evaluation.runners.run_jev_routing_pilot
