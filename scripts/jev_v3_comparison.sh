#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
set -a
source .env.experiments
set +a
export PYTHONUNBUFFERED=1
# Completed 2026-09-27: artifacts/jev_v3_comparison/545892d6559f439a94ef307cc021cac3
# uv run --no-sync python -m cv_agent.evaluation.runners.run_jev_v3_comparison
