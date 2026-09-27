#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
set -a
source .env.experiments
set +a
export PYTHONUNBUFFERED=1
# Completed 2026-09-27: a2e6a57f88794517ad82ff190535577d (4096 source budget, no Jev requests).
# uv run --no-sync python -m cv_agent.evaluation.runners.run_hp003_jev_active
# Completed 2026-09-27: 6b16f651a0904ca194f1af29c86b7366 (6144 source budget, two Jev requests).
# uv run --no-sync python -m cv_agent.evaluation.runners.run_hp003_jev_active
