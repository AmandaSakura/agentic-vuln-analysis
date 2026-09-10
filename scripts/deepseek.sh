#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
environment_file="${CV_AGENT_DEEPSEEK_ENV_FILE:-${project_dir}/.env.deepseek}"

if [[ ! -f "${environment_file}" ]]; then
    echo "DeepSeek environment file not found: ${environment_file}" >&2
    echo "Copy .env.deepseek.example to .env.deepseek and fill CV_AGENT_MODEL_API_KEY." >&2
    exit 2
fi

set -a
# This file is local and Git-ignored because it contains the API key.
source "${environment_file}"
set +a

if [[ -z "${CV_AGENT_MODEL_API_KEY:-}" ]]; then
    echo "CV_AGENT_MODEL_API_KEY is empty in ${environment_file}." >&2
    exit 2
fi

cd "${project_dir}"
exec uv run cv-agent "$@"
