"""Reproduce CVE-2025-65106 / GHSA-6qv9-48xg-fc7f vulnerable/fixed pair in isolated subprocesses."""
from __future__ import annotations

from cv_agent.runtime.paths import PROJECT_ROOT

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

VULN_CHECKOUT = PROJECT_ROOT / "data/diagnostics/langchain-vulnerable"
FIXED_CHECKOUT = PROJECT_ROOT / "data/diagnostics/langchain-fixed"
PYTHON_ENV_BIN = PROJECT_ROOT / "data/diagnostics/langchain-env/bin/python"
PROBE_SCRIPT = PROJECT_ROOT / "scripts/probes/langchain_template_probe.py"

VULN_COMMIT = "b7d1831f9d3560ed4fb45134861eef3f4544eff3"
FIX_COMMIT = "c4b6ba254e1a49ed91f2e268e6484011c540542a"
ADVISORY_ID = "GHSA-6qv9-48xg-fc7f"
CVE_ID = "CVE-2025-65106"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_git_commit(repo_dir: Path) -> str:
    res = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout.strip()


def get_installed_packages(python_bin: Path) -> dict[str, str]:
    res = subprocess.run(
        ["uv", "pip", "list", "--python", str(python_bin)],
        capture_output=True,
        text=True,
        check=True,
    )
    packages: dict[str, str] = {}
    for line in res.stdout.splitlines()[2:]:
        parts = line.split()
        if len(parts) >= 2:
            packages[parts[0]] = parts[1]
    return packages


def require_clean_checkout(checkout: Path) -> None:
    result = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                            cwd=checkout, capture_output=True, text=True, check=True, timeout=30)
    if result.stdout.strip():
        raise ValueError(f"Differential reproduction requires a clean checkout: {checkout}")


def clean_child_env(core_dir: Path) -> dict[str, str]:
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(core_dir),
        "LANGCHAIN_TRACING_V2": "false",
        "LANGCHAIN_TRACING": "false",
        "LANGSMITH_TRACING": "false",
    }
    # Pass necessary system env vars if present, omitting any credentials
    for key in ("HOME", "USER", "TERM", "LANG", "LC_ALL"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def run_single_probe(checkout: Path, scenario: str, template_format: str = "f-string") -> dict:
    core_dir = checkout / "libs/core"
    env = clean_child_env(core_dir)
    cmd = [
        str(PYTHON_ENV_BIN),
        str(PROBE_SCRIPT),
        "--checkout",
        str(checkout),
        "--scenario",
        scenario,
        "--format",
        template_format,
    ]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
    raw_record = {
        "cmd": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    parsed: dict = {}
    if proc.returncode == 0:
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as err:
            parsed = {"status": "PARSE_ERROR", "error": str(err), "raw_stdout": proc.stdout}
    else:
        parsed = {"status": "PROCESS_FAILED", "exit_code": proc.returncode, "stderr": proc.stderr}

    return {"parsed": parsed, "raw": raw_record}


def reproduce_pair(output_dir: Path | None = None) -> dict:
    if not PYTHON_ENV_BIN.exists():
        raise FileNotFoundError(f"Virtualenv python not found: {PYTHON_ENV_BIN}")
    if not VULN_CHECKOUT.is_dir() or not FIXED_CHECKOUT.is_dir():
        raise FileNotFoundError("Checkouts not found under data/diagnostics/")

    vuln_rev = get_git_commit(VULN_CHECKOUT)
    fixed_rev = get_git_commit(FIXED_CHECKOUT)
    if vuln_rev != VULN_COMMIT:
        raise ValueError(f"Vulnerable checkout rev {vuln_rev} != expected {VULN_COMMIT}")
    if fixed_rev != FIX_COMMIT:
        raise ValueError(f"Fixed checkout rev {fixed_rev} != expected {FIX_COMMIT}")
    require_clean_checkout(VULN_CHECKOUT)
    require_clean_checkout(FIXED_CHECKOUT)

    packages = get_installed_packages(PYTHON_ENV_BIN)

    if output_dir is None:
        run_id = uuid4().hex
        output_dir = PROJECT_ROOT / "artifacts/langchain_pair_reproduction" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    scenarios = ["benign", "attribute_access", "dunder_access"]
    matrix: dict[str, dict] = {"vulnerable": {}, "fixed": {}}
    raw_records: list[dict] = []

    for scenario in scenarios:
        # Run vulnerable
        v_res = run_single_probe(VULN_CHECKOUT, scenario)
        matrix["vulnerable"][scenario] = v_res["parsed"]
        raw_records.append({"target": "vulnerable", "scenario": scenario, **v_res["raw"]})

        # Run fixed
        f_res = run_single_probe(FIXED_CHECKOUT, scenario)
        matrix["fixed"][scenario] = f_res["parsed"]
        raw_records.append({"target": "fixed", "scenario": scenario, **f_res["raw"]})

    # Assert differential security invariants
    def benign(result):
        return (result.get("status") == "BENIGN_OK" and result.get("success") is True
                and result.get("output") == "Hello World")

    def blocked(result, variable):
        return (result.get("status") == "BLOCKED" and result.get("error_type") == "ValueError"
                and f"Invalid variable name '{variable}' in f-string template" in result.get("error_message", ""))

    v_benign = benign(matrix["vulnerable"]["benign"])
    f_benign = benign(matrix["fixed"]["benign"])
    v_attr_exploited = (matrix["vulnerable"]["attribute_access"].get("status") == "EXPLOITED"
                        and matrix["vulnerable"]["attribute_access"].get("leaked_secret") is True)
    f_attr_blocked = blocked(matrix["fixed"]["attribute_access"], "marker.secret")
    v_dunder_exploited = (matrix["vulnerable"]["dunder_access"].get("status") == "EXPLOITED"
                          and matrix["vulnerable"]["dunder_access"].get("leaked_dunder") is True)
    f_dunder_blocked = blocked(matrix["fixed"]["dunder_access"], "marker.__class__.__name__")

    verified = all([
        v_benign,
        f_benign,
        v_attr_exploited,
        f_attr_blocked,
        v_dunder_exploited,
        f_dunder_blocked,
    ])

    summary = {
        "verified_differential_security": verified,
        "advisory": ADVISORY_ID,
        "cve": CVE_ID,
        "vulnerable_commit": vuln_rev,
        "fixed_commit": fixed_rev,
        "benign_control_preserved": v_benign and f_benign,
        "attribute_traversal": {
            "vulnerable_status": matrix["vulnerable"]["attribute_access"].get("status"),
            "fixed_status": matrix["fixed"]["attribute_access"].get("status"),
            "differential_holds": v_attr_exploited and f_attr_blocked,
        },
        "dunder_traversal": {
            "vulnerable_status": matrix["vulnerable"]["dunder_access"].get("status"),
            "fixed_status": matrix["fixed"]["dunder_access"].get("status"),
            "differential_holds": v_dunder_exploited and f_dunder_blocked,
        },
    }

    metadata = {
        "started_at": utc_now(),
        "purpose": "CVE-2025-65106 / GHSA-6qv9-48xg-fc7f differential exploit reproduction",
        "advisory": ADVISORY_ID,
        "cve": CVE_ID,
        "vulnerable_commit": vuln_rev,
        "fixed_commit": fixed_rev,
        "environment_packages": packages,
        "python_executable": str(PYTHON_ENV_BIN),
    }

    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output_dir / "results.json").write_text(json.dumps({"summary": summary, "matrix": matrix}, indent=2) + "\n")
    (output_dir / "raw_subprocesses.json").write_text(json.dumps(raw_records, indent=2) + "\n")

    return {"output_dir": str(output_dir), "summary": summary}


def main() -> None:
    res = reproduce_pair()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
