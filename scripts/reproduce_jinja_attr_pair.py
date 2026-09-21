"""Reproduce CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 vulnerable/fixed pair."""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULN_CHECKOUT = PROJECT_ROOT / "data/diagnostics/jinja-vulnerable"
FIXED_CHECKOUT = PROJECT_ROOT / "data/diagnostics/jinja-fixed"
PYTHON_ENV_BIN = PROJECT_ROOT / "data/diagnostics/jinja-env/bin/python"
PROBE_SCRIPT = PROJECT_ROOT / "scripts/jinja_attr_probe.py"
VULN_COMMIT = "877f6e51be8e1765b06d911cfaa9033775f051d1"
FIX_COMMIT = "15206881c006c79667fe5154fe80c01c65410679"
ADVISORY_ID = "GHSA-cpwx-vrp4-4pq7"
CVE_ID = "CVE-2025-27516"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_git_commit(repo_dir: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir,
                            capture_output=True, text=True, check=True)
    return result.stdout.strip()


def require_clean_checkout(checkout: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    if result.stdout.strip():
        raise ValueError(f"Jinja reproduction requires a clean checkout: {checkout}")


def clean_child_env(checkout: Path) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(checkout / "src")}
    for key in ("HOME", "USER", "TERM", "LANG", "LC_ALL"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def run_single_probe(checkout: Path, scenario: str) -> dict:
    proc = subprocess.run(
        [str(PYTHON_ENV_BIN), str(PROBE_SCRIPT), "--checkout", str(checkout), "--scenario", scenario],
        env=clean_child_env(checkout),
        capture_output=True,
        text=True,
        timeout=30,
    )
    raw = {"cmd": proc.args, "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    if proc.returncode != 0:
        return {"parsed": {"status": "PROCESS_FAILED", "exit_code": proc.returncode, "stderr": proc.stderr}, "raw": raw}
    try:
        return {"parsed": json.loads(proc.stdout), "raw": raw}
    except json.JSONDecodeError as error:
        return {"parsed": {"status": "PARSE_ERROR", "error": str(error), "raw_stdout": proc.stdout}, "raw": raw}


def reproduce_pair(output_dir: Path | None = None) -> dict:
    if not PYTHON_ENV_BIN.exists():
        raise FileNotFoundError(f"Virtualenv python not found: {PYTHON_ENV_BIN}")
    if not VULN_CHECKOUT.is_dir() or not FIXED_CHECKOUT.is_dir():
        raise FileNotFoundError("Jinja checkouts not found under data/diagnostics/")
    if get_git_commit(VULN_CHECKOUT) != VULN_COMMIT:
        raise ValueError("Vulnerable Jinja checkout is not pinned to the configured commit")
    if get_git_commit(FIXED_CHECKOUT) != FIX_COMMIT:
        raise ValueError("Fixed Jinja checkout is not pinned to the configured commit")
    require_clean_checkout(VULN_CHECKOUT)
    require_clean_checkout(FIXED_CHECKOUT)

    output_dir = output_dir or PROJECT_ROOT / "artifacts/jinja_pair_reproduction" / uuid4().hex
    output_dir.mkdir(parents=True, exist_ok=True)
    matrix: dict[str, dict] = {"vulnerable": {}, "fixed": {}}
    raw_records: list[dict] = []

    for scenario in ("benign", "attr_format"):
        for target, checkout in (("vulnerable", VULN_CHECKOUT), ("fixed", FIXED_CHECKOUT)):
            result = run_single_probe(checkout, scenario)
            matrix[target][scenario] = result["parsed"]
            raw_records.append({"target": target, "scenario": scenario, **result["raw"]})

    v_benign = matrix["vulnerable"]["benign"].get("status") == "BENIGN_OK"
    f_benign = matrix["fixed"]["benign"].get("status") == "BENIGN_OK"
    v_exploited = (
        matrix["vulnerable"]["attr_format"].get("status") == "EXPLOITED"
        and matrix["vulnerable"]["attr_format"].get("format_exposed") is True
    )
    f_blocked = (
        matrix["fixed"]["attr_format"].get("status") == "BLOCKED"
        and matrix["fixed"]["attr_format"].get("error_type") in {"SecurityError", "UndefinedError", "TemplateRuntimeError", "Undefined"}
        and "format" in matrix["fixed"]["attr_format"].get("error_message", "")
    )
    summary = {
        "verified_differential_security": v_benign and f_benign and v_exploited and f_blocked,
        "advisory": ADVISORY_ID,
        "cve": CVE_ID,
        "vulnerable_commit": VULN_COMMIT,
        "fixed_commit": FIX_COMMIT,
        "benign_control_preserved": v_benign and f_benign,
        "attr_format": {
            "vulnerable_status": matrix["vulnerable"]["attr_format"].get("status"),
            "fixed_status": matrix["fixed"]["attr_format"].get("status"),
            "differential_holds": v_exploited and f_blocked,
        },
    }
    (output_dir / "metadata.json").write_text(json.dumps({
        "started_at": utc_now(),
        "purpose": "CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 differential reproduction",
        "advisory": ADVISORY_ID,
        "cve": CVE_ID,
        "vulnerable_commit": VULN_COMMIT,
        "fixed_commit": FIX_COMMIT,
        "python_executable": str(PYTHON_ENV_BIN),
    }, indent=2) + "\n")
    (output_dir / "results.json").write_text(json.dumps({"summary": summary, "matrix": matrix}, indent=2) + "\n")
    (output_dir / "raw_subprocesses.json").write_text(json.dumps(raw_records, indent=2) + "\n")
    return {"output_dir": str(output_dir), "summary": summary}


def main() -> None:
    print(json.dumps(reproduce_pair(), indent=2))


if __name__ == "__main__":
    main()
