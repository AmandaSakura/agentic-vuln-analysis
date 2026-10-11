"""One fresh owned fixture through the real CLI main with rejecting transport spies."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "artifacts/design_review_repair_20260930/transport_guard"


def main():
    if OUTPUT.exists():
        raise FileExistsError("Preserve the completed guarded run")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cv-agent-owned-transport-") as directory:
        source = Path(directory)
        (source / "entry.py").write_text('import os\nraise RuntimeError("target must not import")\n'
            'def declared_mode(path):\n    os.chmod(path, 0o600)\n')
        completed = subprocess.run([sys.executable,
            "audit/design_review_20260930/offline_cli_guard.py", "review", str(source),
            "--output", str(OUTPUT)], cwd=ROOT, capture_output=True, text=True, timeout=30,
            env={"PATH": os.environ["PATH"], "PYTHONPATH": "src"})
    assert completed.returncode == 0, completed.stderr
    counts = json.loads(completed.stderr)["offline_transport_audit"]
    assert counts == {"http_attempts": 0, "socket_attempts": 0, "live_gate_attempts": 0}
    path = ROOT / "audit/design_review_20260930/transport-guard.json"
    path.write_text(json.dumps({"schema_version": "offline-transport-guard-v1", "passed": True,
        "entrypoint": "cv_agent.cli:main", "counts": counts,
        "source_import_control": "module-level exception was never triggered",
        "model_credentials": "not supplied", "exit_code": completed.returncode,
        "result_path": str((OUTPUT/"result.json").relative_to(ROOT))}, indent=2) + "\n")
    (OUTPUT/".private/transport-audit.json").write_text(json.dumps(counts) + "\n")
    print(json.dumps({"passed": True, **counts}))


if __name__ == "__main__":
    main()
