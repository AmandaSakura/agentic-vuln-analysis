"""Verify and install using only the actual extracted download bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path)
    parser.add_argument("--receipt-name", default="extracted-bundle-acceptance.json")
    args = parser.parse_args()
    release = args.release.resolve()
    sealed = json.loads((release / "bundle-receipt.json").read_text())
    archive = release / sealed["archive"]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == sealed["sha256"]
    external = Path(tempfile.mkdtemp(prefix="cv-agent-extracted-bundle-"))
    with zipfile.ZipFile(archive) as bundle:
        assert not any(Path(name).is_absolute() or ".." in Path(name).parts for name in bundle.namelist())
        bundle.extractall(external)
    hashes = []
    for line in (external / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        assert hashlib.sha256((external / relative).read_bytes()).hexdigest() == expected
        hashes.append(relative)
    uv = shutil.which("uv")
    assert uv
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "UV_OFFLINE": "1"}
    calls = []

    def run(command):
        result = subprocess.run(command, cwd=external, env=environment, text=True, capture_output=True, timeout=120)
        calls.append({"command": command, "return_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == 0, result.stdout + result.stderr
        return result

    receipt = {"schema": "extracted-download-bundle-check-v1", "archive_sha256": sealed["sha256"],
               "external_directory": str(external), "verified_file_count": len(hashes), "calls": calls,
               "model_requests": 0, "target_executions": 0, "network": False, "accepted": False}
    try:
        run([uv, "venv", "--offline", "--python", "python3.13", "--no-python-downloads", "product-env"])
        python = external / "product-env" / "bin" / "python"
        cli = external / "product-env" / "bin" / "cv-agent"
        run([uv, "pip", "install", "--offline", "--no-index", "--require-hashes", "--python", str(python),
             "--find-links", "local-wheelhouse", "--find-links", "dist", "-r", "install-requirements.lock"])
        run([uv, "pip", "check", "--python", str(python)])
        run([str(cli), "doctor", "demos/case-00"])
        review = json.loads(run([str(cli), "review", "demos/case-00", "--output", "run-00",
                                "--profile", "product_triage_v2", "--summary-bytes", "1"]).stdout)
        assert review["findings"][0]["property_state"] == "SUPPORTED"
        assert json.loads(run([str(cli), "verify", "run-00"]).stdout)["valid"] is True
        view = json.loads(run([str(cli), "view", "run-00", "--candidate-id", review["findings"][0]["candidate_id"],
                               "--source-root", "demos/case-00"]).stdout)
        assert view["source"] == "os.chmod(path, 0o772)"
        receipt["accepted"] = True
        print(json.dumps({"accepted": True, "verified_files": len(hashes), "external_directory": str(external)}, indent=2))
    finally:
        (release / args.receipt_name).write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
