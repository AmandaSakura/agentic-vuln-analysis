"""Install the sealed wheel from cache into a fresh external environment."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--allow-baseline-research-parser", action="store_true")
    args = parser.parse_args()
    release = args.release.resolve()
    wheels = list((release / "dist").glob("*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    wheelhouse = (args.wheelhouse or (release.parent / "local-wheelhouse")).resolve()
    external = Path(tempfile.mkdtemp(prefix="cv-agent-product-install-"))
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "UV_OFFLINE": "1"}
    uv = shutil.which("uv")
    assert uv is not None
    calls = []

    def run(command, *, expected=0):
        result = subprocess.run(command, cwd=external, env=environment, text=True, capture_output=True, timeout=120)
        calls.append({"command": command, "return_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if expected is not None and result.returncode != expected:
            raise RuntimeError(f"Release acceptance command failed: {command[0]} ({result.returncode})")
        return result

    receipt = {"schema": "product-release-install-v1", "wheel": wheel.name,
               "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(), "external_working_directory": str(external),
               "pythonpath": "absent", "credentials": "not inherited", "network": "disabled by uv --offline",
               "calls": calls, "accepted": False}
    try:
        run([uv, "venv", "--no-python-downloads", "--python", sys.executable, str(external / "environment")])
        python = external / "environment" / "bin" / "python"
        cli = external / "environment" / "bin" / "cv-agent"
        dependencies = (wheelhouse / "requirements.lock").read_text()
        requirement_file = release / "install-requirements.lock"
        requirement_file.write_text(dependencies + "cv-agent==0.1.0+recovery.20261001 --hash=sha256:"
                                    + receipt["wheel_sha256"] + "\n")
        run([uv, "pip", "install", "--offline", "--no-index", "--require-hashes", "--python", str(python),
             "--find-links", str(wheelhouse), "--find-links", str(release / "dist"), "-r", str(requirement_file)])
        run([uv, "pip", "check", "--python", str(python)])
        receipt["dependency_wheelhouse_manifest_sha256"] = hashlib.sha256((wheelhouse / "dependency-manifest.json").read_bytes()).hexdigest()
        receipt["install_requirements_sha256"] = hashlib.sha256(requirement_file.read_bytes()).hexdigest()
        probe = run([str(python), "-I", "-c", (
            "import importlib.util as u,json,sys,cv_agent; "
            "print(json.dumps({'package':cv_agent.__file__,'sys_path':sys.path,"
            "'absent':{m:u.find_spec(m) is None for m in ['pytest','langgraph','cv_agent.evaluation','cv_agent.baselines','cv_agent.agents.workflow','cv_agent.runtime.model']}}))")])
        installed = json.loads(probe.stdout)
        assert all(installed["absent"].values())
        assert Path(installed["package"]).is_relative_to(external)
        assert not any("AAA_NUS_SEM3/cv_agent" in path for path in installed["sys_path"])
        receipt["installed_identity"] = installed
        receipt["installed_cli"] = str(cli)
        help_result = run([str(cli), "--help"])
        if not args.allow_baseline_research_parser:
            assert all(name not in help_result.stdout for name in ("agentic-live", "vulngym", "owasp", "readiness"))
        cases = []
        for state, statement in (("SUPPORTED", "os.chmod(path, 0o772)"),
                                 ("REFUTED", "os.chmod(path, 0o750)"),
                                 ("UNKNOWN", "os.chmod(path, mode)")):
            source_root = external / "owned" / str(len(cases))
            source_root.mkdir(parents=True)
            source = "import os\nraise RuntimeError('owned text must not be imported')\ndef inspect(path, mode):\n    " + statement + "\n"
            (source_root / "entry.py").write_text(source)
            doctor = run([str(cli), "doctor", str(source_root)])
            assert json.loads(doctor.stdout)["ready"] is True
            result = run([str(cli), "review", str(source_root), "--output", str(external / "outputs" / str(len(cases)))])
            payload = json.loads(result.stdout)
            assert payload["run_state"] == "COMPLETED"
            assert payload["accounting"]["model_requests"] == 0
            assert payload["accounting"]["physical_executions"] == 0
            states = [finding["property_state"] for finding in payload["findings"]]
            assert states == [state], states
            cases.append({"expected": state, "actual": states, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                          "model_requests": 0, "target_execution": 0, "run_state": payload["run_state"]})
        receipt["owned_controls"] = cases
        receipt["research_parser_allowed_only_for_baseline"] = args.allow_baseline_research_parser
        receipt["accepted"] = True
        print(json.dumps({"accepted": True, "external_environment": str(external), "owned_states": [c["actual"] for c in cases]}, indent=2))
    finally:
        (release / "install-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
