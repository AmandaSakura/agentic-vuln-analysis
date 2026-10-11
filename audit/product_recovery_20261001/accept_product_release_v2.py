"""Exercise final installed v2 CLI, with private evidence and exact local view."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path)
    args = parser.parse_args()
    release = args.release.resolve()
    install = json.loads((release / "install-acceptance.json").read_text())
    assert install["accepted"] is True
    external = Path(install["external_working_directory"])
    cli = Path(install["installed_cli"])
    environment = {"PATH": str(cli.parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
                   "PYTHONNOUSERSITE": "1", "UV_OFFLINE": "1"}
    commands = []

    def run(command, expected=0):
        result = subprocess.run(command, cwd=external, env=environment, text=True, capture_output=True, timeout=120)
        commands.append({"command": command, "return_code": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == expected, result.stdout + result.stderr
        return result

    receipt = {"schema": "product-release-v2-acceptance-v1", "wheel_sha256": install["wheel_sha256"],
               "installed_cli": str(cli), "network": False, "model_requests": 0, "target_executions": 0,
               "software_fixture_controls": True, "human_independent_product_quality": "NOT_MEASURED",
               "commands": commands, "accepted": False}
    try:
        cases = []
        sources = {}
        for index, (state, argument) in enumerate((("SUPPORTED", "0o772"), ("REFUTED", "0o750"), ("UNKNOWN", "mode"))):
            source_root = external / "owned-v2" / str(index)
            source_root.mkdir(parents=True, exist_ok=False)
            source = ("import os\ndef inspect(path, mode):\n    os.chmod(path, " + argument +
                      ")\nraise RuntimeError('owned text must not be imported')\n")
            (source_root / "entry.py").write_text(source)
            sources[state] = source_root
            output = external / "outputs-v2" / str(index)
            response = run([str(cli), "review", str(source_root), "--output", str(output),
                            "--profile", "product_triage_v2"])
            result = json.loads(response.stdout)
            assert result["schema_version"] == "product-review-v2"
            assert result["run_state"] == "COMPLETED"
            assert result["accounting"]["model_requests"] == result["accounting"]["target_executions"] == 0
            assert [finding["property_state"] for finding in result["findings"]] == [state]
            assert result["counts"]["analysis_completed"] == result["counts"]["candidate_total"] == 1
            verify = json.loads(run([str(cli), "verify", str(output)]).stdout)
            assert verify["valid"] is True and verify["external_origin_authenticated"] is False
            finding = result["findings"][0]
            view = json.loads(run([str(cli), "view", str(output), "--candidate-id", finding["candidate_id"],
                                  "--source-root", str(source_root)]).stdout)
            assert view["source"] == "os.chmod(path, " + argument + ")"
            assert view["operation_locator"] == finding["operation_locator"]
            assert view["source_digest"] == result["identity"]["source_digest"]
            cases.append({"expected": state, "actual": finding["property_state"],
                          "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                          "local_verified": verify["valid"], "exact_source_view": view["source"],
                          "identity": result["identity"], "counts": result["counts"]})
        summary_output = external / "outputs-v2" / "summary-one"
        small = json.loads(run([str(cli), "review", str(sources["SUPPORTED"]), "--output", str(summary_output),
                               "--profile", "product_triage_v2", "--summary-bytes", "1"]).stdout)
        assert small["findings"][0]["property_state"] == "SUPPORTED"
        assert small["run_state"] == "COMPLETED" and small["counts"]["analysis_completed"] == 1
        assert small["identity"]["semantic_engine_digest"] == cases[0]["identity"]["semantic_engine_digest"]
        assert small["identity"]["delivery_policy_digest"] != cases[0]["identity"]["delivery_policy_digest"]
        share = json.loads((summary_output / "share.json").read_text())
        assert share["verification_availability"] == "NOT_VERIFIABLE"
        assert share["summary_body_bytes"] == 0 and share["omitted_candidates"] == 1 and share["findings"] == []
        assert json.loads(run([str(cli), "verify", str(summary_output)]).stdout)["valid"] is True
        receipt["summary_one"] = {"local_state": "SUPPORTED", "run_state": "COMPLETED", "share": share,
                                  "counts": small["counts"]}
        source_file = sources["SUPPORTED"] / "entry.py"
        original = source_file.read_text()
        source_file.write_text(original + "# owned source drift control\n")
        drift = run([str(cli), "view", str(summary_output), "--candidate-id", small["findings"][0]["candidate_id"],
                     "--source-root", str(sources["SUPPORTED"])], expected=2)
        assert "SOURCE_DRIFT" in drift.stdout
        source_file.write_text(original)
        corrupted = external / "outputs-v2" / "missing-record"
        shutil.copytree(summary_output, corrupted)
        next((corrupted / ".private" / "evidence").glob("*.json")).unlink()
        assert json.loads(run([str(cli), "verify", str(corrupted)], expected=2).stdout)["valid"] is False
        # Both the console and module entry expose the same product-only CLI.
        help_result = run([str(cli.parent / "python"), "-I", "-m", "cv_agent", "--help"])
        assert all(name not in help_result.stdout for name in ("agentic-live", "vulngym", "owasp", "readiness"))
        run([str(cli), "agentic-live-owasp"], expected=2)
        receipt["owned_controls"] = cases
        receipt["source_drift_rejected"] = receipt["missing_evidence_rejected"] = True
        receipt["accepted"] = True
        print(json.dumps({"accepted": True, "owned_states": [case["actual"] for case in cases],
                          "summary_one_local_supported": True, "verified_exact_views": 3}, indent=2))
    finally:
        (release / "install-v2-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
