"""Fresh owned source -> real offline CLI -> validated public/private artifacts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

from cv_agent.domain.product_result import ReviewResult


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "artifacts/design_review_repair_20260930/cli_acceptance_final"
CASES = {
    "literal-mode": "import os\ndef declared_mode(path):\n    os.chmod(path, 0o600)\n",
    "unknown-mode": "import os\ndef declared_mode(path, mode):\n    os.chmod(path, mode)\n",
    "zero-candidates": "def owned_constant():\n    return 7\n",
    "parse-error": "def broken(\n",
    "budget-limited": "import os\ndef declared_mode(path):\n    os.chmod(path, 0o600)\n    os.chmod(path, 0o640)\n",
    "missing-source": None,
    "unsupported-language": "def owned_constant():\n    return 7\n",
}


def main():
    if OUTPUT.exists():
        raise FileExistsError("Acceptance output already exists; preserve the completed run")
    OUTPUT.mkdir(parents=True)
    receipts = []
    for name, text in CASES.items():
        with tempfile.TemporaryDirectory(prefix="cv-agent-owned-acceptance-") as directory:
            source = Path(directory) / "source"
            if text is not None:
                source.mkdir()
                (source / "entry.py").write_text(text, encoding="utf-8")
                # Keep only these authored harmless inputs, never target checkouts.
                (OUTPUT / f"{name}-owned-source.txt").write_text(text, encoding="utf-8")
            command = ["uv", "run", "--no-sync", "cv-agent", "review", str(source),
                       "--output", str(OUTPUT / name)]
            if name == "budget-limited": command += ["--observation-bytes", "1800"]
            if name == "unsupported-language": command += ["--language", "rust"]
            started = time.monotonic()
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            wall = time.monotonic() - started
            (OUTPUT / f"{name}.stdout.json").write_text(completed.stdout, encoding="utf-8")
            (OUTPUT / f"{name}.stderr.txt").write_text(completed.stderr, encoding="utf-8")
            if completed.returncode not in {0, 2}:
                raise AssertionError((name, completed.returncode, completed.stderr))
            result = ReviewResult.model_validate_json((OUTPUT/name/"result.json").read_text())
            report = (OUTPUT/name/"report.md").read_text()
            assert f"Run state: {result.run_state}" in report
            assert result.accounting.model_requests == result.accounting.physical_executions == 0
            raw = [json.loads(line) for line in (OUTPUT/name/".private/observations.jsonl").read_text().splitlines()]
            by_producer = {item["producer_id"]: item for item in raw if "observation" in item}
            for evidence in result.evidence_receipts:
                original = by_producer[evidence.producer_id]["observation"]
                assert hashlib.sha256(original["content"].encode()).hexdigest() == evidence.content_sha256
                assert by_producer[evidence.producer_id]["delivered"] == evidence.delivered
            expected = {
                "literal-mode": "COMPLETED", "unknown-mode": "COMPLETED", "zero-candidates": "COMPLETED",
                "parse-error": "PARTIAL", "budget-limited": "PARTIAL", "missing-source": "BLOCKED",
                "unsupported-language": "BLOCKED",
            }[name]
            assert result.run_state == expected, name
            if name == "unknown-mode": assert result.findings[0].property_state == "UNKNOWN"
            if name == "literal-mode": assert result.findings[0].property_state == "REFUTED"
            receipts.append({"case": name, "exit_code": completed.returncode, "run_state": result.run_state,
                "counts": result.counts.model_dump(), "property_states": [f.property_state for f in result.findings],
                "model_requests": 0, "physical_executions": 0, "wall_seconds": wall,
                "result_path": str((OUTPUT/name/"result.json").relative_to(ROOT)),
                "report_path": str((OUTPUT/name/"report.md").relative_to(ROOT)), "passed": True})
    path = ROOT / "audit/design_review_20260930/cli-acceptance.json"
    path.write_text(json.dumps({"schema_version": "owned-cli-acceptance-v1", "cases": receipts,
        "source_provenance": "authored harmless local source; parsed only", "provider_requests": 0,
        "target_executions": 0, "passed": True}, indent=2) + "\n")
    print(json.dumps({"cases": len(receipts), "passed": True, "provider_requests": 0, "target_executions": 0}))


if __name__ == "__main__":
    main()
