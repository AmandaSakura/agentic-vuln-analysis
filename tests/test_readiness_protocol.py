import json
from pathlib import Path

from cv_agent.evaluation.protocols.readiness import assess_run_readiness


def _write_run(root: Path, *, acceptance=True, claim=True, role="final-test", fixtures=False, usage=None):
    root.mkdir(parents=True)
    (root / "acceptance.json").write_text(json.dumps({
        "passed": acceptance,
        "issues": [] if acceptance else ["offline failure"],
    }))
    fixture_registry = {
        "hp001_a": [{"tool": "run_fixture_test", "case_id": "hp001_a"}]
    } if fixtures else {}
    (root / "metadata.json").write_text(json.dumps({
        "claim_eligible": claim,
        "config": {"claim_eligible": claim, "dataset_role": role},
        "uses_trusted_fixtures": fixtures,
        "validation_fixture_registry": fixture_registry,
    }))
    (root / "summary.json").write_text(json.dumps({
        "claim_eligible": claim,
        "dataset_role": role,
    }))
    clean_usage = {
        "requests": 4,
        "responses": 4,
        "duplicate_request_starts": 0,
        "invalid_responses": 0,
        "orphaned_responses": 0,
        "requests_without_reported_usage": 0,
        "usage_conflicts": 0,
    }
    clean_usage.update(usage or {})
    (root / "usage.json").write_text(json.dumps(clean_usage))


def test_readiness_distinguishes_operational_pass_from_claim_ready(tmp_path):
    run = tmp_path / "development-run"
    _write_run(run, claim=False, role="paired_heldout_advisory", fixtures=True)

    result = assess_run_readiness(run)

    assert result["operational_ready"] is True
    assert result["claim_ready"] is False
    assert result["uses_trusted_fixtures"] is True
    assert result["trusted_fixture_case_count"] == 1
    assert any("claim_eligible" in item for item in result["blockers"])
    assert any("dataset_role" in item for item in result["blockers"])
    assert any("trusted fixtures" in item for item in result["blockers"])


def test_readiness_accepts_clean_final_claim_artifact(tmp_path):
    run = tmp_path / "final-run"
    _write_run(run)

    result = assess_run_readiness(run)

    assert result["operational_ready"] is True
    assert result["claim_ready"] is True
    assert result["blockers"] == []


def test_readiness_blocks_failed_or_inconsistent_run_for_operations_and_claim(tmp_path):
    run = tmp_path / "bad-run"
    _write_run(run, acceptance=False, usage={"responses": 3, "invalid_responses": 1})

    result = assess_run_readiness(run)

    assert result["operational_ready"] is False
    assert result["claim_ready"] is False
    assert "acceptance did not pass" in result["blockers"]
    assert any("responses" in item for item in result["blockers"])
    assert any("invalid_responses" in item for item in result["blockers"])


def test_readiness_infers_fixture_usage_from_legacy_results_without_metadata(tmp_path):
    run = tmp_path / "legacy-run"
    _write_run(run, claim=False, role="paired_heldout_advisory", fixtures=False)
    (run / "results.json").write_text(json.dumps([
        {
            "verdict": {
                "votes": [
                    {
                        "evidence_ids": ["fixture:hp001_a"],
                        "trace": [{"observation": {"tool": "run_fixture_test"}}],
                    }
                ]
            }
        }
    ]))

    result = assess_run_readiness(run)

    assert result["uses_trusted_fixtures"] is True
    assert any("trusted fixture usage inferred" in item for item in result["warnings"])
    assert any("trusted fixtures" in item for item in result["blockers"])


def test_readiness_cli_can_gate_operational_and_claim_readiness(tmp_path, monkeypatch, capsys):
    from cv_agent import cli

    run = tmp_path / "development-run"
    _write_run(run, claim=False, role="paired_heldout_advisory", fixtures=True)

    monkeypatch.setattr("sys.argv", ["cv-agent", "readiness", str(run)])
    assert cli.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["operational_ready"] is True
    assert payload["claim_ready"] is False
    assert payload["command_policy"]["command"] == "readiness"

    monkeypatch.setattr("sys.argv", ["cv-agent", "readiness", str(run), "--require-operational"])
    assert cli.main() == 0
    capsys.readouterr()

    monkeypatch.setattr("sys.argv", ["cv-agent", "readiness", str(run), "--require-claim"])
    assert cli.main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert any("trusted fixtures" in item for item in payload["blockers"])
