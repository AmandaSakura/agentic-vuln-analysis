"""Two snapshot diagnostics may be compared only for identical inputs."""

from __future__ import annotations

import copy

import pytest

from cv_agent.evaluation.diagnostics.compare_bounded_witness_diagnostics import (
    compare_diagnostics,
)


def _record(source_digest: str):
    return {
        "manifest_sha256": source_digest,
        "source_digest": source_digest,
        "result": {
            "status": "UNRESOLVED",
            "gaps": ["preexec_not_verified"],
            "details": {
                "diagnostic_only": True,
                "probe_path": "/tmp/probe/model$(printf NONCE)",
                "control_path": "/tmp/probe/modelCONTROL",
                "probe_nonce": "NONCE",
                "control_nonce": "CONTROL",
                "precondition_sha256": {"probe": {}, "control": {}},
                "reached_popen": True,
                "probe_event": {"kind": "command_event", "event": "subprocess.Popen"},
            },
        },
    }


def test_pair_comparison_keeps_two_sources_and_one_exact_input():
    result = compare_diagnostics(_record("source-a"), _record("source-b"))
    assert result["same_concrete_input"] is True
    assert result["first"]["source_digest"] != result["second"]["source_digest"]
    assert result["input"]["probe_path"] == "/tmp/probe/model$(printf NONCE)"


@pytest.mark.parametrize("changed_field", [
    "probe_path", "control_path", "probe_nonce", "control_nonce", "precondition_sha256",
])
def test_pair_comparison_rejects_any_input_difference(changed_field):
    second = copy.deepcopy(_record("source-b"))
    second["result"]["details"][changed_field] = "different"
    with pytest.raises(ValueError, match="diagnostic inputs differ"):
        compare_diagnostics(_record("source-a"), second)
