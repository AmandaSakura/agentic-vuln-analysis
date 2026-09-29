"""Reviewed behavior snapshots; C1/C5 replace the former weak-vote diagnostics.

The fixture case binding adds an optional plan field. Scoped planner patches may
use zero extra tool calls. Retrieval admission adds a source-bound audit field
to verdicts; these reviewed schema and smoke changes are in the baseline.

K4 adds two post-admission observation counters only. C5 still requires the
original evidence, labels and quorum behavior; removing these two new fields
must restore the complete old snapshots and schema without updating the fixture.
"""
import hashlib
import json
from pathlib import Path

import pytest

from cv_agent.domain.chat import ChatMessage, ModelReply
from cv_agent.domain.evidence import ValidationSubject, ToolObservation
from cv_agent.domain.review import AgentExpertConclusion, ValidationPlan, AgenticVerdict
from cv_agent.evaluation.scripted import run_agentic_scripted_eval
from cv_agent.evaluation.smoke import run_agentic_smoke
from cv_agent.baselines.synthetic_experiment import run_synthetic_experiment


BASELINE_PATH = Path(__file__).parent / "fixtures/refactor_baseline.json"
BASELINE = json.loads(BASELINE_PATH.read_text())
ACCOUNTING_FIELDS = {
    "material_votes_sharing_validator_observation": "Material Votes Sharing Validator Observation",
    "independent_validator_observations": "Independent Validator Observations",
}


def test_original_behavior_baseline_remains_unchanged():
    assert hashlib.sha256(BASELINE_PATH.read_bytes()).hexdigest() == (
        "2e342d8a3be8ce5f29702bc902046f3f6d607550df8711e8b2653f2d6a6d974e"
    )


@pytest.mark.parametrize("name, run", [
    ("agentic_eval", run_agentic_scripted_eval),
    ("agentic_smoke", run_agentic_smoke),
    ("synthetic", run_synthetic_experiment),
])
def test_scripted_end_to_end_behavior_matches_original(name, run):
    actual = json.loads(json.dumps(run()))
    if name == "agentic_smoke":
        verdict = actual["verdict"]
        assert set(verdict) == set(BASELINE[name]["verdict"]) | set(ACCOUNTING_FIELDS)
        # A single final scan V/C survives, but cannot form a material quorum.
        assert verdict["label"] == "ABSTAIN"
        assert verdict.pop("material_votes_sharing_validator_observation") == 0
        assert verdict.pop("independent_validator_observations") == 1
    assert actual == BASELINE[name]


SCHEMAS = {model.__name__: model for model in (
    ChatMessage, ModelReply, ValidationSubject, ToolObservation,
    AgentExpertConclusion, ValidationPlan, AgenticVerdict,
)}


@pytest.mark.parametrize("name", BASELINE["schemas"])
def test_model_contract_matches_original(name):
    actual = SCHEMAS[name].model_json_schema()
    if name == "AgenticVerdict":
        assert set(actual["properties"]) == (
            set(BASELINE["schemas"][name]["properties"]) | set(ACCOUNTING_FIELDS)
        )
        for field, title in ACCOUNTING_FIELDS.items():
            assert actual["properties"].pop(field) == {
                "default": 0, "minimum": 0, "title": title, "type": "integer",
            }
    assert actual == BASELINE["schemas"][name]
