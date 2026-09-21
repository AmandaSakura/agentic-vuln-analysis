"""Frozen observable behavior of the pre-refactor scripted systems and contracts."""
import json
from pathlib import Path

import pytest

from cv_agent.domain.chat import ChatMessage, ModelReply
from cv_agent.domain.evidence import ValidationSubject, ToolObservation
from cv_agent.domain.review import AgentExpertConclusion, ValidationPlan, AgenticVerdict
from cv_agent.evaluation.scripted import run_agentic_scripted_eval
from cv_agent.evaluation.smoke import run_agentic_smoke
from cv_agent.baselines.synthetic_experiment import run_synthetic_experiment


BASELINE = json.loads((Path(__file__).parent / "fixtures/refactor_baseline.json").read_text())


@pytest.mark.parametrize("name, run", [
    ("agentic_eval", run_agentic_scripted_eval),
    ("agentic_smoke", run_agentic_smoke),
    ("synthetic", run_synthetic_experiment),
])
def test_scripted_end_to_end_behavior_matches_original(name, run):
    assert json.loads(json.dumps(run())) == BASELINE[name]


SCHEMAS = {model.__name__: model for model in (
    ChatMessage, ModelReply, ValidationSubject, ToolObservation,
    AgentExpertConclusion, ValidationPlan, AgenticVerdict,
)}


@pytest.mark.parametrize("name", BASELINE["schemas"])
def test_model_contract_matches_original(name):
    assert SCHEMAS[name].model_json_schema() == BASELINE["schemas"][name]
