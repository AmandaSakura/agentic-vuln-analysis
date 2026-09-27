import json

import pytest

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelUsage
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from test_agentic_workflow import _models, _pipeline


def point_model(*, probabilities=None, confidence=0.1, choices=None):
    probabilities = probabilities or {}
    choices = choices or {}
    def respond(messages, tools):
        payload = json.loads(messages[0].content)
        assert set(payload['questions']) == {'scan', 'taint', 'authz'}
        assert 'route' not in payload['questions']
        defaults = {'scan': 'run_static_check', 'taint': 'trace_dataflow',
                    'authz': 'compare_route_and_service_guard'}
        answers = {}
        for role, question in payload['questions'].items():
            chosen = choices.get(role, defaults[role])
            p = probabilities.get(role, 0.95)
            answers[role] = dict(type='choice', choice=chosen, confidence=confidence,
                probabilities={key: p if key == chosen else (1-p)/(len(question['criteria'])-1)
                               for key in question['criteria']})
        return ModelReply(model_id='offline-jev-v2', content=json.dumps(answers),
                          usage=ModelUsage(input_tokens=20, output_tokens=3, total_tokens=23))
    return ScriptedChatModel([respond])


def run_points(router, mode='active'):
    models = _models()
    base, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models)
    pipeline = AgenticPipeline(index=base.index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models=models, tools=base.tools, routing_model=router, routing_mode=mode)
    return pipeline.run(candidate), models


def test_uncertain_taint_does_not_discard_scan_and_authz_decisions():
    result, models = run_points(point_model(probabilities={'taint': 0.6}))
    assert result.planner is None
    assert models['planner'].requests == []
    assert [task.expert for task in result.routing.plan.subtasks] == ['scan', 'authz']
    assert [(item.vote.expert, item.task_id) for item in result.task_executions] == [
        ('scan', 'r1'), ('taint', None), ('authz', 'r2')]
    assert result.routing.decisions['scan'].applied is True
    assert result.routing.decisions['taint'].action == 'expert_react'
    assert result.routing.decisions['taint'].applied is False
    assert result.model_calls == 7
    assert len(result.votes) == 3


def test_selected_probability_is_not_provider_confidence():
    result, _ = run_points(point_model(confidence=0.01))
    assert result.planner is None
    assert result.routing.decisions['scan'].selected_probability == 0.95
    assert result.routing.decisions['scan'].provider_confidence == 0.01
    assert result.routing.decisions['scan'].applied is True
    assert result.routing.spec_version == 2
    assert len(result.routing.state_digest) == 64


def test_shadow_keeps_proposal_but_preserves_baseline_planner_inputs_and_budget():
    baseline_models = _models()
    base, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, baseline_models)
    baseline = base.run(candidate)
    result, models = run_points(point_model(), mode='shadow')
    assert result.routing.proposed_plan is not None
    assert result.routing.plan is None
    assert all(not item.applied for item in result.routing.decisions.values())
    assert models['planner'].requests == baseline_models['planner'].requests
    for role in ('scan', 'taint', 'authz'):
        assert models[role].requests == baseline_models[role].requests
    assert result.label == baseline.label
    assert result.model_calls == baseline.model_calls + 1


def test_off_makes_no_judge_call_or_source_read():
    router = ScriptedChatModel([])
    result, models = run_points(router, mode='off')
    assert router.requests == []
    assert result.routing.model_calls == result.routing.tool_calls == 0
    assert result.routing.observation is None
    assert result.routing.mode == 'off'
    assert result.model_calls == 8
    assert result.tool_calls == 4


def test_unknown_option_defers_only_that_expert():
    result, _ = run_points(point_model(choices={'taint': 'unknown'}))
    assert result.planner is None
    assert result.routing.decisions['taint'].reason == 'escape_option'
    assert result.routing.decisions['scan'].applied is True


def test_all_uncertain_uses_existing_planner_without_extra_votes():
    result, models = run_points(point_model(probabilities={'scan': 0.6, 'taint': 0.6, 'authz': 0.6}))
    assert len(models['planner'].requests) == 2
    assert result.routing.plan is None
    assert all(item.action == 'llm_planner' and not item.applied for item in result.routing.decisions.values())
    assert result.model_calls == 9
    assert len(result.votes) == 3


@pytest.mark.parametrize('taint_probability,taint_confidence', [(0.82, 0.73), (0.79, 0.68)])
def test_historical_v1_answer_policy_replay_retains_only_clear_choices(taint_probability, taint_confidence):
    # Recorded V1 answer distributions, not a fresh evaluation of V2 questions.
    from cv_agent.agents.routing import decide_validator
    from cv_agent.runtime.jev import ChoiceAnswer
    scan = decide_validator('scan', ChoiceAnswer(type='choice', choice='validate_permission_mode',
        confidence=0.99, probabilities={'validate_permission_mode': 1.0, 'unknown': 0.0}), 0.85)
    taint = decide_validator('taint', ChoiceAnswer(type='choice', choice='trace_dataflow',
        confidence=taint_confidence,
        probabilities={'trace_dataflow': taint_probability, 'unknown': 1 - taint_probability}), 0.85)
    assert scan.accepted is True
    assert taint.accepted is False
    assert scan.applied is False  # Replay never claims that a tool actually ran.


def test_partial_fixture_plan_escalates_instead_of_losing_dependency_evidence():
    from cv_agent.agents.routing import route_plan
    from test_agentic_workflow import _complete_tool_registry
    base, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, _models())
    tools = _complete_tool_registry(base.index)
    state = base._retrieve({'candidate': candidate})
    result = route_plan(model=point_model(choices={'scan': 'run_fixture_test', 'taint': 'unknown'}),
        index=base.index, candidate=candidate, evidence=state['evidence'], tools=tools,
        system_spec=base.system_spec, min_probability=0.85)
    assert result.plan is None
    assert 'dependencies' in result.escalation_reason
    assert all(not decision.applied for decision in result.decisions.values())


def test_partial_command_plan_cannot_bypass_mandatory_taint_check():
    from cv_agent.agents.routing import route_plan
    from test_agentic_workflow import _complete_tool_registry
    base, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, _models(),
        source='def get_cmd(value):\n    return subprocess.Popen(value, shell=True)\n')
    tools = _complete_tool_registry(base.index)
    state = base._retrieve({'candidate': candidate})
    result = route_plan(model=point_model(choices={'scan': 'inspect_command_construction', 'taint': 'unknown'}),
        index=base.index, candidate=candidate, evidence=state['evidence'], tools=tools,
        system_spec=base.system_spec, min_probability=0.85)
    assert result.plan is None
    assert 'taint inspect_command_construction' in result.escalation_reason
    assert result.proposed_plan is not None
    assert result.decisions['scan'].accepted is True
    assert result.decisions['scan'].applied is False
