import json

import pytest

from cv_agent.agents.routing import UNKNOWN, route_plan
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelUsage
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel, OpenAICompatibleChatModel
from test_agentic_workflow import _models, _pipeline, _index_and_candidate, _complete_tool_registry


def router_model(*, confidence=0.95, probability=0.95, deep=False, overrides=None):
    def respond(messages, tools):
        assert not tools
        payload = json.loads(messages[0].content)
        selections = dict(scan='run_static_check',
                          taint='trace_dataflow', authz='compare_route_and_service_guard')
        if deep:
            selections = {role: UNKNOWN for role in selections}
        selections.update(overrides or {})
        answers = {}
        for name, question in payload['questions'].items():
            selected = selections[name]
            options = question['criteria']
            answers[name] = dict(type='choice', choice=selected, confidence=confidence,
                probabilities={key: probability if key == selected else (1 - probability) / (len(options) - 1) for key in options})
        return ModelReply(model_id='scripted-jev', content=json.dumps(answers),
                          usage=ModelUsage(input_tokens=20, output_tokens=3, total_tokens=23))
    return ScriptedChatModel([respond])


def routed_pipeline(models, router):
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models)
    return AgenticPipeline(index=pipeline.index, system=AgentSystemVersion.E4_GRAPH_MULTI,
                           models=models, tools=pipeline.tools, routing_model=router), candidate


def test_jev_plan_executes_validators_without_llm_planner_or_extra_votes():
    models = _models()
    for role in ('scan', 'taint', 'authz'):
        models[role]._replies = [reply.model_copy(update={
            'usage': ModelUsage(input_tokens=10, output_tokens=2, total_tokens=12)})
            for reply in models[role]._replies]
    router = router_model()
    pipeline, candidate = routed_pipeline(models, router)
    result = pipeline.run(candidate)
    assert models['planner'].requests == []
    assert result.planner is None
    assert result.routing.plan is not None
    assert result.routing.escalation_reason is None
    assert result.model_calls == 7
    assert result.tool_calls == 4
    assert result.usage.total_tokens == 23 + 6 * 12
    assert result.label == 'ABSTAIN'
    assert [vote.expert for vote in result.votes] == ['scan', 'taint', 'authz']
    assert all(vote.validation_status == 'UNRESOLVED' for vote in result.votes)
    assert len(result.task_executions) == 3
    assert [task.allowed_validator for task in result.routing.plan.subtasks] == [
        'run_static_check', 'trace_dataflow', 'compare_route_and_service_guard']
    assert result.tool_observation_token_count == result.routing.tool_observation_token_count + sum(
        task.vote.tool_observation_token_count for task in result.task_executions)


@pytest.mark.parametrize('probability,deep', [(0.6, False), (0.99, True)])
def test_uncertainty_escalates_to_existing_llm_planner_and_counts_both(probability, deep):
    models = _models()
    pipeline, candidate = routed_pipeline(models, router_model(probability=probability, deep=deep))
    result = pipeline.run(candidate)
    assert len(models['planner'].requests) == 2
    assert result.planner is not None
    assert result.routing.plan is None
    assert 'No validator choice' in result.routing.escalation_reason
    assert result.model_calls == 9
    assert result.tool_calls == 5
    assert result.label == 'ABSTAIN'
    assert result.tool_observation_token_count == (
        result.routing.tool_observation_token_count + result.planner.tool_observation_token_count
        + sum(item.vote.tool_observation_token_count for item in result.task_executions))


def test_oracle_metadata_and_case_identity_do_not_enter_jev_state():
    models = _models()
    router = router_model()
    pipeline, candidate = routed_pipeline(models, router)
    candidate = candidate.model_copy(update={'query': 'ORACLE_SECRET', 'metadata': {'ground_truth': 'ORACLE_SECRET'},
                                            'case_id': 'ORACLE_CASE', 'candidate_id': 'ORACLE_CANDIDATE'})
    pipeline.run(candidate)
    prompt = router.requests[0][0][0].content
    assert 'ORACLE' not in prompt
    assert 'ground_truth' not in prompt
    assert 'eval(command)' in prompt


def test_unavailable_or_safe_choice_fails_without_silent_llm_retry():
    models = _models()
    pipeline, candidate = routed_pipeline(models, router_model(overrides={'scan': 'SAFE'}))
    with pytest.raises(ValueError): pipeline.run(candidate)
    assert models['planner'].requests == []
    assert models['scan'].requests == []


def test_truncated_source_escalates_without_spending_a_jev_request():
    models = _models()
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models, source='x' * 10000)
    state = pipeline._retrieve({'candidate': candidate})
    router = router_model()
    result = route_plan(model=router, index=pipeline.index, candidate=candidate,
                        evidence=state['evidence'], tools=pipeline.tools,
                        system_spec=pipeline.system_spec, min_probability=0.85)
    assert router.requests == []
    assert result.model_calls == 0
    assert result.usage.total_tokens == 0
    assert result.plan is None
    assert 'incomplete' in result.escalation_reason
    assert result.tool_observation_token_count <= 4096


@pytest.mark.parametrize('source_size,read_budget,request_count', [
    (4700, 4096, 0), (4700, 6144, 1), (10000, 6144, 0),
])
@pytest.mark.parametrize('mode', ['active', 'shadow'])
def test_explicit_source_budget_reaches_jev_and_preserves_planner_total(
        source_size, read_budget, request_count, mode):
    from cv_agent.harness import FULL_SYSTEM_HARNESS

    source = 'def handle(request):\n    # ' + 'x' * source_size + '\n    return request\n'
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, _models(), source=source)
    state = pipeline._retrieve({'candidate': candidate})
    router = router_model(deep=True)
    result = route_plan(model=router, index=pipeline.index, candidate=candidate,
                        evidence=state['evidence'], tools=pipeline.tools,
                        system_spec=pipeline.system_spec, min_probability=0.85,
                        mode=mode, max_source_observation_tokens=read_budget)
    assert len(router.requests) == result.model_calls == request_count
    assert result.plan is None
    assert result.tool_observation_token_count <= read_budget
    if request_count:
        assert result.observation.content == source
        assert result.observation.metadata['observation_truncated'] is False
        assert 'No validator choice' in result.escalation_reason
    else:
        assert result.observation.metadata['observation_truncated'] is True
        assert 'incomplete' in result.escalation_reason
    engine = pipeline._engine('planner', {**state, 'candidate': candidate,
        'routing': result, 'planner': None, 'task_executions': [], 'votes': []})
    total = FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    charged = result.tool_observation_token_count if mode == 'active' else 0
    assert engine.scope.max_observation_tokens == total
    assert engine.scope.observed_tokens == charged
    assert engine.scope.remaining_tokens == total - charged


def test_pipeline_applies_jev_plan_with_explicit_source_read_budget():
    source = 'def handle(request):\n    # ' + 'x' * 4700 + '\n    return request\n'
    models = _models()
    base, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models, source=source)
    router = router_model()
    pipeline = AgenticPipeline(index=base.index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models=models, tools=base.tools, routing_model=router, routing_mode='active',
        routing_max_source_observation_tokens=6144)
    state = {'candidate': candidate, 'planner': None, 'task_executions': [], 'votes': [],
             **pipeline._retrieve({'candidate': candidate})}
    planned = pipeline._plan(state)
    assert planned['planner'] is None
    assert planned['routing'].plan is not None
    assert all(item.applied for item in planned['routing'].decisions.values())
    assert len(router.requests) == 1
    assert models['planner'].requests == []


def test_high_confidence_cannot_bypass_existing_permission_plan_policy():
    models = _models()
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models,
                                  source='import os\ndef handle(path):\n    os.chmod(path, 0o777)\n')
    # Include the actual validator capability; the router's static-only plan is insufficient.
    pipeline.tools = _complete_tool_registry(pipeline.index)
    state = pipeline._retrieve({'candidate': candidate})
    result = route_plan(model=router_model(), index=pipeline.index, candidate=candidate,
                        evidence=state['evidence'], tools=pipeline.tools,
                        system_spec=pipeline.system_spec, min_probability=0.85)
    assert result.plan is None
    assert 'validate_permission_mode' in result.escalation_reason


def test_jev_requests_a_fixture_before_dependent_checks():
    models = _models()
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models)
    pipeline.tools = _complete_tool_registry(pipeline.index)
    state = pipeline._retrieve({'candidate': candidate})
    result = route_plan(model=router_model(overrides={'scan': 'run_fixture_test'}), index=pipeline.index,
                        candidate=candidate, evidence=state['evidence'], tools=pipeline.tools,
                        system_spec=pipeline.system_spec, min_probability=0.85)
    assert result.plan is not None
    assert result.plan.subtasks[0].allowed_validator == 'run_fixture_test'
    assert result.plan.subtasks[1].dependencies == result.plan.subtasks[2].dependencies == ('r1',)


def test_routing_cannot_mix_live_and_scripted_provenance():
    live = OpenAICompatibleChatModel(base_url='https://api.typesafe.ai/v1', model='jev-latest',
                                    api_key=None, temperature=0, timeout_seconds=1, protocol='jev-systemone')
    with pytest.raises(ValueError, match='provenance'): routed_pipeline(_models(), live)


def test_routing_rejects_single_expert_and_early_exit_systems():
    index, _ = _index_and_candidate()
    for system in (AgentSystemVersion.E3_GRAPH_SINGLE, AgentSystemVersion.E5_GRAPH_FAST):
        with pytest.raises(ValueError, match='E4'):
            AgenticPipeline(index=index, system=system, models=_models(),
                            tools=_complete_tool_registry(index), routing_model=router_model())
