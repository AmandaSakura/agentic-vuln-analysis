"""Source-only discovery feeds actual tools and LangGraph, without model HTTP."""
import json

import pytest

from cv_agent.tools.registry import ToolRegistry
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.agents.discovery import discover_python_repository
from cv_agent.tools.validation import full_agent_tools


@pytest.mark.parametrize('expression,inputs,label,status', [
    ('request.args["value"]', (), 'ABSTAIN', 'UNRESOLVED'),
    ('request.args["value"]', ('request',), 'VULNERABLE', 'CONFIRMED'),
    ('"1 + 1"', (), 'ABSTAIN', 'UNRESOLVED'),
    ('"1 + 1"', ('request',), 'ABSTAIN', 'UNRESOLVED'),
])
def test_discovered_candidate_is_bound_to_its_actual_probe(tmp_path, expression, inputs, label, status):
    (tmp_path / 'entry.py').write_text(f'def entry(request):\n    return eval({expression})\n')
    discovery = discover_python_repository(tmp_path, 'subject-01')
    candidate, = discovery.candidates
    # C1: a source-only discovery does not establish externally controlled
    # request fields. The positive scenario declares that premise explicitly.
    assert candidate.input_parameters == ()
    candidate = candidate.model_copy(update={'input_parameters': inputs})
    model = ScriptedChatModel([
        ModelReply(model_id='offline', tool_calls=(ModelToolCall(
            call_id='probe', name='probe_python_eval', arguments={'source_path': candidate.path}),)),
        ModelReply(model_id='offline', content=json.dumps({
            'expert': 'scan', 'label': label, 'confidence': 0.9,
            'validation_status': status, 'evidence_ids': ['scan/tool:1'],
            'rationale': 'The bounded candidate probe supplies the validation status.',
        })),
    ])
    verdict = AgenticPipeline(index=discovery.index, system=AgentSystemVersion.E3_GRAPH_SINGLE,
        models={'scan': model}, tools=ToolRegistry(full_agent_tools(discovery.index), max_output_bytes=8192)).run(candidate)
    assert verdict.label == label
    assert verdict.votes[0].validation_status.value == status
    assert verdict.votes[0].trace[0].observation.subject.candidate_id == candidate.candidate_id
    assert candidate.analysis_scope in model.requests[0][0][1].content


@pytest.mark.parametrize('rule,source', [
    ('database-operation', 'def entry(cursor, value):\n    return cursor.execute(value)\n'),
    ('template-operation', 'def entry(renderer, value):\n    return renderer.render(value)\n'),
    ('authorization-boundary', '@router.get("/record")\ndef entry():\n    return record\n'),
    ('dynamic-attribute-access', 'def entry(record, field):\n    return getattr(record, field)\n'),
    ('process-control', 'def entry():\n    return os._exit(0)\n'),
])
def test_discovered_property_requires_proof_beyond_reading_source(tmp_path, rule, source):
    from cv_agent.agents.evidence_policy import validate_conclusion
    from cv_agent.domain.evidence import ReActStep
    from cv_agent.domain.review import AgentExpertConclusion
    from cv_agent.tools.identity import candidate_subject
    from cv_agent.tools.registry import ToolExecutionScope

    (tmp_path / 'entry.py').write_text(source)
    discovery = discover_python_repository(tmp_path, 'neutral')
    candidate, = discovery.candidates
    subject = candidate_subject(discovery.index, candidate)
    registry = ToolRegistry(full_agent_tools(discovery.index), max_output_bytes=8192)
    call = ModelToolCall(call_id='read', name='read_span', arguments={'path': candidate.path})
    scope = ToolExecutionScope(frozenset(discovery.index.documents), 8192, candidate_path=candidate.path, subject=subject)
    observation = registry.invoke(call, allowed=('read_span',), scope=scope).model_copy(update={'citation_id': 'read'})
    assert observation.status == 'ok'
    step = ReActStep(step=1, model_id='offline', tool_call=call, observation=observation)
    vote = AgentExpertConclusion(expert='scan', label='VULNERABLE', confidence=.9,
        validation_status='UNRESOLVED', evidence_ids=('read',), supporting_observation_ids=('read',),
        rationale='Source contains a suspicious operation.')
    with pytest.raises(ValueError, match='declared candidate property'):
        validate_conclusion(vote, [step], frozenset(), subject=subject)
    assert candidate.property_id == subject.property_id == rule
    validate_conclusion(vote.model_copy(update={'label': 'ABSTAIN'}), [step], frozenset(), subject=subject)
