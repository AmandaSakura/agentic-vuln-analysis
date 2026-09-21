"""Source-only discovery feeds actual tools and LangGraph, without model HTTP."""
import json

import pytest

from cv_agent.agent_tools import ToolRegistry
from cv_agent.agent_types import ModelReply, ModelToolCall
from cv_agent.agentic_workflow import AgenticPipeline
from cv_agent.harness import AgentSystemVersion
from cv_agent.model_runtime import ScriptedChatModel
from cv_agent.repository_discovery import discover_python_repository
from cv_agent.validation_tools import full_agent_tools


@pytest.mark.parametrize('expression,label,status', [
    ('request.args["value"]', 'VULNERABLE', 'CONFIRMED'),
    ('"1 + 1"', 'ABSTAIN', 'UNRESOLVED'),
])
def test_discovered_candidate_is_bound_to_its_actual_probe(tmp_path, expression, label, status):
    (tmp_path / 'entry.py').write_text(f'def entry(request):\n    return eval({expression})\n')
    discovery = discover_python_repository(tmp_path, 'subject-01')
    candidate, = discovery.candidates
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
