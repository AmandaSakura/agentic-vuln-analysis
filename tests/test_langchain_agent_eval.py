import importlib
import sys
from pathlib import Path

import pytest



def test_neutral_candidate_and_bound_evidence(tmp_path, monkeypatch):
    mod = importlib.import_module('cv_agent.evaluation.runners.run_langchain_pair_eval')
    source = tmp_path / 'prompt.py'
    source.write_text('class PromptTemplate:\n    def from_template(template):\n        return template\n')
    case = dict(case_id='template_case_01', file_path='prompt.py',
                entry_symbol='PromptTemplate.from_template', commit='private-commit')
    index, candidate = mod.build_input(tmp_path, case)
    assert 'private-commit' not in candidate.model_dump_json()
    assert str(tmp_path) not in candidate.model_dump_json()
    monkeypatch.setattr(mod, 'check_checkout', lambda *args: None)
    subject = mod.candidate_subject(index, candidate)
    tool = mod.evidence_tool(tmp_path, case, index, candidate, {'benign': {'status': 'BENIGN_OK'}}, 'CONFIRMED')
    scope = mod.ToolExecutionScope(frozenset(index.documents), 4096,
                                   candidate_path=candidate.path, subject=subject)
    result = tool.handler(mod.PairInput(fixture_id='template_traversal'), scope)
    assert result.validation_status == 'CONFIRMED'
    assert result.subject == subject
    scope.subject = subject.model_copy(update={'candidate_id': 'different'})
    assert tool.handler(mod.PairInput(fixture_id='template_traversal'), scope).status == 'blocked'
    scope.subject = subject
    source.write_text(source.read_text() + '# changed\n')
    with pytest.raises(ValueError, match='Source changed'):
        tool.handler(mod.PairInput(fixture_id='template_traversal'), scope)


def test_unknown_fixture_is_rejected():
    mod = importlib.import_module('cv_agent.evaluation.runners.run_langchain_pair_eval')
    with pytest.raises(ValueError):
        mod.PairInput(fixture_id='arbitrary-execution')


@pytest.mark.parametrize('status,label', [('CONFIRMED', 'VULNERABLE'), ('REFUTED', 'SAFE')])
def test_fixture_through_agent_pipeline(tmp_path, monkeypatch, status, label):
    import json
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    from cv_agent.runtime.model import ScriptedChatModel
    mod = importlib.import_module('cv_agent.evaluation.runners.run_langchain_pair_eval')
    (tmp_path / 'prompt.py').write_text('class PromptTemplate:\n    def from_template(template):\n        return template\n')
    case = dict(case_id='template_case_01', file_path='prompt.py', entry_symbol='PromptTemplate.from_template')
    index, candidate = mod.build_input(tmp_path, case)
    monkeypatch.setattr(mod, 'check_checkout', lambda *args: None)
    fixture = mod.evidence_tool(tmp_path, case, index, candidate, {}, status)
    registered = tuple(t for t in mod.full_agent_tools(index) if t.name != fixture.name) + (fixture,)
    model = ScriptedChatModel([
        ModelReply(model_id='offline', tool_calls=(ModelToolCall(call_id='probe', name='run_fixture_test', arguments={'fixture_id': 'template_traversal'}),)),
        ModelReply(model_id='offline', content=json.dumps(dict(expert='scan', label=label, confidence=1,
                   validation_status=status, evidence_ids=['scan/tool:1'], rationale='Bounded traversal evidence.'))),
    ])
    verdict = AgenticPipeline(index=index, system=mod.AgentSystemVersion.E1_LOCAL_SINGLE,
                             models={'scan': model}, tools=ToolRegistry(registered, max_output_bytes=8192)).run(candidate)
    assert verdict.label == label
    assert verdict.votes[0].validation_status == status
    prompt = model.requests[0][0][1].content
    assert candidate.analysis_scope in prompt
    assert 'applies only to these traversal hypotheses, not general safety' in prompt


def test_real_pair_entry_is_located():
    mod = importlib.import_module('cv_agent.evaluation.runners.run_langchain_pair_eval')
    import json
    config = json.loads((mod.project_root / 'configs/experiments/langchain_pair_eval.json').read_text())
    for case in config['detector_cases']:
        checkout = mod.project_root / config['runner_private_checkouts'][case['case_id']]
        if not checkout.exists():
            pytest.skip('Optional real checkout missing')
        index, candidate = mod.build_input(checkout, case)
        assert 'PromptTemplate.from_template' in index.documents[candidate.path].defines
