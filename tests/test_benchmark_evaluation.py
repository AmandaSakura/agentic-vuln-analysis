from types import SimpleNamespace
import pytest
from cv_agent.evaluation.metrics import metrics, paired, select_cases, wilson, replay_fast_prefix, provider_usage


def test_interleaved_trials_count_received_usage_once_per_stream():
    def event(case, kind, **payload):
        return dict(case_id=case, system='E1', role='scan', event=kind, **payload)
    events = [event('a', 'model_start'),
              event('a', 'model_response_received', summary={'usage': {'total_tokens': 10}}),
              event('b', 'model_start'),
              event('a', 'model_reply', reply={'model_id': 'test', 'usage': {'total_tokens': 10}}),
              event('b', 'model_response_received', summary={'usage': {'total_tokens': 20}}),
              event('b', 'model_invalid_response', summary={'usage': {'total_tokens': 20}})]
    value = provider_usage(events)
    assert value['reported_total_tokens'] == 30
    assert value['requests_without_reported_usage'] == 0


def row(case, system, truth, prediction=None, status='completed'):
    return dict(case_id=case, system=system, ground_truth=truth, predicted_label=prediction,
                status=status, model_calls=2, tool_calls=1, latency_sec=3)


def test_stratification_is_order_independent_and_balanced():
    labels = {f'{c}-{v}-{i}': SimpleNamespace(category=c, vulnerable=v)
              for c in ['x', 'y'] for v in [False, True] for i in range(10)}
    selected = select_cases(labels, 3)
    assert len(selected) == 12
    assert selected == select_cases(dict(reversed(list(labels.items()))), 3)
    for category in ['x', 'y']:
        for vulnerable in [False, True]:
            assert sum(labels[key].category == category and labels[key].vulnerable == vulnerable
                       for key in selected) == 3


def test_failures_remain_in_denominator_but_are_not_binary_errors():
    values = metrics([
        row('1','E1','VULNERABLE','VULNERABLE'),
        row('2','E1','VULNERABLE',status='failed'),
        row('3','E1','SAFE',status='not_run'),
        row('4','E1','SAFE','SAFE'),
    ])
    assert values['strict_recall'] == .5
    assert values['covered_recall'] == 1
    assert values['coverage'] == .5
    assert values['fn'] == values['fp'] == 0
    assert values['conservative_fpr'] == .5
    assert values['provisional']
    assert values['strict_recall_wilson95'] is None


def test_paired_failures_are_unavailable_not_wins():
    rows = [row('1','E2','SAFE',status='failed'), row('1','E3','SAFE','SAFE'),
            row('2','E2','VULNERABLE','ABSTAIN','abstained'),
            row('2','E3','VULNERABLE','VULNERABLE')]
    assert paired(rows,'E2','E3') == dict(left_wins=0,right_wins=1,ties=0,unavailable=1,
                                        completed_label_disagreements=1)


def test_paired_missing_selected_systems_are_unavailable():
    rows = [
        row('1', 'E2', 'SAFE', 'SAFE'),
        row('2', 'E3', 'VULNERABLE', 'VULNERABLE'),
        row('3', 'E2', 'SAFE', 'SAFE'),
        row('3', 'E3', 'SAFE', 'SAFE'),
    ]
    assert paired(rows, 'E2', 'E3') == dict(
        left_wins=0,
        right_wins=0,
        ties=1,
        unavailable=2,
        completed_label_disagreements=0,
    )


def test_empty_denominators_are_unknown():
    assert metrics([])['precision'] is None
    assert wilson(0,0) is None
    lower, upper = wilson(0,3)
    assert lower == pytest.approx(0)
    assert upper > .5


def test_failed_response_tokens_are_counted_once_and_missing_usage_stays_unknown():
    events=[{'event':'model_start'} for _ in range(3)]+[
        {'event':'model_reply','reply':{'model_id':'model','usage':{'total_tokens':10}}},
        {'event':'model_invalid_response','summary':{'usage':{'total_tokens':7}}},
        {'event':'model_error','error':'no choices'},
        {'event':'model_error','error':'timeout'}]
    value=provider_usage(events)
    assert value['requests']==3
    assert value['reported_total_tokens']==17
    assert value['invalid_responses']==1
    assert value['requests_without_reported_usage']==1


def test_received_usage_is_not_double_counted_with_reply_or_invalid_event():
    events = [
        {'event': 'model_start'},
        {'event': 'model_response_received', 'summary': {'usage': {'total_tokens': 30}}},
        {'event': 'model_reply', 'reply': {'model_id': 'offline', 'usage': {'total_tokens': 30}}},
        {'event': 'model_start'},
        {'event': 'model_response_received', 'summary': {'usage': {'total_tokens': 12}}},
        {'event': 'model_invalid_response', 'summary': {'usage': {'total_tokens': 12}}},
        {'event': 'model_error'},
        {'event': 'model_start'},
        {'event': 'model_reply', 'reply': {'model_id': 'legacy', 'usage': {'total_tokens': 7}}},
    ]
    value = provider_usage(events)
    assert value['reported_total_tokens'] == 49
    assert value['requests_without_reported_usage'] == 0
    assert value['responses'] == 2
    assert value['invalid_responses'] == 1


def test_raw_diagnostic_audit_counts_legacy_once_and_prefers_new_journals(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from cv_agent.evaluation.diagnostics.summarize_live_usage import audit_usage
    for name in ('legacy', 'journaled'):
        directory = tmp_path / 'artifacts/transport_raw_diagnostic' / name
        directory.mkdir(parents=True)
        (directory / 'raw_response.json').write_text(json.dumps(dict(
            response_body={'model': 'offline', 'choices': [{}]}, usage={'total_tokens': 10})))
    directory = tmp_path / 'artifacts/transport_raw_diagnostic/journaled'
    (directory / 'metadata.json').write_text('{}')
    (directory / 'events.jsonl').write_text('\n'.join(json.dumps(event) for event in [
        {'event': 'model_start'},
        {'event': 'model_response_received', 'summary': {'usage': {'total_tokens': 10}}},
        {'event': 'model_reply', 'reply': {'model_id': 'offline', 'usage': {'total_tokens': 10}}},
    ]) + '\n')
    totals = audit_usage(tmp_path)['totals']
    assert totals['requests'] == 2
    assert totals['reported_total_tokens'] == 20
    assert totals['requests_without_reported_usage'] == 0


def test_predictions_and_matching_validator_votes_are_reported_separately():
    unsupported = row('1','E1','VULNERABLE','VULNERABLE')
    supported = row('2','E1','SAFE','SAFE')
    supported['verdict'] = {'votes':[{'label':'SAFE','validation_status':'REFUTED'}]}
    values = metrics([unsupported, supported])
    assert values['accuracy'] == 1
    assert values['material_with_matching_validator_vote'] == 1
    assert values['material_without_matching_validator_vote'] == 1
    assert values['vote_validation_status_counts']['REFUTED'] == 1


def test_prefix_replay_counts_only_suffix_tasks_and_compares_full_label():
    votes = [dict(expert=expert,label=label,confidence=.9,validation_status=status,
                  evidence_ids=['tool'],rationale='test',model_calls=3,tool_calls=2)
             for expert,label,status in [('scan','VULNERABLE','CONFIRMED'),
                                         ('taint','VULNERABLE','CONFIRMED'),
                                         ('authz','SAFE','REFUTED')]]
    verdict = dict(label='VULNERABLE',votes=votes,task_executions=[dict(vote=vote) for vote in votes])
    replay = replay_fast_prefix(verdict)
    assert replay['eligible'] and replay['label_equivalent']
    assert replay['counterfactual_saved_model_calls'] == 3
    assert replay['counterfactual_saved_tool_calls'] == 2
    # If authz finished first, the actual runtime never has exactly the fast prefix.
    verdict['task_executions'] = [dict(vote=votes[i]) for i in (2,0,1)]
    assert not replay_fast_prefix(verdict)['eligible']


def test_budget_rejects_before_recording_unmade_request(monkeypatch):
    import sys
    from pathlib import Path
    from cv_agent.evaluation.runners.run_development_benchmark import Budget, BudgetExceeded
    recorded=[]
    budget=Budget(1,60)
    observe=budget.observer(SimpleNamespace(record=recorded.append),'scan')
    observe({'event':'model_start'})
    observe({'event':'model_reply'})
    with pytest.raises(BudgetExceeded):
        observe({'event':'model_start'})
    assert budget.used == 1
    assert len(recorded) == 2


def test_development_runner_serializes_real_verdict_label(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setenv('ANTIGRAVITY_API_KEY','offline')
    from cv_agent.evaluation.runners.run_development_benchmark import run_candidate, Budget, AgentSystemVersion, Journal
    from cv_agent.domain.review import AgenticVerdict
    from cv_agent.domain.chat import ModelUsage
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.domain.types import Candidate, CodeDocument
    verdict = AgenticVerdict(runtime_mode='scripted', label='ABSTAIN', confidence=0.2,
        path='single', rationale='Insufficient evidence', votes=(), model_calls=1, tool_calls=1,
        usage=ModelUsage(), retrieval_context_token_count=0, tool_observation_token_count=0,
        context_token_count=0)
    monkeypatch.setattr(AgenticPipeline,'run',lambda *args:verdict)
    candidate=Candidate(candidate_id='case',case_id='case',repository_id='repo',path='file.py',line=1,query='')
    index=RepositoryIndex([CodeDocument(repository_id='repo',path='file.py',text='def f(): return 1')])
    result=run_candidate(index, candidate, AgentSystemVersion.E1_LOCAL_SINGLE,
                         Journal(tmp_path/'events.jsonl'), Budget(8,60))
    assert result['status']=='abstained'
    assert result['predicted_label']=='ABSTAIN'
    assert result['verdict']==verdict.model_dump(mode='json')


def test_real_pipeline_probe_and_collector_keep_matching_counts(tmp_path,monkeypatch):
    from pathlib import Path
    import json
    monkeypatch.setenv('ANTIGRAVITY_API_KEY','offline')
    from cv_agent.evaluation.runners.run_development_benchmark import run_candidate, Budget, Journal, AgentSystemVersion
    from cv_agent.code_adapters.python import parse_python_source
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.domain.types import Candidate
    from cv_agent.runtime.model import OpenAICompatibleChatModel
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    documents=[span.document for span in parse_python_source('test','entry.py',
        "def entry(request):\n    return eval(request.args['x'])\n")]
    path=documents[0].path
    calls=[]
    def complete(self,messages,tools):
        calls.append(1)
        if len(calls)==1:
            return ModelReply(model_id='offline-transport',tool_calls=(ModelToolCall(
                call_id='probe',name='probe_python_eval',arguments={'source_path':path}),))
        observation=json.loads(messages[-1].content)
        assert observation['validation_status']=='CONFIRMED'
        return ModelReply(model_id='offline-transport',content=json.dumps(dict(expert='scan',
            label='VULNERABLE',confidence=.9,validation_status='CONFIRMED',
            evidence_ids=[observation['citation_id']],rationale='Two input witnesses reached eval.')))
    monkeypatch.setattr(OpenAICompatibleChatModel,'_complete',complete)
    journal=Journal(tmp_path/'events.jsonl')
    result=run_candidate(RepositoryIndex(documents),Candidate(candidate_id='one',case_id='one',
        repository_id='test',path=path,line=1,query='eval request'),
        AgentSystemVersion.E3_GRAPH_SINGLE,journal,Budget(8,60))
    assert result['status']=='completed'
    assert result['model_calls']==result['verdict']['model_calls']==2
    assert result['tool_calls']==result['verdict']['tool_calls']==1
    assert result['verdict']['votes'][0]['validation_status']=='CONFIRMED'
    events=[json.loads(line) for line in journal.path.read_text().splitlines()]
    assert next(event for event in events if event['event']=='tool_start')['candidate_path']==path
