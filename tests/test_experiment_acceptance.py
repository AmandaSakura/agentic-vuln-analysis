from copy import deepcopy

import pytest

from cv_agent.domain.evidence import ValidationSubject


def evidence_rows():
    expected = {(case, f'E{system}'): label for case, label in [('one', 'SAFE'), ('two', 'VULNERABLE')]
                for system in range(1, 6)}
    subjects = {case: ValidationSubject(candidate_id=case, repository_id='repo',
                entry_path=case, entry_line=1, source_digest='digest') for case in ('one', 'two')}
    rows = []
    for (case, system), label in expected.items():
        status = 'REFUTED' if label == 'SAFE' else 'CONFIRMED'
        observation = dict(tool='run_fixture_test', status='ok', content='executed bounded fixture',
                           citation_id='tool:1', validation_status=status,
                           subject=subjects[case].model_dump(mode='json'))
        vote = dict(expert='scan', label=label, confidence=.9, validation_status=status,
                    evidence_ids=[f'local:{case}', 'tool:1'], rationale='bounded witness', runtime_mode='live',
                    trace=[dict(step=1, model_id='offline-test',
                                tool_call=dict(call_id='one', name='run_fixture_test', arguments={}),
                                observation=observation)], model_ids=['offline-test'], model_calls=2,
                    tool_calls=1, tool_observation_token_count=20, usage={})
        rows.append(dict(case_id=case, system=system, status='completed', predicted_label=label,
                         ground_truth=label, model_calls=2,
                         verdict=dict(label=label, runtime_mode='live', votes=[vote])))
    summary = dict(usage=dict(requests=20, responses=20, invalid_responses=0,
                              requests_without_reported_usage=0))
    return rows, summary, expected, subjects


def test_acceptance_requires_exact_ten_cells_and_bound_validator_evidence():
    from cv_agent.evaluation.protocols.development import acceptance_issues
    rows, summary, expected, subjects = evidence_rows()
    assert acceptance_issues(rows, summary, expected, subjects) == []
    for mutate in ('unresolved', 'no_trace', 'wrong_subject', 'wrong_label', 'duplicate', 'missing', 'usage'):
        values, totals = deepcopy(rows), deepcopy(summary)
        if mutate == 'unresolved':
            values[0]['verdict']['votes'][0]['validation_status'] = 'UNRESOLVED'
        elif mutate == 'no_trace':
            values[0]['verdict']['votes'][0]['trace'] = []
        elif mutate == 'wrong_subject':
            values[0]['verdict']['votes'][0]['trace'][0]['observation']['subject']['entry_line'] = 2
        elif mutate == 'wrong_label':
            values[0]['predicted_label'] = 'VULNERABLE'
            values[0]['ground_truth'] = 'VULNERABLE'  # Stored truth cannot override frozen labels.
        elif mutate == 'duplicate':
            values[0] = deepcopy(values[1])
        elif mutate == 'missing':
            values.pop()
        else:
            totals['usage']['responses'] = 19
        assert acceptance_issues(values, totals, expected, subjects), mutate


def test_full_gate_rejects_stale_fingerprint_and_changed_protocol(tmp_path, monkeypatch):
    from cv_agent.evaluation.protocols.development import require_development_acceptance
    import json
    directory = tmp_path / 'artifacts/development_benchmark/pilot'
    directory.mkdir(parents=True)
    (tmp_path / 'artifacts/development_acceptance.json').write_text(json.dumps({'run_directory': str(directory)}))
    (directory / 'metadata.json').write_text(json.dumps({'source_fingerprint': 'old'}))
    with pytest.raises(ValueError, match='acceptance.*source'):
        require_development_acceptance(tmp_path, {}, {})


def test_transport_acceptance_does_not_treat_stripped_limit_as_effective():
    from cv_agent.evaluation.protocols.development import transport_issues
    events = [dict(event='model_start', request_id='one'),
              dict(event='model_proxy_diagnostic', request_id='one',
                   diagnostic=dict(diagnosis='upstream_response', output_limit_status='missing'))]
    config = dict(proxy_log_dir='local-logs', max_tokens=1200)
    assert transport_issues(events, config)
    events[1]['diagnostic']['output_limit_status'] = 'matched'
    assert not transport_issues(events, config)
    assert transport_issues(events[:1], config)


def test_verification_batch_rejects_prediction_only_tools_before_live_calls():
    from cv_agent.evaluation.protocols.development import require_verification_capability
    from cv_agent.tools.validation import full_agent_tools
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.domain.types import CodeDocument
    from dataclasses import replace
    index = RepositoryIndex([CodeDocument(repository_id='repo', path='Entry.java',
                            text='public void doPost() {}', language='java', adapter_tier='ast')])
    tools = full_agent_tools(index)
    with pytest.raises(ValueError, match='No model requests'):
        require_verification_capability(tools)
    fixture = next(tool for tool in tools if tool.name == 'run_fixture_test')
    require_verification_capability([replace(fixture, available=True)])


def test_full_gate_revalidates_evidence_not_the_stored_pass_boolean(tmp_path):
    import json
    from cv_agent.evaluation.protocols.development import require_development_acceptance
    from cv_agent.runtime.admission import source_fingerprint
    rows, summary, expected, subjects = evidence_rows()
    directory = tmp_path / 'artifacts/development_benchmark/pilot'
    directory.mkdir(parents=True)
    (tmp_path / 'configs').mkdir()
    config = dict(model_config='configs/model.json', entry_method='doPost', concurrency=2)
    (tmp_path / config['model_config']).write_text('{}')
    manifest = dict(systems=[f'E{i}' for i in range(1, 6)], pilot_case_ids=['one', 'two'],
                    labels={'one': {'vulnerable': False}, 'two': {'vulnerable': True}},
                    identity={'datasets': {'repo': 'commit'}})
    metadata = dict(source_fingerprint=source_fingerprint(tmp_path), model_config={},
                    config=dict(entry_method='doPost', systems=manifest['systems'], case_ids=['one', 'two'], concurrency=2),
                    identity=manifest['identity'],
                    subjects={case: subject.model_dump(mode='json') for case, subject in subjects.items()})
    (directory / 'metadata.json').write_text(json.dumps(metadata))
    (tmp_path / 'artifacts/development_acceptance.json').write_text(json.dumps({'run_directory': str(directory)}))
    events = []
    for i, row in enumerate(rows):
        for suffix in ('a', 'b'):
            request_id = str(i) + suffix
            events.extend([dict(event='model_start', request_id=request_id),
                           dict(event='model_reply', request_id=request_id,
                                reply=dict(model_id='offline', usage={'total_tokens': 10}))])
        events.append(dict(event='trial_result', result=row))
    events.append(dict(event='run_end', interrupted=False))
    path = directory / 'events.jsonl'
    path.write_text('\n'.join(json.dumps(event) for event in events))
    assert require_development_acceptance(tmp_path, config, manifest) == directory
    (directory / 'acceptance.json').write_text('{"passed": true}')
    rows[0]['verdict']['votes'][0]['validation_status'] = 'UNRESOLVED'
    path.write_text('\n'.join(json.dumps(event) for event in events))
    with pytest.raises(ValueError, match='validator evidence'):
        require_development_acceptance(tmp_path, config, manifest)
