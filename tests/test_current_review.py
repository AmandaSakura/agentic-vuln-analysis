"""Behavioral counterexamples from the post-integration project review."""
import json
from pathlib import Path

import pytest

from cv_agent.tools.identity import candidate_subject
from cv_agent.agents.workflow import _bounded_context_prompt
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.tools.analysis.python_probe import probe_python_eval
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate


def index_for(source):
    index = RepositoryIndex(span.document for span in parse_python_source('review', 'entry.py', source))
    path = next(path for path in index.documents if '::entry@' in path)
    return index, path


@pytest.mark.parametrize('source', [
    'def entry(request):\n    return missing(eval(request.args["x"]))\n',
    'def entry(request):\n    eval(request.args["x"])\n    import math as eval\n',
    'def entry(request):\n    eval(request.args["x"])\n    def eval(value):\n        return value\n',
])
def test_unbound_callable_never_produces_an_eval_witness(source):
    index, path = index_for(source)
    result = probe_python_eval(index, frozenset(index.documents), path)
    assert result['status'] == 'UNRESOLVED'
    assert all(item['outcome'] != 'input reached eval' for item in result['attempts'])


def test_supported_nested_call_keeps_argument_eval_witness():
    index, path = index_for('def identity(value):\n    return value\n\ndef entry(request):\n    return identity(eval(request.args["x"]))\n')
    assert probe_python_eval(index, frozenset(index.documents), path)['status'] == 'CONFIRMED'


def test_explicit_scope_reaches_model_without_retrieval_query_or_labels():
    index, path = index_for('def entry(request):\n    return 1\n')
    candidate = Candidate(candidate_id='one', case_id='one', repository_id='review', path=path,
        line=1, query='private retrieval hint', metadata={'label': 'private reference'},
        analysis_scope='Only attribute and dunder traversal; no general safety claim.')
    _, prompt, count = _bounded_context_prompt(candidate, [], token_budget=1000)
    assert json.loads(prompt)['candidate']['analysis_scope'] == candidate.analysis_scope
    assert 'private' not in prompt
    assert count == len(prompt.encode())
    with pytest.raises(ValueError, match='budget'):
        _bounded_context_prompt(candidate, [], token_budget=10)
    other = candidate.model_copy(update={'analysis_scope': 'A different hypothesis'})
    assert candidate_subject(index, candidate) != candidate_subject(index, other)


def test_active_heldout_excludes_newly_used_development_repository():
    from cv_agent.evaluation.datasets.heldout_manifest import prepare_heldout
    config = json.loads((Path(__file__).parents[1] / 'configs/preparation/heldout_preparation_v2.json').read_text())
    rows = [dict(entry_id=identity, repo_url=repo, report_id=advisory, verify=1, commit='a'*40)
            for identity, repo, advisory in [
                ('dev', 'https://github.com/langchain-ai/langchain', 'shared'),
                ('shared', 'https://github.com/other/project', 'shared'),
                ('heldout', 'https://github.com/other/project', 'independent')]]
    prepared = prepare_heldout(rows, config['development_repositories'])
    assert set(prepared['evaluator_labels']) == {'heldout'}
    assert config['detector_output'] != 'configs/datasets/vulngym_heldout_inputs.json'


def test_scanner_coverage_requires_exact_source_and_line(monkeypatch, tmp_path):
    from types import SimpleNamespace
    import cv_agent.evaluation.diagnostics.profile_langchain_scanner_coverage as mod
    candidate = Candidate(candidate_id='one', case_id='one', repository_id='review',
        path='langchain_core/prompts/prompt.py::other@180-210', line=200, query='eval')
    monkeypatch.setattr(mod, 'git_identity', lambda _: SimpleNamespace(revision='a'*40))
    monkeypatch.setattr(mod, 'load_code_repository', lambda *args: SimpleNamespace(
        documents=[], source_file_count=1, language_file_counts={}, adapter_tier_file_counts={},
        parse_error_paths=[]))
    monkeypatch.setattr(mod.StaticScanner, 'scan', lambda *args: [candidate])
    result = mod.profile_langchain(tmp_path)
    assert all(not row['covered_reference_sink'] for row in result['summaries'])
    assert not mod.covers_reference([candidate.model_copy(update={'line': 198})], 'unrelated/prompt.py', 198)
    assert mod.covers_reference([candidate.model_copy(update={'line': 198})],
                            'langchain_core/prompts/prompt.py', 198)
