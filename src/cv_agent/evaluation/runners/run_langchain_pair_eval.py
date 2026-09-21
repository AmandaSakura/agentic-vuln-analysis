"""Bounded, oracle-seeded LangChain development evaluation. No held-out claims."""
import hashlib
import json
from pathlib import Path
from typing import Literal
from types import SimpleNamespace
from uuid import uuid4

from cv_agent.evaluation.runners.reproduce_langchain_template_pair import reproduce_pair, require_clean_checkout, get_git_commit, VULN_COMMIT, FIX_COMMIT
from cv_agent.runtime.budget import Budget
from cv_agent.evaluation.runners.run_development_benchmark import run_candidate
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.runtime.journal import Journal
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.tools.registry import AgentTool, ToolExecutionScope
from cv_agent.tools.identity import candidate_subject
from cv_agent.domain.evidence import ToolObservation
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.admission import require_passing_tests
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.evaluation.datasets.python_pair_fixture import build_pair_input as build_full_pair_input, fixture_validation_status
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate, FrozenModel
from cv_agent.tools.validation import full_agent_tools


class PairInput(FrozenModel):
    fixture_id: Literal['template_traversal']


def check_checkout(checkout, case):
    require_clean_checkout(checkout)
    if get_git_commit(checkout) != case['commit']:
        raise ValueError('Checkout identity changed')


def build_input(checkout, case):
    if (checkout / 'libs/core').is_dir():
        pair = SimpleNamespace(
            source_root='libs/core',
            exclude_path_parts=('tests', '__pycache__'),
            entry_symbol=case['entry_symbol'],
            source_scope='PromptTemplate.from_template f-string attribute and dunder traversal only',
            analysis_scope='Assess only f-string attribute and dunder traversal through '
            'PromptTemplate.from_template. Use registered template_traversal '
            'fixture evidence and preserve the benign control. A negative result '
            'applies only to these traversal hypotheses, not general safety.',
        )
        full_case = SimpleNamespace(
            case_id=case['case_id'],
            checkout=checkout.name,
            file_path=case['file_path'],
            line_hint=case['line'],
            revision_role='vulnerable' if case['case_id'].endswith('01') else 'fixed',
            commit=case.get('commit', ''),
        )
        index, candidate, _ = build_full_pair_input(checkout.parent, pair, full_case)
        return index, candidate
    spans = parse_python_source(case['case_id'], case['file_path'],
                                (checkout / case['file_path']).read_text())
    entry = next(span for span in spans
                 if case['entry_symbol'] in span.document.defines)
    index = RepositoryIndex(span.document for span in spans)
    candidate = Candidate(candidate_id=case['case_id'], case_id=case['case_id'],
                          repository_id=case['case_id'], path=entry.document.path,
                          line=entry.start_line,
                          query='PromptTemplate.from_template f-string attribute dunder traversal',
                          analysis_scope='Assess only f-string attribute and dunder traversal through '
                          'PromptTemplate.from_template. Use registered template_traversal '
                          'fixture evidence and preserve the benign control. A negative result '
                          'applies only to these traversal hypotheses, not general safety.')
    return index, candidate


def evidence_tool(checkout, case, index, candidate, observations, validation_status):
    """Expose current-run preflight witnesses, never evaluator labels or raw paths."""
    subject = candidate_subject(index, candidate)
    source = checkout / case['file_path']
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    def handler(args, scope):
        if scope.subject != subject or scope.candidate_path != candidate.path:
            return ToolObservation(tool='run_fixture_test', status='blocked',
                                   content='Fixture is bound to another candidate.')
        check_checkout(checkout, case)
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError('Source changed since pair validation')
        return ToolObservation(tool='run_fixture_test', status='ok', subject=subject,
                               validation_status=validation_status,
                               content=json.dumps(dict(
                                   execution='current-run offline preflight; checkout revalidated',
                                   scope='f-string attribute and dunder traversal only',
                                   observations=observations)))

    return AgentTool('run_fixture_test',
                     'Read executed template_traversal fixture witnesses for this exact candidate. '
                     'Includes benign control and two synthetic traversal probes; no general safety claim.',
                     PairInput, handler, content_type='json',
                     validation_statuses=('CONFIRMED', 'REFUTED'))


def run():
    config = json.loads((project_root / 'configs/experiments/langchain_pair_eval.json').read_text())
    if [case['commit'] for case in config['detector_cases']] != [VULN_COMMIT, FIX_COMMIT]:
        raise ValueError('Pair evidence mapping differs from pinned reproduction')
    run_dir = project_root / 'artifacts/langchain_agent_eval' / uuid4().hex
    run_dir.mkdir(parents=True)
    require_passing_tests()
    reproduction = reproduce_pair(run_dir / 'pair_preflight')
    if not reproduction['summary']['verified_differential_security']:
        raise ValueError('Mandatory real pair preflight failed')
    matrix = json.loads((run_dir / 'pair_preflight/results.json').read_text())['matrix']
    model_config = json.loads((project_root / config['model_config']).read_text())
    (run_dir / 'metadata.json').write_text(json.dumps(dict(
        config=config, model_config=model_config, source_sha256=snapshot_sources(project_root, run_dir)), indent=2))
    journal = Journal(run_dir / 'events.jsonl')
    budget = Budget(config['limits']['max_requests'], config['limits']['max_seconds'])
    rows = []
    print(f'Run directory: {run_dir}', flush=True)
    for case, target in zip(config['detector_cases'],
                            ('vulnerable', 'fixed'), strict=True):
        checkout = project_root / config['runner_private_checkouts'][case['case_id']]
        check_checkout(checkout, case)
        index, candidate = build_input(checkout, case)
        # Whitelist behavioral fields: raw subprocess output contains private paths.
        observations = {scenario: {key: value for key, value in result.items()
                        if key in {'status', 'success', 'output', 'leaked_secret', 'leaked_dunder',
                                   'error_type', 'error_message'}} for scenario, result in matrix[target].items()}
        status = fixture_validation_status('langchain_template_traversal', target, observations)
        fixture = evidence_tool(checkout, case, index, candidate, observations, status)
        registered = tuple(tool for tool in full_agent_tools(index) if tool.name != fixture.name) + (fixture,)
        row = run_candidate(index, candidate, AgentSystemVersion.E1_LOCAL_SINGLE,
                            journal, budget, model_config=model_config, registered_tools=registered)
        rows.append(row)
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        (run_dir / 'results.json').write_text(json.dumps(dict(
            claim_eligible=False, candidate_protocol='oracle_entry_point',
            scope='two traversal hypotheses; development pair only',
            results=rows, usage=provider_usage(events)), indent=2))
        print(f"{case['case_id']}: {row['status']} {row['predicted_label']}", flush=True)
    return run_dir


if __name__ == '__main__':
    run()
