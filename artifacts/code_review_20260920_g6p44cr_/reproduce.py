from pathlib import Path
import json
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path('/home/joker/AAA_NUS_SEM2/cv_agent')
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'scripts'))
from test_validation_tools import _registry, _invoke, _command_documents
from cv_agent.agent_tools import ToolExecutionScope, repository_source_digest
from cv_agent.agent_types import ValidationSubject, AgentExpertConclusion, ReActStep, ModelToolCall, ToolObservation
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import CodeDocument
from cv_agent.react_engine import validate_conclusion

records = []

def check_predictions(observation, subject):
    observation = observation.model_copy(update={'citation_id': 'tool:1'})
    step = ReActStep(step=1, model_id='offline', tool_call=ModelToolCall(call_id='review', name=observation.tool, arguments={}), observation=observation)
    outcomes = {}
    for label in ('SAFE', 'VULNERABLE'):
        output = AgentExpertConclusion(expert='scan', label=label, confidence=0.8, validation_status='UNRESOLVED', evidence_ids=('tool:1',), rationale='Offline semantic check.')
        try:
            validate_conclusion(output, [step], frozenset(), subject=subject)
            outcomes[label] = 'accepted'
        except ValueError as error:
            outcomes[label] = str(error)
    return outcomes

def permission(name, source):
    document = CodeDocument(repository_id='review', path='permission.py::check@1-20', text=source)
    index = RepositoryIndex([document])
    subject = ValidationSubject(candidate_id='review', repository_id='review', entry_path=document.path, source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(admitted_paths=frozenset({document.path}), candidate_path=document.path, subject=subject, max_observation_tokens=20000)
    observation = _invoke(_registry(index), 'validate_permission_mode', {'path': document.path}, scope)
    calls = []
    namespace = {'os': SimpleNamespace(chmod=lambda *args: calls.append(args))}
    exec(compile(source, '<review-fixture>', 'exec'), namespace)
    error = None
    try:
        namespace['check']('review-target', SimpleNamespace())
    except Exception as caught:
        error = type(caught).__name__
    record = {'name': name, 'source': source, 'tool_status': observation.validation_status.value, 'runtime_chmod_calls': calls, 'runtime_error': error, 'observation': observation.model_dump(mode='json')}
    records.append(record)
    print(name, observation.validation_status.value, 'runtime calls:', calls, 'runtime error:', error)

permission('permission_positive', 'def check(path, replacement):\n    os.chmod(path, 0o777)\n')
permission('permission_negative', 'def check(path, replacement):\n    os.chmod(path, 0o750)\n')
permission('permission_try_return', 'def check(path, replacement):\n    try:\n        return path\n    finally:\n        pass\n    os.chmod(path, 0o777)\n')
permission('permission_short_circuit', 'def check(path, replacement):\n    False and os.chmod(path, 0o777)\n')
permission('permission_local_binding_after_call', 'def check(path, replacement):\n    os.chmod(path, 0o777)\n    os = replacement\n')
permission('permission_call_order', 'def check(path, replacement):\n    os.chmod(path, 0o750) or os.chmod(path, 0o777)\n')

SAFE_HELPER = 'def get_cmd(model_uri):\n    cmd = f"worker {shlex.quote(model_uri)}"\n    return cmd, {}\n'

def command(name, source, backend_source=None, args=('clean',)):
    backend, helper = _command_documents(source)
    if backend_source is not None:
        backend = backend.model_copy(update={'text': backend_source})
    index = RepositoryIndex([backend, helper])
    subject = ValidationSubject(candidate_id='review', repository_id='repo', entry_path=backend.path, source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(admitted_paths=frozenset({backend.path, helper.path}), candidate_path=backend.path, subject=subject, max_observation_tokens=20000)
    observation = _invoke(_registry(index), 'inspect_command_construction', {'source_path': backend.path}, scope)
    namespace = {'shlex': shlex}
    exec(compile(source, '<review-fixture>', 'exec'), namespace)
    returned = namespace['get_cmd'](*args)
    payload = json.loads(observation.content)
    record = {'name': name, 'source': source, 'backend_source': backend.text, 'command_status': payload['command_construction_status'], 'returned_command': returned, 'predictions': check_predictions(observation, subject), 'observation': observation.model_dump(mode='json')}
    if backend_source:
        captured = []
        caller_namespace = {'mlserver': SimpleNamespace(get_cmd=namespace['get_cmd']), 'subprocess': SimpleNamespace(Popen=lambda argv: captured.append(argv))}
        exec(compile(backend_source, '<review-caller>', 'exec'), caller_namespace)
        caller_namespace['serve']('clean', '; printf REVIEW_MARKER')
        record['captured_sink_argv'] = captured
    records.append(record)
    print(name, record['command_status'], 'returned:', returned, 'predictions:', record['predictions'])
    return record

command('command_quoted_control', SAFE_HELPER)
command('command_raw_control', 'def get_cmd(model_uri):\n    cmd = f"worker {model_uri}"\n    return cmd, {}\n')
command('command_loop_append', 'def get_cmd(model_uri, suffix):\n    cmd = f"worker {shlex.quote(model_uri)}"\n    for value in [suffix]:\n        cmd += value\n    return cmd, {}\n', args=('clean', '; printf REVIEW_MARKER'))
command('command_dead_code', 'def get_cmd(model_uri):\n    cmd = f"worker {shlex.quote(model_uri)}"\n    return cmd, {}\n    cmd = f"worker {model_uri}"\n')
command('command_overwritten_raw_value', 'def get_cmd(model_uri):\n    cmd = f"worker {model_uri}"\n    cmd = f"worker {shlex.quote(model_uri)}"\n    return cmd, {}\n')
command('command_caller_append', SAFE_HELPER, backend_source='def serve(model_uri, suffix):\n    command, command_env = mlserver.get_cmd(model_uri)\n    command += suffix\n    return subprocess.Popen(["bash", "-c", command])\n')
quote_context = command('command_double_quote_context', '''def get_cmd(model_uri):
    cmd = f'printf "%s" "{shlex.quote(model_uri)}"'
    return cmd, {}
''', args=('$(printf REVIEW_MARKER)',))
# This is a fixed project-owned marker command: no file changes, network, or external input.
completed = subprocess.run(['/bin/bash', '-c', quote_context['returned_command'][0]], capture_output=True, text=True, timeout=5, check=True)
quote_context['controlled_bash_stdout'] = completed.stdout
quote_context['literal_input'] = '$(printf REVIEW_MARKER)'
print('quote context actual stdout:', repr(completed.stdout))

source_read = ToolObservation(tool='read_span', status='ok', content='command += suffix', citation_id='tool:source')
counter = ToolObservation(tool='inspect_command_construction', status='ok', content=json.dumps({'command_construction_status':'SANITIZED'}), citation_id='tool:counter')
trace = [ReActStep(step=i, model_id='offline', tool_call=ModelToolCall(call_id=f'call{i}', name=obs.tool, arguments={}), observation=obs) for i, obs in enumerate((source_read, counter), start=1)]
for references in ((), ('tool:counter',)):
    output = AgentExpertConclusion(expert='scan', label='VULNERABLE', confidence=0.8, validation_status='UNRESOLVED', evidence_ids=('tool:source',), supporting_observation_ids=('tool:source',), counter_observation_ids=references, rationale='The helper quotes one input; the caller appends a raw suffix afterward.')
    error = None
    try:
        validate_conclusion(output, trace, frozenset())
    except ValueError as caught:
        error = str(caught)
    records.append({'name':'counter_citation_present' if references else 'counter_citation_absent', 'output':output.model_dump(mode='json'), 'error':error})
    print('counter citation:', references, 'validation error:', error)

from run_python_heldout_pair_matrix import rows_with_truth
from cv_agent.python_heldout_pair_config import PythonHeldoutPairExperimentConfig, planned_heldout_cells, heldout_truth
from cv_agent.python_heldout_pair_acceptance import heldout_pair_acceptance_issues
config = PythonHeldoutPairExperimentConfig.model_validate_json((ROOT / 'configs/python_heldout_pairs_v2.json').read_text())
rows = [{'case_id':case.case_id, 'system':system.value, 'pair_id':pair.pair_id, 'revision_role':case.revision_role, 'status':'completed', 'predicted_label':heldout_truth(case.revision_role)} for pair, case, system in planned_heldout_cells(config)]
extra = {**rows[0], 'case_id':'unexpected', 'status':'failed'}
raw = rows + [extra]
enriched = rows_with_truth(raw, config)
issues_raw = heldout_pair_acceptance_issues(raw, {'requests':31}, config)
issues_enriched = heldout_pair_acceptance_issues(enriched, {'requests':31}, config)
records.append({'name':'unexpected_row_disappears_from_results', 'raw_count':len(raw), 'enriched_count':len(enriched), 'issues_raw':issues_raw, 'issues_enriched':issues_enriched})
print('unexpected row:', len(raw), '->', len(enriched), 'raw acceptance:',issues_raw,'saved acceptance:',issues_enriched)

out = Path(tempfile.mkdtemp(prefix='code_review_20260920_', dir=ROOT / 'artifacts'))
(out / 'offline_reproductions.json').write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n')
(out / 'reproduce.py').write_text(Path(__file__).read_text())
print('REVIEW_ARTIFACT', out)
