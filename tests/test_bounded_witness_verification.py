"""Full runtime obligations and benign control belong to this candidate only."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.diagnostics.bounded_execution_witness import SourceFileBinding, run_witness
from test_bounded_execution_witness import NONCE, _manifest


SOURCE = '''
import os
import sys
import subprocess
import shlex
RUNTIME = "runtime"
MODEL = "model"
def is_windows():
    return False
def download(path):
    if os.path.exists(path):
        return path
    raise ValueError("missing path")
def before_exec():
    try:
        raise OSError("ordinary caught exception")
    except OSError:
        return
class Service:
    def __init__(self):
        self.nworkers = 1
        self.manager = "local"
    def serve(self, model_uri):
        path = download(model_uri)
        if sys.platform.startswith("linux"):
            fn = before_exec
        else:
            fn = None
        if not is_windows():
            command = f"record {path}"
        else:
            command = f"record {path}"
        if self.manager != "local":
            raise RuntimeError("wrong manager")
        if not is_windows():
            argv = ["bash", "-c", command]
        subprocess.Popen(argv, preexec_fn=fn)
'''


def _bound(root: Path, source=SOURCE):
    manifest = _manifest(root, source)
    return manifest.model_copy(update={'subject': manifest.subject.model_copy(update={
        'entry_value_assumptions': {'self.nworkers': 1, 'RUNTIME': 'runtime', 'MODEL': 'model'},
        'entry_condition_assumptions': {"sys.platform.startswith('linux')": True,
                                       'is_windows()': False,
                                       'self.manager != "local"': False,
                                       'os.path.exists(path)': True},
    })})


def test_all_obligations_and_real_benign_control_close_confirmation(tmp_path):
    result = run_witness(_bound(tmp_path), nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    assert result.raw_status == 'EXPANDED_OBSERVED'
    assert result.gaps == ()
    for name in ('probe_event', 'control_event'):
        event = result.details[name]
        assert event['candidate_frame']['sha256'] == result.details['entry_file_sha256']
        assert event['assumption_verification']['gaps'] == []
        assert event['preexec_verification']['ok'] is True
        assert event['preexec_verification']['kind'] == 'executed_child'
    assert result.details['control_replay']['arguments'] == [result.details['control_path']]
    assert result.details['verification_mode'] is True


def test_verified_literal_is_unresolved_and_never_refuted_or_safe(tmp_path):
    source = SOURCE.replace('command = f"record {path}"', 'command = f"record {shlex.quote(path)}"')
    result = run_witness(_bound(tmp_path, source), nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.raw_status == 'LITERAL_OBSERVED'
    assert result.gaps == ()
    assert result.details['control_replay']['ok'] is True


def test_runtime_value_mismatch_keeps_specific_gap(tmp_path):
    manifest = _bound(tmp_path)
    manifest = manifest.model_copy(update={'subject': manifest.subject.model_copy(update={
        'entry_value_assumptions': {'self.nworkers': 2, 'RUNTIME': 'runtime', 'MODEL': 'model'},
    })})
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'entry_value_assumption_mismatch:self.nworkers' in result.gaps
    assert result.details['probe_event']['assumption_verification']['values']['observations']['self.nworkers'][0]['actual'] == 1


def test_any_executed_branch_mismatch_prevents_confirmation(tmp_path):
    source = SOURCE.replace('return False', 'return True')
    # Still reach Popen, so a branch failure cannot be hidden by successful argv.
    source = source.replace('if not is_windows():\n            argv', 'if is_windows():\n            argv')
    result = run_witness(_bound(tmp_path, source), nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert 'entry_condition_assumption_mismatch:is_windows()' in result.gaps


def test_unexecuted_condition_is_not_discharged(tmp_path):
    source = SOURCE.replace('path = download(model_uri)', 'path = download(model_uri)\n        if False:\n            if never_called():\n                pass')
    manifest = _bound(tmp_path, source)
    assumptions = {**manifest.subject.entry_condition_assumptions, 'never_called()': True}
    manifest = manifest.model_copy(update={'subject': manifest.subject.model_copy(update={
        'entry_condition_assumptions': assumptions})})
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'entry_condition_assumption_unverified:never_called()' in result.gaps


def test_unrelated_same_name_constant_blocks_unique_definition(tmp_path):
    manifest = _bound(tmp_path)
    extra = tmp_path / 'other.py'
    extra.write_text('RUNTIME = "runtime"\n')
    binding = SourceFileBinding(module_name='other', relative_path='other.py',
                                sha256=hashlib.sha256(extra.read_bytes()).hexdigest())
    manifest = manifest.model_copy(update={'source_modules': (*manifest.source_modules, binding)})
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'entry_value_definition_nonunique:RUNTIME' in result.gaps


def test_caught_preexec_exec_attempt_never_confirms(tmp_path):
    source = SOURCE.replace('raise OSError("ordinary caught exception")', 'os.execv("/bin/true", ["/bin/true"])').replace('except OSError:', 'except BaseException:')
    result = run_witness(_bound(tmp_path, source), nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'preexec_not_verified' in result.gaps
    assert result.details['probe_event']['preexec_verification']['forbidden_events']


def test_benign_control_failure_cannot_be_ignored(tmp_path):
    source = SOURCE.replace('subprocess.Popen(argv, preexec_fn=fn)',
                            'if "$(printf " not in model_uri:\n            argv = ["bash", "-c", "record wrong"]\n        subprocess.Popen(argv, preexec_fn=fn)')
    result = run_witness(_bound(tmp_path, source), nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'benign_control_failed' in result.gaps
    assert 'control_event' in result.details


def test_legacy_diagnostic_stays_observation_only(tmp_path):
    result = run_witness(_bound(tmp_path), nonce=NONCE, diagnostic_only=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.raw_status == 'UNRESOLVED'
    assert 'control_event' not in result.details


def test_verification_and_legacy_diagnostic_modes_are_exclusive(tmp_path):
    with pytest.raises(ValueError, match='exclusive'):
        run_witness(_bound(tmp_path), nonce=NONCE, verify_obligations=True, diagnostic_only=True)
