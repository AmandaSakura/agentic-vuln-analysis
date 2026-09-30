"""Recorder selection comes from the authenticated boundary, never sample identity."""

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.runtime.witness.kernel import run_witness
from test_bounded_execution_witness import NONCE, _manifest


@pytest.mark.parametrize('executable,args', [('widget', 'launch'), ('other_server', '--serve --quiet')])
def test_recorder_prefix_is_measured_and_control_uses_same_prefix(tmp_path, executable, args):
    manifest = _manifest(tmp_path, f'''
        import subprocess
        class Service:
            def serve(self, model_uri):
                subprocess.Popen(["bash", "-c", f"exec {executable} {args} {{model_uri}}"])
    ''')
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True, derive_recorder=True)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    assert result.details['derived_recorder'] == {'command':executable,'arguments':args.split()}
    assert result.details['control_replay']['arguments'] == [*args.split(),result.details['control_path']]


def test_measured_quoted_command_keeps_literal_positive_only_contract(tmp_path):
    manifest = _manifest(tmp_path, '''
        import subprocess
        import shlex
        class Service:
            def serve(self, model_uri):
                subprocess.Popen(["bash", "-c", f"widget --serve {shlex.quote(model_uri)}"])
    ''')
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True, derive_recorder=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.raw_status == 'LITERAL_OBSERVED'
    assert result.gaps == ()


@pytest.mark.parametrize('command', ['widget start {model_uri}; echo injected',
                                    '/bin/widget {model_uri}',
                                    'widget start {model_uri} && other',
                                    'widget "dynamic arg" {model_uri}'])
def test_unsupported_prefix_or_control_syntax_cannot_supply_confirmation(tmp_path, command):
    manifest = _manifest(tmp_path, f'''
        import subprocess
        class Service:
            def serve(self, model_uri):
                subprocess.Popen(["bash", "-c", f{command!r}])
    ''')
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True, derive_recorder=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'recorder_prefix_not_established' in result.gaps


def test_control_prefix_cannot_change_after_probe_measurement(tmp_path):
    manifest = _manifest(tmp_path, '''
        import subprocess
        class Service:
            def serve(self, model_uri):
                name = "widget" if "$(printf " in model_uri else "other"
                subprocess.Popen(["bash", "-c", f"{name} {model_uri}"])
    ''')
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True, derive_recorder=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert 'benign_control_failed' in result.gaps


def test_derivation_requires_full_verification_mode(tmp_path):
    with pytest.raises(ValueError, match='verification'):
        run_witness(_manifest(tmp_path, 'class Service:\n    def serve(self, model_uri): pass\n'),
                    nonce=NONCE, derive_recorder=True)
