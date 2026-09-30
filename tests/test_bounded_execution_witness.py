"""Offline controls for the positive-only bounded execution witness."""

from __future__ import annotations

import ast
import hashlib
import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.runtime.witness.kernel import (
    SourceFileBinding,
    WitnessManifest,
    WitnessResult,
    run_witness,
)


NONCE = "A1B2C3D4E5F6A7B8"


def _manifest(root: Path, source: str) -> WitnessManifest:
    text = textwrap.dedent(source).lstrip()
    path = root / "sample.py"
    path.write_text(text)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    tree = ast.parse(text)
    service = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == "Service")
    serve = next(node for node in service.body if isinstance(node, ast.FunctionDef)
                 and node.name == "serve")
    subject = ValidationSubject(
        candidate_id="neutral-candidate", repository_id="synthetic", property_id="command-execution",
        entry_path=f"sample.py::Service.serve@{serve.lineno}-{serve.end_lineno}",
        entry_line=serve.lineno, source_digest="synthetic-index-digest",
        input_parameters=("model_uri",), analysis_scope="whole Service.serve call",
    )
    return WitnessManifest(
        subject=subject, checkout_root=root, module_name="sample", class_name="Service",
        method_name="serve", entry_relative_path="sample.py", entry_file_sha256=digest,
        entry_first_line=serve.lineno,
        source_modules=(SourceFileBinding(module_name="sample", relative_path="sample.py",
                                          sha256=digest),),
        probe_argument="model_uri", recorder_command="record",
    )


DIRECT = """
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"])
"""

QUOTED = """
import shlex
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {shlex.quote(model_uri)}"])
"""


def test_direct_concat_confirms_candidate_and_records_bound_source(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DIRECT)
    result = run_witness(manifest, nonce=NONCE)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    assert result.raw_status == "EXPANDED_OBSERVED"
    assert not result.gaps
    event = result.details["probe_event"]
    assert event["candidate_frame"]["sha256"] == manifest.entry_file_sha256
    assert event["candidate_frame"]["qualname"] == "Service.serve"
    assert event["emitter_frame"]["file"] == str(tmp_path / "sample.py")
    assert event["emitter_frame"]["line"] == 5
    assert event["seccomp_selftest"] is True
    assert event["hook_selftest"] is True
    assert event["preexec_verified_none"] is True
    assert result.details["control_replay"]["ok"] is True


def test_shlex_quote_only_records_literal_and_never_safe(tmp_path: Path) -> None:
    result = run_witness(_manifest(tmp_path, QUOTED), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.raw_status == "LITERAL_OBSERVED"
    assert result.details["probe_replay"]["ok"] is True
    assert "REFUTED" not in result.model_dump_json()
    assert "SAFE" not in result.model_dump_json()


def test_helper_command_preempts_later_quoted_call_and_confirms(tmp_path: Path) -> None:
    source = """
import shlex
import subprocess

def helper(value):
    subprocess.Popen(["bash", "-c", f"record {value}"])

class Service:
    def serve(self, model_uri):
        helper(model_uri)
        subprocess.Popen(["bash", "-c", f"record {shlex.quote(model_uri)}"])
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    event = result.details["probe_event"]
    assert event["emitter_frame"]["qualname"] == "helper"
    assert event["emitter_frame"]["line"] == 5
    assert event["candidate_frame"]["qualname"] == "Service.serve"


def test_quoted_then_argv_mutation_is_measured_as_expansion(tmp_path: Path) -> None:
    source = """
import shlex
import subprocess

class Service:
    def serve(self, model_uri):
        command = ["bash", "-c", f"record {shlex.quote(model_uri)}"]
        command[2] = f"record {model_uri}"
        subprocess.Popen(command)
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()


@pytest.mark.parametrize("source,gap", [
    ("""
import subprocess
subprocess.Popen(["bash", "-c", "record import"])

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"])
""", "import_time_command_event"),
    ("""
import subprocess
import threading

class Service:
    def serve(self, model_uri):
        worker = threading.Thread(target=lambda: subprocess.Popen(
            ["bash", "-c", f"record {model_uri}"]))
        worker.start()
        worker.join()
""", "event_outside_candidate_frame"),
])
def test_out_of_candidate_events_do_not_confirm(tmp_path: Path, source: str, gap: str) -> None:
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert gap in result.gaps
    assert result.details["probe_event"]["candidate_frame"] is None


def test_probe_only_in_environment_never_confirms(tmp_path: Path) -> None:
    source = """
import os
import subprocess

class Service:
    def serve(self, model_uri):
        env = dict(os.environ, MODEL_URI=model_uri)
        subprocess.Popen(["bash", "-c", "record constant"], env=env)
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "probe_not_in_argv" in result.gaps
    assert result.details["probe_event"]["env_has_probe"] is True


def test_failed_benign_control_blocks_positive(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        if "$(printf " in model_uri:
            subprocess.Popen(["bash", "-c", f"record {model_uri}"])
        else:
            subprocess.Popen(["bash", "-c", "record unexpected"])
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "benign_control_failed" in result.gaps


def test_benign_control_expansion_blocks_positive(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        command = f"record {model_uri}"
        if "$(printf " not in model_uri:
            command += "$(printf unexpected)"
        subprocess.Popen(["bash", "-c", command])
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "benign_control_failed" in result.gaps
    assert "control_replay" not in result.details


def test_replay_path_branch_cannot_create_false_confirmation(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        command = f'if [ -e "$PATH/zcvagentrecord" ]; then zcvagentrecord {model_uri}; fi'
        subprocess.Popen(["bash", "-c", command])
"""
    manifest = _manifest(tmp_path, source).model_copy(update={
        "recorder_command": "zcvagentrecord",
    })
    result = run_witness(manifest, nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "unsupported_shell_command_shape" in result.gaps


def test_direct_exec_prefix_is_supported(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"exec record {model_uri}"])
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()


def test_cross_file_helper_requires_source_binding(tmp_path: Path) -> None:
    source = """
import helper

class Service:
    def serve(self, model_uri):
        helper.launch(model_uri)
"""
    helper_source = """
import subprocess

def launch(value):
    subprocess.Popen(["bash", "-c", f"record {value}"])
"""
    manifest = _manifest(tmp_path, source)
    helper_file = tmp_path / "helper.py"
    helper_file.write_text(textwrap.dedent(helper_source).lstrip())
    helper_binding = SourceFileBinding(
        module_name="helper", relative_path="helper.py",
        sha256=hashlib.sha256(helper_file.read_bytes()).hexdigest(),
    )
    bound = manifest.model_copy(update={
        "source_modules": (*manifest.source_modules, helper_binding),
    })
    confirmed = run_witness(bound, nonce=NONCE)
    assert confirmed.status == ValidationStatus.CONFIRMED, confirmed.model_dump()
    assert confirmed.details["probe_event"]["emitter_frame"]["module_name"] == "helper"
    unbound = run_witness(manifest, nonce=NONCE)
    assert unbound.status == ValidationStatus.UNRESOLVED, unbound.model_dump()
    assert "source_mismatch" in unbound.gaps
    assert "undeclared_imported_source:helper" in unbound.details["probe_event"]["source_gaps"]
    helper_file.write_text(helper_file.read_text() + "\n# changed after manifest\n")
    altered = run_witness(bound, nonce=NONCE)
    assert altered.status == ValidationStatus.UNRESOLVED, altered.model_dump()
    assert "source_mismatch" in altered.gaps


def test_returned_helper_source_is_bound_even_when_emitter_is_entry(tmp_path: Path) -> None:
    source = """
import helper
import subprocess

class Service:
    def serve(self, model_uri):
        value = helper.transform(model_uri)
        subprocess.Popen(["bash", "-c", f"record {value}"])
"""
    helper_source = """
import shlex

def transform(value):
    return shlex.quote(value)
"""
    manifest = _manifest(tmp_path, source)
    helper_file = tmp_path / "helper.py"
    helper_file.write_text(textwrap.dedent(helper_source).lstrip())
    helper_binding = SourceFileBinding(
        module_name="helper", relative_path="helper.py",
        sha256=hashlib.sha256(helper_file.read_bytes()).hexdigest(),
    )
    bound = manifest.model_copy(update={
        "source_modules": (*manifest.source_modules, helper_binding),
    })
    literal = run_witness(bound, nonce=NONCE)
    assert literal.status == ValidationStatus.UNRESOLVED, literal.model_dump()
    assert literal.raw_status == "LITERAL_OBSERVED"
    helper_file.write_text("def transform(value):\n    return value\n")
    stale = run_witness(bound, nonce=NONCE)
    assert stale.status == ValidationStatus.UNRESOLVED, stale.model_dump()
    assert "source_mismatch" in stale.gaps
    omitted = run_witness(manifest, nonce=NONCE)
    assert omitted.status == ValidationStatus.UNRESOLVED, omitted.model_dump()
    assert "undeclared_imported_source:helper" in omitted.details["probe_event"]["source_gaps"]


def test_forged_audit_event_cannot_confirm(tmp_path: Path) -> None:
    source = """
import sys

class Service:
    def serve(self, model_uri):
        sys.audit("subprocess.Popen", "bash", ["bash", "-c", f"record {model_uri}"], None, None)
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "audit_event_not_authenticated" in result.gaps
    assert result.details["probe_event"]["authentic_subprocess_popen"] is False


def test_forged_benign_control_cannot_validate_real_probe(tmp_path: Path) -> None:
    source = """
import subprocess
import sys

class Service:
    def serve(self, model_uri):
        argv = ["bash", "-c", f"record {model_uri}"]
        if "$(printf " in model_uri:
            subprocess.Popen(argv)
        else:
            sys.audit("subprocess.Popen", "bash", argv, None, None)
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "benign_control_failed" in result.gaps
    assert result.details["probe_event"]["authentic_subprocess_popen"] is True
    assert result.details["control_event"]["authentic_subprocess_popen"] is False


def test_unverifiable_direct_os_system_event_cannot_confirm(tmp_path: Path) -> None:
    source = """
import os

class Service:
    def serve(self, model_uri):
        os.system(f"record {model_uri}")
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "audit_event_not_authenticated" in result.gaps


def test_selftest_and_source_failures_are_unresolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import cv_agent.runtime.witness.kernel as witness

    manifest = _manifest(tmp_path, DIRECT)
    original = witness._run_worker
    monkeypatch.setattr(witness, "_run_worker", lambda *a: {
        "kind": "error", "gap": "hook_selftest_failed"})
    assert "hook_selftest_failed" in run_witness(manifest, nonce=NONCE).gaps
    monkeypatch.setattr(witness, "_run_worker", lambda *a: {
        "kind": "error", "gap": "seccomp_selftest_failed"})
    assert "seccomp_selftest_failed" in run_witness(manifest, nonce=NONCE).gaps
    monkeypatch.setattr(witness, "_run_worker", original)
    (tmp_path / "sample.py").write_text(DIRECT + "\n# altered\n")
    assert "source_mismatch" in run_witness(manifest, nonce=NONCE).gaps


def test_imported_module_source_must_match_checkout(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"])
"""
    manifest = _manifest(tmp_path, source)
    other = SourceFileBinding(module_name="json", relative_path="json.py", sha256="0" * 64)
    altered = manifest.model_copy(update={"source_modules": (*manifest.source_modules, other)})
    result = run_witness(altered, nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED
    assert "source_mismatch" in result.gaps


def test_manifest_rejects_target_stubs_and_revision_role(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DIRECT)
    base = manifest.model_dump(mode="json")
    for key in ("stubs", "target_stubs", "revision_role"):
        with pytest.raises(ValidationError):
            WitnessManifest.model_validate({**base, key: {"helper": "replacement"}})


def test_label_role_cannot_affect_result_bytes(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DIRECT)
    # Roles are deliberately outside the invocation manifest. An external
    # scorer may flip them. Normalize temporary roots and volatile process
    # measurements; retain statuses, provenance, arguments and actual limits.
    serialized: list[bytes] = []
    for external_revision_role in ("vulnerable", "fixed"):
        assert external_revision_role not in manifest.model_dump_json()
        result = run_witness(manifest, nonce=NONCE)
        assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
        normalized = result.model_dump(mode="json")
        for event_name in ("probe_event", "control_event"):
            event = normalized["details"][event_name]
            assert event["applied_resource_limits"]["cpu"] == [5, 5]
            for field in ("target_pid", "target_self_usage", "resource_accounting"):
                event.pop(field)
        import json
        record = json.dumps(normalized, sort_keys=True)
        expanded_path = result.details["probe_path"].replace(f"$(printf {NONCE})", NONCE)
        record = record.replace(expanded_path, "<EXPANDED_PATH>")
        record = record.replace(result.details["probe_path"], "<PROBE_PATH>")
        record = record.replace(result.details["control_path"], "<CONTROL_PATH>")
        serialized.append(record.encode())
    assert serialized[0] == serialized[1]
    assert "revision_role" not in manifest.model_dump_json()


def test_catching_baseexception_cannot_continue_past_first_event(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        try:
            subprocess.Popen(["bash", "-c", f"record {model_uri}"])
        except BaseException:
            subprocess.Popen(["bash", "-c", "record caught"])
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    assert result.details["probe_event"]["emitter_frame"]["line"] == 6


def test_result_schema_rejects_refuted_at_type_boundary() -> None:
    with pytest.raises(ValidationError):
        WitnessResult(status=ValidationStatus.REFUTED, raw_status="LITERAL_OBSERVED")


def test_non_bash_shell_remains_unresolved(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["/bin/sh", "-c", f"record {model_uri}"])
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED
    assert "actual_executable_not_verified_bash" in result.gaps


def test_popen_executable_override_blocks_false_bash_witness(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"], executable="/bin/true")
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "actual_executable_not_verified_bash" in result.gaps


def test_failing_preexec_cannot_confirm_bash_execution(tmp_path: Path) -> None:
    source = """
import subprocess

def fail_before_exec():
    raise RuntimeError("child would never start Bash")

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"],
                         preexec_fn=fail_before_exec)
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "preexec_not_verified" in result.gaps
    assert result.details["probe_event"]["authentic_subprocess_popen"] is True
    assert result.details["probe_event"]["preexec_verified_none"] is False


def test_popen_environment_path_must_resolve_to_bash(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"],
                         env={"PATH": "/no-such-bin"})
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "actual_executable_not_verified_bash" in result.gaps


@pytest.mark.parametrize("key", ["BASH_ENV", "BASH_FUNC_printf%%"])
def test_captured_shell_environment_is_recorded_but_not_replayed(
    tmp_path: Path, key: str,
) -> None:
    source = f"""
import subprocess

class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {{model_uri}}"],
                         env={{"PATH": "/bin:/usr/bin", {key!r}: "injected"}})
"""
    result = run_witness(_manifest(tmp_path, source), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "captured_shell_environment_not_replayed" in result.gaps
    assert key in result.details["probe_event"]["shell_env_keys"]
    assert "probe_replay" not in result.details


def test_declared_entry_boolean_must_match_actual_call(tmp_path: Path) -> None:
    source = """
import subprocess

class Service:
    def serve(self, model_uri, enabled=False):
        if enabled:
            subprocess.Popen(["bash", "-c", f"record {model_uri}"])
"""
    manifest = _manifest(tmp_path, source)
    subject = manifest.subject.model_copy(update={"entry_boolean_arguments": {"enabled": False}})
    mismatched = manifest.model_copy(update={"subject": subject, "call_kwargs": {"enabled": True}})
    result = run_witness(mismatched, nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED
    assert "entry_boolean_argument_unverified:enabled" in result.gaps
    matched_subject = subject.model_copy(update={"entry_boolean_arguments": {"enabled": True}})
    matched = mismatched.model_copy(update={"subject": matched_subject})
    positive = run_witness(matched, nonce=NONCE)
    assert positive.status == ValidationStatus.CONFIRMED, positive.model_dump()


def test_unverified_condition_and_value_assumptions_cannot_confirm(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DIRECT)
    subject = manifest.subject.model_copy(update={
        "entry_condition_assumptions": {"is_linux()": True},
        "entry_value_assumptions": {"self.mode": "local"},
    })
    result = run_witness(manifest.model_copy(update={"subject": subject}), nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED
    assert "entry_condition_assumption_unverified:is_linux()" in result.gaps
    assert "entry_value_assumption_unverified:self.mode" in result.gaps
