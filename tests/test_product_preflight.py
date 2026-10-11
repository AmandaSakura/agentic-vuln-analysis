"""Capability checks do not turn unavailable execution into a static-path failure."""
from pathlib import Path

from cv_agent.application.preflight import preflight


def test_static_preflight_needs_no_model_or_execution(tmp_path):
    (tmp_path / "entry.py").write_text("def entry():\n    return 42\n")
    result = preflight(tmp_path, language="python", property_id="chmod-mode-others-write")
    selected = {item.method: item for item in result.capabilities}
    assert selected["source_index"].state == "AVAILABLE"
    assert selected["validate_permission_mode"].state == "AVAILABLE"
    assert selected["model_explanation"].state == "UNSUPPORTED"
    assert selected["bounded_witness"].state == "UNSUPPORTED"
    assert result.model_requests == 0
    assert result.ready is True


def test_missing_validator_does_not_disable_source_index(tmp_path):
    result = preflight(tmp_path, language="python", property_id="chmod-mode-others-write",
                       available_tools=frozenset())
    selected = {item.method: item for item in result.capabilities}
    assert selected["source_index"].state == "AVAILABLE"
    assert selected["validate_permission_mode"].state == "UNSUPPORTED"
    assert selected["validate_permission_mode"].reason_code == "validator_unavailable"
    assert result.model_requests == 0


def test_unregistered_required_fixture_is_blocked_without_call(tmp_path):
    result = preflight(tmp_path, required_methods=("fixture:owned",))
    blocked = next(item for item in result.capabilities if item.method == "fixture:owned")
    assert blocked.state == "BLOCKED"
    assert blocked.reason_code == "owned_fixture_not_registered"
    assert result.ready is False
    assert result.model_requests == 0
    assert result.diagnoses[0].owner == "environment"
    assert result.diagnoses[0].experiment_failure_class == "F4"


def test_approved_owned_check_restores_only_its_capability(tmp_path):
    calls = []
    ready = False

    def owned_check():
        calls.append("owned")
        return ready, "owned dependency missing" if not ready else "owned check ready"

    before = preflight(tmp_path, required_methods=("fixture:owned",),
                       owned_checks={"owned": owned_check})
    ready = True
    after = preflight(tmp_path, required_methods=("fixture:owned",),
                      owned_checks={"owned": owned_check})
    assert before.ready is False and after.ready is True
    assert calls == ["owned", "owned"]
    assert before.capabilities[0] == after.capabilities[0]
    assert after.model_requests == 0


def test_missing_root_and_unsupported_language_are_explicit(tmp_path):
    result = preflight(tmp_path / "missing", language="unknown", property_id="command-execution")
    assert result.ready is False
    assert result.capabilities[0].reason_code == "source_root_unavailable"
    assert any(item.reason_code == "language_not_supported" for item in result.capabilities)
    assert result.model_requests == 0


def test_symlink_root_cannot_silently_expand_access(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    result = preflight(alias)
    assert result.ready is False
    assert result.capabilities[0].reason_code == "source_root_symlink"
