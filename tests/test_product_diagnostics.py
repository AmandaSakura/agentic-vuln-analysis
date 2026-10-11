import json
import subprocess
import sys

from cv_agent.application.diagnostics import doctor, observation_diagnosis
from cv_agent.application.controller import ReviewTask, TaskController
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.validation_protocol import ValidationPreparation, MissingValidationInput


def completed():
    return ToolObservation(tool="owned-static", status="ok", content="constant",
                           validation_status="UNRESOLVED")


def test_doctor_never_exposes_configured_secret_or_calls_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("CV_AGENT_MODEL_API_KEY", "fake-private-key-do-not-display")
    result = doctor(tmp_path)
    assert result["ready"]
    assert result["model_requests"] == 0
    assert result["configuration_presence"]["api_key_env"] is True
    assert "fake-private-key" not in json.dumps(result)
    cli = subprocess.run([sys.executable, "-c", "from cv_agent.cli import main; raise SystemExit(main())",
                          "doctor", str(tmp_path)], capture_output=True, text=True, timeout=30)
    assert cli.returncode == 0, cli.stderr
    assert json.loads(cli.stdout)["model_requests"] == 0


def test_missing_environment_is_not_model_failure_and_unresolved_is_finished():
    environment = observation_diagnosis(ToolObservation(tool="owned-static", status="blocked",
        content="private error text", metadata={"capability_missing": True}), "owned")
    assert environment.owner == "environment"
    assert environment.experiment_failure_class == "F4"
    assert "private error" not in environment.message
    assert observation_diagnosis(completed(), "owned") is None


def test_waiting_for_explicit_input_then_resume_without_fabrication():
    calls = []
    task = ReviewTask(task_id="owned", required_inputs=("declared_policy",))
    controller = TaskController((task,), {"owned": lambda values: calls.append(dict(values)) or completed()})
    state = controller.advance()["owned"]
    assert state.state == "WAITING_INPUT"
    assert state.validator_completed is False and not calls
    assert state.diagnosis.owner == "user"
    controller.supply("owned", {"declared_policy": "approved constant policy"})
    state = controller.advance()["owned"]
    assert state.state == "FINISHED" and state.validator_completed
    assert len(calls) == 1
    controller.advance()
    assert len(calls) == 1


def test_preparation_is_waiting_and_never_validator_completion():
    preparation = ValidationPreparation(mode="dataset_provided", action="complete_call_data",
        missing_inputs=(MissingValidationInput(name="policy", destination="approved", classified=False),))
    controller = TaskController((ReviewTask(task_id="owned"),), {"owned": lambda _: ToolObservation(
        tool="owned-static", status="ok", content="preparation", validation_status="UNRESOLVED",
        metadata={"validation_preparation": preparation.model_dump(mode="json")})})
    result = controller.advance()["owned"]
    assert result.state == "WAITING_INPUT"
    assert result.protocol_complete and not result.validator_completed
    assert result.diagnosis.required_input == ("approved.policy",)


def test_optional_failure_preserves_independent_static_task_and_real_data_dependency_blocks():
    calls = []
    tasks = (ReviewTask(task_id="optional", available=False), ReviewTask(task_id="static"),
             ReviewTask(task_id="dependent", dependencies=("optional",)))
    controller = TaskController(tasks, {"static": lambda _: calls.append("static") or completed(),
                                       "dependent": lambda _: calls.append("dependent") or completed()})
    states = controller.advance()
    assert states["optional"].state == states["dependent"].state == "BLOCKED"
    assert states["static"].state == "FINISHED"
    assert calls == ["static"]


def test_completed_unknown_unlocks_dependency_and_invalid_progress_is_bounded():
    calls = []
    controller = TaskController((ReviewTask(task_id="a"), ReviewTask(task_id="b", dependencies=("a",))),
        {"a": lambda _: calls.append("a") or completed(), "b": lambda _: calls.append("b") or completed()})
    assert all(state.validator_completed for state in controller.advance().values())
    assert calls == ["a", "b"]
    for _ in range(20): controller.advance()
    assert calls == ["a", "b"]


def test_repeated_invalid_supplement_terminates_at_fixed_limit():
    controller = TaskController((ReviewTask(task_id="owned", required_inputs=("policy",)),),
        {"owned": lambda _: completed()}, invalid_action_limit=2)
    controller.advance()
    controller.supply("owned", {"wrong": True})
    controller.supply("owned", {"wrong": True})
    state = controller.advance()["owned"]
    assert state.state == "FAILED"
    assert state.diagnosis.reason_code == "invalid_input_limit"
    assert len(controller.events) >= 2


def test_explicit_supplement_also_unlocks_real_data_dependents():
    calls = []
    tasks = (ReviewTask(task_id="a", required_inputs=("policy",)),
             ReviewTask(task_id="b", dependencies=("a",)))
    controller = TaskController(tasks, {key: lambda _, key=key: calls.append(key) or completed()
                                       for key in ("a", "b")})
    assert controller.advance()["b"].state == "BLOCKED"
    controller.supply("a", {"policy": "approved constant"})
    states = controller.advance()
    assert states["b"].state == "FINISHED"
    assert calls == ["a", "b"]
