"""Successful execution is remembered even when its observation is clipped."""
from dataclasses import replace

import pytest

from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.types import FrozenModel
from cv_agent.tools.registry import AgentTool, ToolExecutionScope, ToolRegistry


class ValueInput(FrozenModel):
    value: int = 1


def _scope(tokens=20_000):
    return ToolExecutionScope(admitted_paths=frozenset(), max_observation_tokens=tokens)


def _call(value=1, call_id="one"):
    return ModelToolCall(call_id=call_id, name="observe_value", arguments={"value": value})


def test_truncated_success_is_not_executed_again_but_changed_arguments_and_new_task_execute():
    executions = []

    def observe(arguments, scope):
        executions.append(arguments.value)
        return ToolObservation(tool="observe_value", status="ok", content='{"value":"' + "x" * 1000 + '"}')

    tools = ToolRegistry((AgentTool("observe_value", "Observe one value.", ValueInput, observe,
                                    content_type="json"),), max_output_bytes=256)
    scope = _scope()
    first = tools.invoke(_call(), allowed=("observe_value",), scope=scope, citation_id="one")
    repeat = tools.invoke(_call(call_id="two"), allowed=("observe_value",), scope=scope, citation_id="two")
    changed = tools.invoke(_call(2, "three"), allowed=("observe_value",), scope=scope, citation_id="three")
    new_task = tools.invoke(_call(), allowed=("observe_value",), scope=_scope(), citation_id="four")
    assert first.status == changed.status == new_task.status == "error"
    assert first.metadata["observation_truncated"] is True
    assert repeat.status == "blocked"
    assert repeat.validation_status is None and repeat.fixture_proof is None
    assert "one" in repeat.content
    assert executions == [1, 2, 1]


def test_success_without_citation_is_remembered_without_inventing_a_proof_reference():
    executions = []

    def observe(arguments, scope):
        executions.append(arguments.value)
        return ToolObservation(tool="observe_value", status="ok", content="observed")

    tools = ToolRegistry((AgentTool("observe_value", "Observe one value.", ValueInput, observe),),
                         max_output_bytes=256)
    scope = _scope()
    first = tools.invoke(_call(), allowed=("observe_value",), scope=scope)
    repeat = tools.invoke(_call(call_id="two"), allowed=("observe_value",), scope=scope)
    assert first.status == "ok" and first.citation_id is None
    assert repeat.status == "blocked" and repeat.citation_id is None
    assert repeat.validation_status is None and repeat.fixture_proof is None
    assert executions == [1]


@pytest.mark.parametrize("failure", ["returned_error", "raised_error"])
def test_true_handler_errors_retain_the_existing_retry_policy(failure):
    executions = []

    def observe(arguments, scope):
        executions.append(arguments.value)
        if failure == "raised_error":
            raise RuntimeError("genuine producer error")
        return ToolObservation(tool="observe_value", status="error", content="genuine producer error")

    tools = ToolRegistry((AgentTool("observe_value", "Observe one value.", ValueInput, observe),),
                         max_output_bytes=256)
    scope = _scope()
    first = tools.invoke(_call(), allowed=("observe_value",), scope=scope, citation_id="one")
    repeat = tools.invoke(_call(call_id="two"), allowed=("observe_value",), scope=scope, citation_id="two")
    assert first.status == repeat.status == "error"
    assert executions == [1, 1]


def test_schema_rejection_does_not_execute_or_poison_a_later_valid_call():
    executions = []

    def observe(arguments, scope):
        executions.append(arguments.value)
        return ToolObservation(tool="observe_value", status="ok", content="observed")

    tools = ToolRegistry((AgentTool("observe_value", "Observe one value.", ValueInput, observe),),
                         max_output_bytes=256)
    scope = _scope()
    invalid = ModelToolCall(call_id="bad", name="observe_value", arguments={"extra": True})
    for citation in ("bad-one", "bad-two"):
        rejected = tools.invoke(invalid, allowed=("observe_value",), scope=scope, citation_id=citation)
        assert rejected.status == "error" and "invalid tool arguments" in rejected.content
    accepted = tools.invoke(_call(), allowed=("observe_value",), scope=scope, citation_id="good")
    assert accepted.status == "ok"
    assert executions == [1]


def _real_tools(index, candidate, context, *, max_output_bytes):
    from cv_agent.tools.validation.registry import full_agent_tools

    registered = next(tool for tool in full_agent_tools(index,
        witness_contexts={candidate.repository_id: context}) if tool.name == "run_bounded_execution_witness")
    calls = []

    def counted(arguments, scope):
        result = registered.handler(arguments, scope)
        calls.append(result)
        return result

    return ToolRegistry((replace(registered, handler=counted),), max_output_bytes=max_output_bytes), calls


def _real_call(tools, index, candidate, *, tokens=20_000):
    from cv_agent.tools.identity import candidate_subject

    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
                               subject=subject, max_observation_tokens=tokens)
    call = ModelToolCall(call_id="real-one", name="run_bounded_execution_witness",
                         arguments={"constructor_parameters": {}, "precondition_files": {}})
    first = tools.invoke(call, allowed=(call.name,), scope=scope, citation_id="real:first")
    return call, first, scope


@pytest.mark.parametrize("quoted", [False, True])
@pytest.mark.parametrize("delivery", ["byte_budget", "token_budget"])
def test_real_witness_execution_is_cached_after_clipping_without_admitting_proof(tmp_path, quoted, delivery):
    from test_bounded_witness_tool import _inputs, _conclude
    from test_experiment_guard import _guard, _record
    from cv_agent.evaluation.experiment_guard import ExperimentHardStop

    index, candidate, context, _ = _inputs(tmp_path / "repo", quoted=quoted)
    tools, executions = _real_tools(index, candidate, context,
        max_output_bytes=256 if delivery == "byte_budget" else 8192)
    call, first, scope = _real_call(tools, index, candidate,
        tokens=400 if delivery == "token_budget" else 20_000)
    repeat = tools.invoke(call.model_copy(update={"call_id": "real-two"}), allowed=(call.name,),
                          scope=scope, citation_id="real:repeat")
    assert first.status == "error" and first.metadata["observation_truncated"] is True
    assert first.validation_status is None and first.fixture_proof is None
    assert first.metadata["witness_attempted"] is True
    expected = "UNRESOLVED" if quoted else "CONFIRMED"
    assert first.metadata["witness_result_status"] == expected
    assert repeat.status == "blocked"
    assert repeat.validation_status is None and repeat.fixture_proof is None
    assert len(executions) == 1
    assert executions[0].metadata["witness_attempted"] is True
    with pytest.raises(ValueError):
        _conclude(call, first, scope.subject)
    with pytest.raises(ValueError):
        _conclude(call, repeat, scope.subject)
    guard = _guard(tmp_path)
    guard.bind_cell("fixed", fixed=True)
    event = {"event": "tool_result", "observation": first.model_dump(mode="json")}
    if quoted:
        _record(guard, event)
        assert guard.hard_stop is None
    else:
        with pytest.raises(ExperimentHardStop, match="S1"):
            _record(guard, event)


def test_complete_real_confirmation_remains_admitted_and_a_new_task_executes(tmp_path):
    from test_bounded_witness_tool import _inputs, _conclude

    index, candidate, context, _ = _inputs(tmp_path / "repo")
    tools, executions = _real_tools(index, candidate, context, max_output_bytes=8192)
    call, first, scope = _real_call(tools, index, candidate)
    assert first.status == "ok" and first.validation_status == "CONFIRMED"
    _conclude(call, first, scope.subject)
    repeat = tools.invoke(call, allowed=(call.name,), scope=scope, citation_id="real:repeat")
    assert repeat.status == "blocked"
    _, fresh, fresh_scope = _real_call(tools, index, candidate)
    assert fresh.status == "ok" and fresh.validation_status == "CONFIRMED"
    _conclude(call, fresh, fresh_scope.subject)
    assert len(executions) == 2
