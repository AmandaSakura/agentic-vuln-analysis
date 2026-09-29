"""A trusted per-response ceiling preserves proof only after full delivery."""
from dataclasses import replace
import json

import pytest

from cv_agent.domain.evidence import FixtureProofScope, ToolObservation, ValidationStatus
from cv_agent.retrieval import prompt_token_upper_bound
from cv_agent.tools.registry import AgentTool, ToolRegistry
from test_tool_execution_memory import ValueInput, _call, _scope


def _registry(size, *, limit=1000):
    executions = []
    proof = FixtureProofScope(contract_id="offline-unit", property_id="unit",
                             coverage="local", method="bounded_execution",
                             supported_statuses=(ValidationStatus.CONFIRMED,))

    def observe(arguments, scope):
        executions.append(arguments.value)
        return ToolObservation(tool="observe_value", status="ok",
                               content=json.dumps({"measured": "x" * size}),
                               validation_status=ValidationStatus.CONFIRMED, fixture_proof=proof,
                               metadata={"witness_result_status": "CONFIRMED"})

    tool = AgentTool("observe_value", "Observe one value.", ValueInput, observe,
                     content_type="json", response_token_limit=lambda scope: limit)
    return ToolRegistry((tool,), max_output_bytes=8192), executions, proof


def test_full_serialized_response_limit_includes_citation_and_typed_proof():
    registry, executions, proof = _registry(100)
    scope = _scope(tokens=8192)
    observation = registry.invoke(_call(), allowed=("observe_value",), scope=scope,
                                  citation_id="scan/tool:1")
    assert observation.status == "ok" and observation.validation_status == ValidationStatus.CONFIRMED
    assert observation.fixture_proof == proof
    assert observation.metadata["observation_truncated"] is False
    charged = prompt_token_upper_bound(registry.prompt_payload(observation))
    assert charged == observation.metadata["observation_token_count"] == scope.observed_tokens
    assert charged <= 1000
    assert observation.metadata["response_token_limit"] == 1000
    assert executions == [1]


def test_oversized_response_clears_proof_but_preserves_actual_execution_and_remaining_budget():
    registry, executions, _ = _registry(2000)
    scope = _scope(tokens=8192)
    first = registry.invoke(_call(), allowed=("observe_value",), scope=scope, citation_id="scan/tool:1")
    assert first.status == "error" and first.validation_status is first.fixture_proof is None
    assert first.metadata["observation_truncated"] is True
    assert first.metadata["witness_result_status"] == "CONFIRMED"
    assert first.metadata["observation_token_count"] <= 1000
    assert scope.remaining_tokens >= 7192 and scope.budget_exhausted is False
    repeated = registry.invoke(_call(call_id="repeat"), allowed=("observe_value",), scope=scope,
                               citation_id="scan/tool:2")
    assert repeated.status == "blocked" and repeated.fixture_proof is None
    changed = registry.invoke(_call(2), allowed=("observe_value",), scope=scope,
                              citation_id="scan/tool:3")
    assert changed.status == "error" and changed.fixture_proof is None
    assert executions == [1, 2]


def test_default_response_delivery_and_original_scope_budget_are_unchanged():
    registry, _, proof = _registry(2000, limit=None)
    scope = _scope(tokens=8192)
    observation = registry.invoke(_call(), allowed=("observe_value",), scope=scope, citation_id="scan/tool:1")
    assert observation.status == "ok" and observation.fixture_proof == proof
    assert observation.metadata["observation_token_count"] > 1000
    assert "response_token_limit" not in observation.metadata
    assert len(json.loads(observation.content)["measured"]) == 2000


def test_scope_exhaustion_still_removes_proof_before_response_cap():
    registry, _, _ = _registry(100)
    observation = registry.invoke(_call(), allowed=("observe_value",), scope=_scope(tokens=200),
                                  citation_id="scan/tool:1")
    assert observation.status != "ok"
    assert observation.validation_status is observation.fixture_proof is None
    assert observation.metadata["observation_truncated"] is True


def test_response_limit_is_trusted_policy_and_does_not_change_model_tool_schema():
    registry, _, _ = _registry(100)
    tool = registry._tools["observe_value"]
    assert tool.definition() == replace(tool, response_token_limit=None).definition()
    scope = _scope(tokens=8192)
    call = _call().model_copy(update={"arguments": {"value": 1, "response_token_limit": 999999}})
    observation = registry.invoke(call, allowed=("observe_value",), scope=scope)
    assert observation.status == "error" and observation.fixture_proof is None
    assert "invalid tool arguments" in observation.content


def test_invalid_trusted_response_limit_is_rejected():
    registry, _, _ = _registry(100, limit=0)
    with pytest.raises(ValueError, match="response token limit must be positive"):
        registry.invoke(_call(), allowed=("observe_value",), scope=_scope())


def test_schema_error_is_capped_without_poisoning_a_later_valid_call():
    registry, executions, proof = _registry(100)
    scope = _scope(tokens=8192)
    malformed = _call().model_copy(update={"arguments": {"value": "bad" * 1500}})
    rejected = registry.invoke(malformed, allowed=("observe_value",), scope=scope,
                               citation_id="scan/tool:1")
    assert rejected.status == "error" and rejected.fixture_proof is None
    assert rejected.metadata["observation_token_count"] <= 1000
    assert prompt_token_upper_bound(registry.prompt_payload(rejected)) <= 1000
    assert executions == []
    accepted = registry.invoke(_call(), allowed=("observe_value",), scope=scope,
                               citation_id="scan/tool:2")
    assert accepted.status == "ok" and accepted.fixture_proof == proof
    assert executions == [1]


def test_handler_error_also_uses_registered_response_limit():
    registry, _, _ = _registry(100)
    tool = registry._tools["observe_value"]

    def fail(arguments, scope):
        raise RuntimeError("failure " * 800)

    registry._tools["observe_value"] = replace(tool, handler=fail)
    observation = registry.invoke(_call(), allowed=("observe_value",), scope=_scope(tokens=8192),
                                  citation_id="scan/tool:1")
    assert observation.status == "error" and observation.fixture_proof is None
    assert observation.metadata["observation_token_count"] <= 1000
    assert prompt_token_upper_bound(registry.prompt_payload(observation)) <= 1000
