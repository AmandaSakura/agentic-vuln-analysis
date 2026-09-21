import pytest

from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentRuntimeMode, AgentSystemVersion, validate_full_system_harness


def test_full_system_harness_requires_live_claims_and_three_react_experts():
    validate_full_system_harness()

    assert FULL_SYSTEM_HARNESS.claim_runtime_mode == AgentRuntimeMode.LIVE
    assert {expert.expert for expert in FULL_SYSTEM_HARNESS.experts} == {
        "scan",
        "taint",
        "authz",
    }
    assert all(expert.require_react_trace for expert in FULL_SYSTEM_HARNESS.experts)
    assert {"python", "typescript", "javascript", "go"}.issubset(
        FULL_SYSTEM_HARNESS.tier1_languages
    )
    assert all(
        suffix.startswith(".") for suffix in FULL_SYSTEM_HARNESS.fallback_suffixes
    )
    executable_tools = {
        tool
        for expert in FULL_SYSTEM_HARNESS.experts
        for tool in expert.tools
    }
    assert set(FULL_SYSTEM_HARNESS.validation.validators) <= executable_tools


def test_full_system_e4_e5_share_everything_except_scheduling():
    e4 = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    e5 = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E5_GRAPH_FAST)

    assert e4.retrieval == e5.retrieval
    assert e4.budget == e5.budget
    assert e4.expert_order == e5.expert_order
    assert e4.full_review_policy == e5.full_review_policy
    assert e4.early_quorum_after is None
    assert e5.early_quorum_after == 2


def test_full_system_rejects_scripted_claim_runtime():
    invalid = FULL_SYSTEM_HARNESS.model_copy(
        update={"claim_runtime_mode": AgentRuntimeMode.SCRIPTED}
    )

    with pytest.raises(ValueError, match="only live model runs"):
        validate_full_system_harness(invalid)


def test_full_system_rejects_expert_without_tool_trace():
    scan = FULL_SYSTEM_HARNESS.experts[0].model_copy(
        update={"require_react_trace": False}
    )
    invalid = FULL_SYSTEM_HARNESS.model_copy(
        update={"experts": (scan, *FULL_SYSTEM_HARNESS.experts[1:])}
    )

    with pytest.raises(ValueError, match="lacks a mandate, tools, or ReAct"):
        validate_full_system_harness(invalid)


def test_full_system_rejects_validator_with_no_executable_owner():
    invalid_validation = FULL_SYSTEM_HARNESS.validation.model_copy(
        update={
            "validators": (
                *FULL_SYSTEM_HARNESS.validation.validators,
                "orphan_validator",
            )
        }
    )
    invalid = FULL_SYSTEM_HARNESS.model_copy(
        update={"validation": invalid_validation}
    )

    with pytest.raises(ValueError, match="owned by an executable expert"):
        validate_full_system_harness(invalid)
