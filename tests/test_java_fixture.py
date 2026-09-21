"""Offline Java command-boundary witnesses; model labels are never fixture inputs."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.identity import candidate_subject
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs, select_owasp_entry
from cv_agent.evaluation.protocols.development import require_verification_capability
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.evaluation.datasets.java_fixture import JavaCommandValidator, java_command_fixture_cases
from cv_agent.tools.validation import full_agent_tools


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _owasp_pair():
    inputs = load_owasp_agentic_inputs(
        PROJECT_ROOT / "data/raw",
        case_ids=("BenchmarkTest00827", "BenchmarkTest02244"),
    )
    return inputs, select_owasp_entry(inputs, "doPost")


def _invoke_fixture(registry, case_id, candidate, subject):
    return registry.invoke(
        ModelToolCall(
            call_id=f"{case_id}-fixture",
            name="run_fixture_test",
            arguments={"case_id": case_id},
        ),
        allowed=("run_fixture_test",),
        scope=ToolExecutionScope(
            admitted_paths=frozenset({candidate.path}),
            max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
            candidate_path=candidate.path,
            subject=subject,
        ),
    )


def test_java_validator_has_a_concrete_build_entrypoint():
    assert callable(JavaCommandValidator.build)


def test_java_command_fixture_confirms_and_refutes_real_owasp_pair():
    inputs, candidates = _owasp_pair()
    fixtures = java_command_fixture_cases(PROJECT_ROOT, inputs.index, candidates)
    registry = ToolRegistry(
        full_agent_tools(inputs.index, fixture_cases=fixtures),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    require_verification_capability(registry._tools.values())

    observations = {}
    for candidate in candidates:
        observations[candidate.case_id] = _invoke_fixture(
            registry,
            candidate.case_id,
            candidate,
            candidate_subject(inputs.index, candidate),
        )

    assert observations["BenchmarkTest02244"].validation_status == ValidationStatus.CONFIRMED
    assert observations["BenchmarkTest00827"].validation_status == ValidationStatus.REFUTED
    for case_id, observation in observations.items():
        assert observation.status == "ok", case_id
        payload = json.loads(observation.content)
        assert payload["details"]["process_boundary_count"] >= 1
        assert payload["details"]["stubbed_helpers"] == ["org/owasp/benchmark/helpers/Utils.java"]
        assert observation.subject == candidate_subject(
            inputs.index,
            next(candidate for candidate in candidates if candidate.case_id == case_id),
        )


def test_java_fixture_subject_mismatch_is_blocked_before_execution():
    inputs, candidates = _owasp_pair()
    safe, vulnerable = candidates
    fixtures = java_command_fixture_cases(PROJECT_ROOT, inputs.index, candidates)
    registry = ToolRegistry(
        full_agent_tools(inputs.index, fixture_cases=fixtures),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )

    observation = _invoke_fixture(
        registry,
        safe.case_id,
        vulnerable,
        candidate_subject(inputs.index, vulnerable),
    )

    assert observation.status == "blocked"
    assert observation.validation_status is None


def test_java_fixture_source_snapshot_mismatch_is_unresolved():
    inputs, candidates = _owasp_pair()
    validator = JavaCommandValidator.build(PROJECT_ROOT, inputs.index, candidates[0])
    first = replace(validator.files[0], sha256="0" * 64)
    stale = replace(validator, files=(first, *validator.files[1:]))

    outcome = stale.run()

    assert outcome.status == ValidationStatus.UNRESOLVED
    assert validator.files[0].relative_path in outcome.details["mismatches"]
