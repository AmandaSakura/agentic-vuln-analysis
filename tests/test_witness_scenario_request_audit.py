"""Private cells keep neutral detector identities from colliding in audits."""
import json

from cv_agent.evaluation.diagnostics.audit_witness_scenario_requests import audit_events, failure_diagnostics


def _events(case, origin, request_id, *, call_id="reused", content="{}"):
    common = {"case_id": "neutral-entry", "system": "E1",
              "evaluation_case_id": case, "scenario_origin": origin}
    call = {"call_id": call_id, "name": "run_bounded_execution_witness", "arguments": {
        "scenario_hypothesis": {"input_parameter": {"value": "path",
            "classification": "attacker_controlled_input", "rationale": "Caller input."}}}}
    return [
        {**common, "event": "model_start", "role": "scan", "request_id": request_id},
        {**common, "event": "model_response_received", "role": "scan", "request_id": request_id,
         "summary": {"model": "test-model", "id": request_id, "usage": {"total_tokens": 7}}},
        {**common, "event": "model_reply", "role": "scan", "request_id": request_id,
         "reply": {"model_id": "test-model", "tool_calls": [call]}},
        {**common, "event": "tool_start", "citation_id": "scan:1", "call": call,
         "time": "2026-09-29T00:00:00+00:00"},
        {**common, "event": "tool_result", "time": "2026-09-29T00:00:03+00:00", "observation": {
         "tool": call["name"], "citation_id": "scan:1", "status": "ok",
         "validation_status": "UNRESOLVED", "metadata": {"witness_attempted": True}, "content": content}},
    ]


def test_reused_ids_are_attributed_per_private_cell_and_latest_reply():
    events = _events("case-a", "dataset_provided", "one")
    events += _events("case-a", "model_proposed", "two")
    events += _events("case-a", "model_proposed", "three")
    result = audit_events(events, [])
    assert result["request_count"] == 3
    assert result["reported_total_tokens"] == 21
    assert [request["tool_outcomes"][0]["request_id"] for request in result["requests"]] == ["one", "two", "three"]
    assert [request["tool_outcomes"][0]["elapsed_seconds"] for request in result["requests"]] == [3, 3, 3]
    assert len(result["by_cell"]) == 2
    assert [item["scenario_hypothesis"]["input_parameter"]["classification"]
            for item in result["scenario_proposals"]] == ["attacker_controlled_input"] * 3


def test_parse_failure_keeps_all_usage_fields_and_actual_returned_model():
    events = _events("case-a", "model_proposed", "one")[:2]
    events[1]["summary"]["usage"] = {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7,
                                      "prompt_cache_hit_tokens": 3}
    events += [{**events[0], "event": "model_invalid_response"}]
    result = audit_events(events, [])
    request = result["requests"][0]
    assert request["parsed_reply"] is False
    assert request["invalid_response"] is True
    assert request["reported_usage"][0]["prompt_cache_hit_tokens"] == 3
    assert request["returned_model_ids"] == ["test-model"]
    assert result["reported_total_tokens"] == 7


def test_schema_rejected_scenarios_are_preserved_without_normalization():
    events = _events("case-a", "model_proposed", "one")
    events[-2]["call"]["arguments"]["scenario_hypothesis"] = {"not_the_schema": ["exact", "original"]}
    events[-1]["observation"].update(status="error", validation_status=None,
                                     content="invalid tool arguments: required classification missing")
    result = audit_events(events, [])
    assert result["scenario_proposals"][0]["scenario_hypothesis"] == {"not_the_schema": ["exact", "original"]}
    assert result["tool_timeline"][0]["schema_rejected"] is True


def test_semantic_wrong_or_unsupported_premise_is_f3_not_resource_failure():
    row = {"status": "abstained", "predicted_label": "ABSTAIN", "verdict": None}
    timeline = [{"tool": "run_bounded_execution_witness", "schema_rejected": False,
                 "observation": {"status": "ok", "validation_status": "UNRESOLVED", "metadata": {}},
                 "payload": {"classification_status": "complete", "scenario_origin": "model_proposed",
                             "gaps": ["preempted_by_unrelated_command_event", "constructor_parameter_missing:setting"]}}]
    result = failure_diagnostics(row, timeline)
    assert result["primary"] == "F3"
    assert "F4" not in result["contributors"]
    assert result["gaps"] == timeline[0]["payload"]["gaps"]


def test_explicit_timeout_is_f4_and_confirmed_not_accepted_is_f5():
    row = {"status": "abstained", "predicted_label": "ABSTAIN", "verdict": None}
    timeout = [{"tool": "run_bounded_execution_witness", "schema_rejected": False,
                "observation": {"status": "ok", "validation_status": "UNRESOLVED", "metadata": {}},
                "payload": {"gaps": ["worker_timeout"]}}]
    assert failure_diagnostics(row, timeout)["primary"] == "F4"
    confirmed = [{"tool": "run_bounded_execution_witness", "schema_rejected": False,
                  "observation": {"status": "ok", "validation_status": "CONFIRMED", "metadata": {}},
                  "payload": {"gaps": []}}]
    assert failure_diagnostics(row, confirmed)["primary"] == "F5"
    row["predicted_label"] = "VULNERABLE"
    assert failure_diagnostics(row, confirmed)["qualified_success"] is True
    assert failure_diagnostics(row, confirmed)["primary"] is None


def test_f1_f2_and_authorization_budget_f6_are_factual_separate_diagnostics():
    row = {"status": "failed", "predicted_label": None, "verdict": None}
    assert failure_diagnostics(row, [])["primary"] == "F1"
    rejected = [{"tool": "run_bounded_execution_witness", "schema_rejected": True,
                 "observation": {"status": "error", "metadata": {}}, "payload": None}] * 2
    assert failure_diagnostics(row, rejected)["primary"] == "F2"
    row.update(error_type="ExperimentHardStop", error="S3: request ceiling")
    assert failure_diagnostics(row, [])["primary"] == "F6"
