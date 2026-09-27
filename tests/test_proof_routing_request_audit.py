"""A failed model parse must not erase the provider's reported usage."""

import json

from cv_agent.evaluation.diagnostics.audit_proof_routing_requests import audit


def test_audit_keeps_usage_when_response_has_no_parsed_reply(tmp_path):
    events = [
        {
            "event": "model_start", "request_id": "parse-failed",
            "case_id": "case-a", "system": "E4_RULE_V1", "role": "planner",
            "messages": [{"role": "user", "content": "The previous final object failed schema or evidence validation."}],
        },
        {
            "event": "model_response_received", "request_id": "parse-failed",
            "case_id": "case-a", "system": "E4_RULE_V1", "role": "planner",
            "summary": {"usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}},
        },
    ]
    (tmp_path / "events.jsonl").write_text("".join(json.dumps(item) + "\n" for item in events))

    result = audit(tmp_path)

    assert result["request_count"] == result["response_count"] == 1
    assert result["parsed_reply_count"] == 0
    assert result["missing_parsed_reply_ids"] == ["parse-failed"]
    assert result["reported_tokens"] == {
        "input_tokens": 5, "output_tokens": 3, "total_tokens": 8,
    }
    assert result["by_role"]["planner"]["purpose:schema_or_evidence_correction"] == 1
