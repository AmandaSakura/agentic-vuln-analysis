"""Product properties never become application-security claims."""
import pytest

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.product_result import (
    EvidenceReceipt, FindingView, IdentityBundle, ReviewAccounting,
    ReviewCounts, ReviewResult, property_contract,
)


def example_result(property_state="UNKNOWN"):
    subject = ValidationSubject(
        candidate_id="owned-mode", repository_id="owned-source", entry_path="entry.py",
        entry_line=2, source_digest="a" * 64, property_id="chmod-mode-others-write",
        analysis_scope="The mode at this declared statement.",
    )
    receipt = EvidenceReceipt(
        observation_id="owned-observation", producer_id="owned-run/1",
        tool="validate_permission_mode", subject=subject, status="ok",
        validation_status="UNRESOLVED" if property_state == "UNKNOWN" else "CONFIRMED", method="complete_static_analysis",
        coverage="candidate", delivered=True, content_sha256="b" * 64,
        source_identity="a" * 64, analysis_contract_digest="c" * 64,
    )
    finding = FindingView(
        candidate_id=subject.candidate_id, subject=subject,
        contract=property_contract(subject.property_id), property_state=property_state,
        evidence_refs=(receipt.observation_id,), facts=("The selected mode was inspected.",),
    )
    return ReviewResult(
        run_id="owned-run", run_state="COMPLETED",
        identity=IdentityBundle(source_digest="a" * 64, analysis_contract_digest="c" * 64,
                                retrieval_view_revision="d" * 64),
        findings=(finding,), evidence_receipts=(receipt,),
        counts=ReviewCounts(source_files=1, parsed_files=1, candidate_count=1,
                           sufficient_evidence_candidates=int(property_state != "UNKNOWN")),
        accounting=ReviewAccounting(),
    )


@pytest.mark.parametrize("state", ["UNKNOWN", "SUPPORTED"])
def test_unknown_round_trip_keeps_application_unassessed(state):
    result = example_result(state)
    assert ReviewResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings[0].application_security == "NOT_ASSESSED"
    assert result.findings[0].remote_authority_evaluated is False
    assert result.findings[0].public_entry_evaluated is False
    assert result.accounting.model_requests == 0
    assert result.counts.candidate_count == 1


@pytest.mark.parametrize("field,value", [
    ("candidate_id", "other"), ("property_id", "dynamic-evaluation"),
    ("entry_line", 3), ("source_digest", "e" * 64),
    ("analysis_scope", "A different complete scope."),
])
def test_strong_state_rejects_receipt_for_another_subject(field, value):
    data = example_result("SUPPORTED").model_dump(mode="json")
    data["evidence_receipts"][0]["subject"][field] = value
    with pytest.raises(ValueError, match="subject"):
        ReviewResult.model_validate(data)


@pytest.mark.parametrize("field,value", [
    ("method", "source_pattern"), ("method", "source_read"),
    ("coverage", "local"), ("delivered", False), ("status", "error"),
    ("validation_status", "UNRESOLVED"),
])
def test_incomplete_or_pattern_receipt_cannot_support_property(field, value):
    data = example_result("SUPPORTED").model_dump(mode="json")
    data["evidence_receipts"][0][field] = value
    with pytest.raises(ValueError, match="proof"):
        ReviewResult.model_validate(data)


def test_unknown_schema_and_unsupported_application_claims_rejected():
    data = example_result().model_dump(mode="json")
    data["schema_version"] = "unrecognized-v9"
    with pytest.raises(ValueError):
        ReviewResult.model_validate(data)
    data = example_result().model_dump(mode="json")
    data["findings"][0]["application_security"] = "SAFE"
    with pytest.raises(ValueError):
        ReviewResult.model_validate(data)


def test_missing_reference_and_wrong_predicate_rejected():
    data = example_result().model_dump(mode="json")
    data["findings"][0]["evidence_refs"] = ["invented"]
    with pytest.raises(ValueError, match="reference"):
        ReviewResult.model_validate(data)
    data = example_result().model_dump(mode="json")
    data["findings"][0]["contract"]["property_id"] = "dynamic-evaluation"
    with pytest.raises(ValueError, match="property"):
        ReviewResult.model_validate(data)


def test_refuted_requires_matching_negative_proof():
    data = example_result("SUPPORTED").model_dump(mode="json")
    data["findings"][0]["property_state"] = "REFUTED"
    with pytest.raises(ValueError, match="proof"):
        ReviewResult.model_validate(data)
    data["evidence_receipts"][0]["validation_status"] = "REFUTED"
    result = ReviewResult.model_validate(data)
    assert result.findings[0].property_state == "REFUTED"
    assert result.findings[0].application_security == "NOT_ASSESSED"


def test_unrecognized_proof_version_is_rejected():
    data = example_result("SUPPORTED").model_dump(mode="json")
    data["evidence_receipts"][0]["method_version"] = "unknown-v99"
    with pytest.raises(ValueError, match="method_version"):
        ReviewResult.model_validate(data)


def test_completed_review_cannot_hide_required_blocked_capability():
    data = example_result().model_dump(mode="json")
    data["capabilities"] = [dict(language="python", method="source_index", required=True,
        state="BLOCKED", reason_code="source_missing", detail="Source is unavailable.")]
    with pytest.raises(ValueError, match="capability"):
        ReviewResult.model_validate(data)


@pytest.mark.parametrize("field", ["source_identity", "analysis_contract_digest"])
def test_proof_receipt_from_another_product_identity_is_rejected(field):
    data = example_result("SUPPORTED").model_dump(mode="json")
    data["evidence_receipts"][0][field] = "e" * 64
    with pytest.raises(ValueError, match="identity"):
        ReviewResult.model_validate(data)


def test_final_unknown_cannot_erase_a_delivered_complete_proof():
    data = example_result("SUPPORTED").model_dump(mode="json")
    data["findings"][0]["property_state"] = "UNKNOWN"
    with pytest.raises(ValueError, match="proof"):
        ReviewResult.model_validate(data)


@pytest.mark.parametrize("run_state", ["COMPLETED", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"])
@pytest.mark.parametrize("property_state", ["UNKNOWN", "SUPPORTED", "REFUTED", "CONFLICT"])
def test_legal_run_and_property_states_round_trip_independently(run_state, property_state):
    data = example_result("SUPPORTED" if property_state != "UNKNOWN" else "UNKNOWN").model_dump(mode="json")
    data["run_state"] = run_state
    data["findings"][0]["property_state"] = property_state
    if property_state == "REFUTED":
        data["evidence_receipts"][0]["validation_status"] = "REFUTED"
    elif property_state == "CONFLICT":
        opposing = dict(data["evidence_receipts"][0], observation_id="owned-counterproof",
                        producer_id="owned-run/2", validation_status="REFUTED")
        data["evidence_receipts"].append(opposing)
        data["findings"][0]["evidence_refs"].append("owned-counterproof")
    result = ReviewResult.model_validate(data)
    assert ReviewResult.model_validate_json(result.model_dump_json()) == result


def test_result_counters_cannot_invent_processed_or_proved_candidates():
    data = example_result().model_dump(mode="json")
    data["counts"]["validated_candidates"] = 2
    with pytest.raises(ValueError, match="count"):
        ReviewResult.model_validate(data)
    data = example_result().model_dump(mode="json")
    data["counts"]["sufficient_evidence_candidates"] = 1
    with pytest.raises(ValueError, match="count"):
        ReviewResult.model_validate(data)
