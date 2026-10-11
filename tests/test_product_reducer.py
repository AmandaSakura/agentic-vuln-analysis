"""Deterministic property reduction uses runtime observations, not model votes."""
import pytest
import json

from cv_agent.application.evidence import reduce_observations
from cv_agent.domain.evidence import FixtureProofScope, ToolObservation, ValidationSubject


def subject():
    return ValidationSubject(candidate_id="owned", repository_id="owned", entry_path="entry.py",
        entry_line=1, source_digest="a"*64, property_id="chmod-mode-others-write",
        analysis_scope="The selected owned statement's mode.")


def proof(status, *, selected=None, citation="proof"):
    selected=subject() if selected is None else selected
    return ToolObservation(tool="run_fixture_test",status="ok",content='{"owned":true}',
        subject=selected,citation_id=citation,validation_status=status,
        fixture_proof=FixtureProofScope(contract_id="owned-constant-mode",property_id=selected.property_id,
            coverage="candidate",method="complete_static_analysis",supported_statuses=("CONFIRMED","REFUTED")))


@pytest.mark.parametrize("reverse",[False,True])
def test_conflicting_complete_proofs_are_order_independent(reverse):
    items=[("producer/1",proof("CONFIRMED")),("producer/2",proof("REFUTED",citation="counter"))]
    if reverse: items.reverse()
    finding,receipts=reduce_observations(subject(),items)
    assert finding.property_state == "CONFLICT"
    assert len(receipts)==2
    assert finding.application_security == "NOT_ASSESSED"


def test_unknown_and_unrelated_observations_cannot_erase_support():
    unrelated=subject().model_copy(update={"candidate_id":"other"})
    unknown=proof("UNRESOLVED",citation="unknown")
    finding,receipts=reduce_observations(subject(),[
        ("producer/1",proof("CONFIRMED")),("producer/2",unknown),
        ("producer/3",proof("REFUTED",selected=unrelated,citation="unrelated"))])
    assert finding.property_state == "SUPPORTED"
    assert len(receipts)==2


def test_aliases_of_one_producer_do_not_add_an_observation():
    observed=proof("CONFIRMED")
    aliases=[("producer/1",observed.model_copy(update={"citation_id":f"role/{role}"}))
             for role in ("scan","taint","authz")]
    finding,receipts=reduce_observations(subject(),aliases)
    assert finding.property_state == "SUPPORTED"
    assert len(receipts)==1
    assert len(finding.evidence_refs)==1


def test_reused_producer_identity_with_different_facts_is_an_explicit_error():
    with pytest.raises(ValueError,match="producer"):
        reduce_observations(subject(),[("same",proof("CONFIRMED")),("same",proof("REFUTED"))])


@pytest.mark.parametrize("kind",["clipped","suppressed","error","local","pattern"])
def test_incomplete_or_local_facts_never_support_candidate(kind):
    observed=proof("CONFIRMED")
    if kind=="clipped": observed=observed.model_copy(update={"metadata":{"observation_truncated":True}})
    elif kind=="suppressed": observed=observed.model_copy(update={"metadata":{"model_payload_suppressed":True}})
    elif kind=="error": observed=observed.model_copy(update={"status":"error"})
    else:
        scope=observed.fixture_proof.model_copy(update={"coverage":"local"} if kind=="local" else {"method":"source_pattern"})
        observed=observed.model_copy(update={"fixture_proof":scope})
    finding,receipts=reduce_observations(subject(),[("producer/1",observed)])
    assert finding.property_state == "UNKNOWN"
    assert len(receipts)==1


def test_status_text_is_data_not_authoritative_validation():
    observed=ToolObservation(tool="run_static_check",status="ok",content='{"status":"CONFIRMED"}',
        subject=subject(),validation_status="UNRESOLVED")
    finding,receipts=reduce_observations(subject(),[("producer/1",observed)])
    assert finding.property_state == "UNKNOWN"
    assert receipts[0].method == "source_pattern"


def test_local_counterfact_does_not_cancel_a_complete_supported_property():
    local = proof("REFUTED", citation="local").model_copy(update={"fixture_proof": proof("REFUTED").fixture_proof.model_copy(
        update={"coverage": "local"})})
    finding, receipts = reduce_observations(subject(), [("whole/1", proof("CONFIRMED")), ("local/1", local)])
    assert finding.property_state == "SUPPORTED"
    assert len(receipts) == 2


def test_reduction_preserves_producer_owned_helper_references_used_by_shared_admission():
    selected = subject().model_copy(update={"property_id": "command-execution", "entry_line": 1,
        "input_parameters": ("value",), "analysis_scope": "The complete declared owned function."})
    observed = ToolObservation(tool="inspect_command_construction", status="ok", subject=selected,
        validation_status="UNRESOLVED", evidence_ids=("command_helper:owned_helper.py",),
        content=json.dumps({"source_path": "entry.py", "function_header_lines": [1],
            "source_line_count": 3, "issues": [], "helpers": [], "sink_facts": [
                {"path": "owned_helper.py", "line": 1, "status": "UNSANITIZED"}]}))
    finding, receipts = reduce_observations(selected, [("owned/1", observed)])
    assert finding.property_state == "SUPPORTED"
    assert receipts[0].validation_status == "UNRESOLVED"
    assert receipts[0].accepted_static_status == "CONFIRMED"
