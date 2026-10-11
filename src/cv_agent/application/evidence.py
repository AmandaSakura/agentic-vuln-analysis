"""Order-independent projections of delivered, candidate-bound tool observations."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from cv_agent.agents.evidence_policy import acceptance_decision
from cv_agent.domain.evidence import ToolObservation, ValidationStatus, ValidationSubject
from cv_agent.domain.product_result import EvidenceReceipt, FindingView, property_contract


def reduce_observations(
    subject: ValidationSubject, items: Iterable[tuple[str, ToolObservation]],
) -> tuple[FindingView, tuple[EvidenceReceipt, ...]]:
    """Use exact subjects and original producer IDs, independent of citations/votes.

    A producer ID belongs to an invocation. Reusing it with different facts is a
    protocol error. Source text and model-written status strings carry no proof.
    """
    original: dict[str, ToolObservation] = {}
    for producer, observation in items:
        if not producer:
            raise ValueError("An observation requires its original producer identity")
        if observation.subject is not None and observation.subject != subject:
            continue
        normalized = observation.model_copy(update={
            "citation_id": None,
            # Helper/source references are producer-owned facts used by the
            # shared scoping policy; only their presentation order is immaterial.
            "evidence_ids": tuple(sorted(set(observation.evidence_ids))),
        })
        if producer in original and original[producer] != normalized:
            raise ValueError("One producer identity cannot describe different observations")
        original[producer] = normalized

    receipts = []
    facts = []
    gaps = []
    contract = property_contract(subject.property_id or "undefined-property")
    for producer, observation in sorted(original.items()):
        decision = acceptance_decision(observation, subject)
        delivered, method, coverage = decision.delivered, decision.method, decision.coverage
        receipt = EvidenceReceipt(
            observation_id="observation-" + hashlib.sha256(producer.encode()).hexdigest(),
            producer_id=producer, tool=observation.tool, subject=subject,
            status=observation.status, validation_status=observation.validation_status,
            accepted_static_status=decision.accepted_static_status, method=method, coverage=coverage,
            delivered=delivered, content_sha256=hashlib.sha256(observation.content.encode()).hexdigest(),
        )
        receipts.append(receipt)
        facts.append(f"{observation.tool}: {observation.status}; original validation status "
                     f"{observation.validation_status or 'not reported'}; {coverage} scope.")
        if not receipt.supplies_proof(subject, contract):
            gaps.append(f"{receipt.observation_id}: no complete matching property proof was delivered.")
        if observation.status == "ok" and delivered:
            try:
                content = json.loads(observation.content)
            except json.JSONDecodeError:
                content = None
            # Producer-selected classifications only; do not echo arbitrary source strings.
            if isinstance(content, dict):
                state = content.get("command_construction_status")
                if state in {"SANITIZED", "UNSANITIZED", "AMBIGUOUS", "UNAVAILABLE", "NOT_ESTABLISHED"}:
                    facts.append(f"Bounded command construction: {state}.")
                if observation.tool == "validate_permission_mode":
                    if type(content.get("final_others_write")) is bool:
                        facts.append(f"Final bounded mode has others-write bit: {content['final_others_write']}.")
                    if isinstance(content.get("calls"), list):
                        facts.append(f"Collected literal chmod calls in the bounded slice: {len(content['calls'])}.")
                    if content.get("issues"):
                        gaps.append("Permission interpretation has uncovered constructs; inspect the private observation for details.")
                if observation.tool == "inspect_command_construction":
                    known_gaps = {"unmodeled_call", "definition_not_admitted", "available_definition_not_expanded", "unresolved_binding"}
                    kinds = sorted({gap.get("kind") for gap in content.get("analysis_gaps", [])
                                    if isinstance(gap, dict) and gap.get("kind") in known_gaps})
                    gaps.extend(f"Command analysis gap: {kind}." for kind in kinds)

    proofs = {item.proof_status for item in receipts if item.supplies_proof(subject, contract)}
    state = ("CONFLICT" if len(proofs) == 2 else "SUPPORTED"
             if ValidationStatus.CONFIRMED in proofs else "REFUTED"
             if ValidationStatus.REFUTED in proofs else "UNKNOWN")
    if state == "CONFLICT":
        gaps.append("Complete mutually exclusive proofs cover the same exact subject; reconcile the producers.")
    elif state == "UNKNOWN" and not receipts:
        gaps.append("No candidate-bound observation was delivered.")
    return FindingView(
        candidate_id=subject.candidate_id, subject=subject, contract=contract,
        property_state=state, evidence_refs=tuple(item.observation_id for item in receipts),
        facts=tuple(facts), missing_obligations=tuple(gaps),
        next_steps=("Review the declared source location and the unmet property obligations.",)
        if state in {"UNKNOWN", "CONFLICT"} else
        ("Assess application policy, public reachability and remote authority separately.",),
    ), tuple(receipts)
