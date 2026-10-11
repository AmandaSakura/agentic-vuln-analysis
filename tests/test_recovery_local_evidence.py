"""Local material evidence is complete even when model delivery is partial.

The two-proof inputs are controlled consumer injections, not a claim that the
original v1 service normally produced two observations for one candidate.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

from cv_agent.agents.evidence_policy import acceptance_decision, validate_conclusion
from cv_agent.application.delivery import CertificateDelivery, DeliveryBudgetError, allocation_plan
from cv_agent.application.evidence import reduce_observations
from cv_agent.application.local_evidence import (EvidenceStore, LocalEvidenceBudgetError,
    LocalEvidenceError, complete_local_observations, read_descriptor)
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import FixtureProofScope, ReActStep, ToolObservation, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion


def subject():
    return ValidationSubject(candidate_id="owned-mode", repository_id="owned-source", entry_path="entry.py",
        entry_line=1, source_digest="a" * 64, property_id="chmod-mode-others-write",
        analysis_scope="The selected owned statement's bounded mode.")


def proof(status="CONFIRMED", *, selected=None, citation="owned-tool"):
    selected = subject() if selected is None else selected
    return ToolObservation(tool="run_fixture_test", status="ok", content='{"owned":true}',
        subject=selected, citation_id=citation, validation_status=status,
        fixture_proof=FixtureProofScope(contract_id="owned-mode-contract", property_id=selected.property_id,
            coverage="candidate", method="complete_static_analysis", supported_statuses=("CONFIRMED", "REFUTED")))


def context():
    return {"run_id": "owned-local-run", "source_identity": "a" * 64,
            "analysis_contract_digest": "b" * 64}


def certificate(producer, observation, size=4000):
    def serialize(value):
        return json.dumps({"producer_id": producer, "observation": value.model_dump(mode="json")},
                          sort_keys=True, separators=(",", ":")).encode()
    observed = observation.model_copy(update={"content": json.dumps({"owned": True, "padding": ""})})
    padding = size - len(serialize(observed))
    assert padding >= 0
    observed = observed.model_copy(update={"content": json.dumps({"owned": True, "padding": "x" * padding})})
    payload = serialize(observed)
    assert len(payload) == size
    return observed, payload


@pytest.mark.parametrize("reverse", [False, True])
def test_full_local_conflict_survives_only_one_model_delivery(tmp_path, reverse):
    pairs = [("owned/positive", proof()), ("owned/negative", proof("REFUTED", citation="owned-counter"))]
    if reverse:
        pairs.reverse()
    store = EvidenceStore(tmp_path / "records")
    delivery = CertificateDelivery(allocation_plan({}, total_bytes=8192, diagnostic_reserve=256))
    delivered = []
    for producer, original in pairs:
        observed, payload = certificate(producer, original)
        store.persist(producer, observed, context=context())
        delivery.store(producer, payload, physical_execution=False)
        try:
            delivery.deliver(producer)
        except DeliveryBudgetError:
            continue
        delivered.append((producer, observed))
    assert len(delivered) == 1
    assert delivery.used_bytes == 4000
    # This control documents the subset projection's insufficient semantics.
    subset, _ = reduce_observations(subject(), delivered)
    assert subset.property_state in {"SUPPORTED", "REFUTED"}
    local, receipts = reduce_observations(subject(), store.observations(subject()))
    assert local.property_state == "CONFLICT"
    assert len(receipts) == 2
    assert len(store.descriptors) == 2


def test_record_persists_exact_original_and_context_with_private_permissions(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    observed = proof()
    descriptor = store.persist("owned/1", observed, context=context())
    path = Path(descriptor["path"])
    payload = path.read_bytes()
    assert descriptor["sha256"] == hashlib.sha256(payload).hexdigest()
    assert descriptor["size_bytes"] == len(payload) == store.used_bytes
    assert descriptor["observation"] == observed.model_dump(mode="json")
    assert json.loads(payload)["context"] == context()
    assert descriptor["content_sha256"] == hashlib.sha256(observed.content.encode()).hexdigest()
    assert store.read_descriptor(descriptor, subject=subject(), context=context()) == ("owned/1", observed)
    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("problem", ["missing", "truncated", "edited", "symlink"])
def test_unverifiable_material_file_blocks_one_sided_strong_projection(tmp_path, problem):
    store = EvidenceStore(tmp_path / "records")
    store.persist("owned/positive", proof(), context=context())
    missing = store.persist("owned/negative", proof("REFUTED"), context=context())
    path = Path(missing["path"])
    if problem == "missing":
        path.unlink()
    elif problem == "truncated":
        path.write_bytes(path.read_bytes()[:-1])
    elif problem == "edited":
        path.write_bytes(path.read_bytes().replace(b"REFUTED", b"REFUTEZ"))
    else:
        original = path.read_bytes()
        path.unlink()
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_bytes(original)
        path.symlink_to(elsewhere)
    with pytest.raises(LocalEvidenceError):
        store.observations(subject())


@pytest.mark.parametrize("field,value", [
    ("producer_id", "different-owned-producer"), ("sha256", "f" * 64),
    ("content_sha256", "f" * 64), ("context_sha256", "f" * 64),
    ("size_bytes", 1), ("version", "unknown-local-v9"),
    ("subject", None), ("context", {"run_id": "wrong-run"}),
    ("observation", {"tool": "fabricated"}),
])
def test_descriptor_mismatch_is_rejected(tmp_path, field, value):
    store = EvidenceStore(tmp_path / "records")
    descriptor = store.persist("owned/1", proof(), context=context())
    descriptor[field] = value
    with pytest.raises(LocalEvidenceError):
        store.read_descriptor(descriptor, subject=subject(), context=context())


def test_subject_or_context_from_another_analysis_cannot_supply_proof(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    descriptor = store.persist("owned/1", proof(), context=context())
    with pytest.raises(LocalEvidenceError, match="subject"):
        store.read_descriptor(descriptor, subject=subject().model_copy(update={"entry_line": 2}))
    with pytest.raises(LocalEvidenceError, match="context"):
        store.read_descriptor(descriptor, context={"run_id": "different-analysis"})


def test_unknown_extra_record_or_observation_fields_are_rejected_even_with_rehashed_bytes(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    descriptor = store.persist("owned/1", proof(), context=context())
    path = Path(descriptor["path"])
    record = json.loads(path.read_bytes())
    record["observation"]["unregistered_proof"] = "CONFIRMED"
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(payload)
    descriptor.update(sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload),
                      observation=record["observation"])
    with pytest.raises(LocalEvidenceError, match="original schema"):
        store.read_descriptor(descriptor)


def test_duplicate_json_keys_are_not_an_unambiguous_original_record(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    descriptor = store.persist("owned/1", proof(), context=context())
    path = Path(descriptor["path"])
    payload = path.read_bytes().replace(b'"producer_id":"owned/1"',
        b'"producer_id":"ignored-owned","producer_id":"owned/1"')
    path.write_bytes(payload)
    descriptor.update(sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload))
    with pytest.raises(LocalEvidenceError, match="duplicate field"):
        store.read_descriptor(descriptor)


def test_aliases_and_duplicate_descriptors_preserve_one_original_producer(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    observed = proof().model_copy(update={"evidence_ids": ("helper:b", "helper:a", "helper:a")})
    original = store.persist("owned/1", observed, context=context())
    alias = store.persist("owned/1", observed.model_copy(update={"citation_id": "presentation-alias",
        "evidence_ids": ("helper:a", "helper:b")}), context=context())
    assert alias == original
    assert len(store.descriptors) == 1
    complete = complete_local_observations(subject(), [original, alias], expected_producers={"owned/1"})
    assert complete == (("owned/1", observed),)
    finding, receipts = reduce_observations(subject(), complete)
    assert finding.property_state == "SUPPORTED" and len(receipts) == 1


def test_same_producer_cannot_change_original_payload_or_context(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    original = store.persist("owned/1", proof(), context=context())
    with pytest.raises(LocalEvidenceError, match="producer"):
        store.persist("owned/1", proof("REFUTED"), context=context())
    assert json.loads(Path(original["path"]).read_bytes())["observation"]["validation_status"] == "CONFIRMED"
    assert store.incomplete_producers == ("owned/1",)
    with pytest.raises(LocalEvidenceError, match="identity conflicts"):
        store.observations(subject())


def test_same_producer_cannot_be_rebound_to_another_context(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    store.persist("owned/1", proof(), context=context())
    with pytest.raises(LocalEvidenceError, match="context"):
        store.persist("owned/1", proof(), context={"run_id": "changed-run"})
    assert store.incomplete_producers == ("owned/1",)
    with pytest.raises(LocalEvidenceError, match="identity conflicts"):
        store.observations(subject())


def test_duplicate_producer_from_different_files_cannot_hide_different_facts(tmp_path):
    first = EvidenceStore(tmp_path / "first").persist("same-producer", proof(), context=context())
    second = EvidenceStore(tmp_path / "second").persist("same-producer", proof("REFUTED"), context=context())
    with pytest.raises(LocalEvidenceError, match="producer"):
        complete_local_observations(subject(), [first, second])


def test_complete_unknown_and_unrelated_facts_do_not_erase_sufficient_positive(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    store.persist("owned/positive", proof(), context=context())
    store.persist("owned/unknown", proof("UNRESOLVED"), context=context())
    store.persist("owned/unrelated", proof("REFUTED", selected=subject().model_copy(
        update={"candidate_id": "another-owned-candidate"})), context=context())
    finding, receipts = reduce_observations(subject(), store.observations(subject()))
    assert finding.property_state == "SUPPORTED"
    assert len(receipts) == 2


def test_missing_expected_descriptor_is_a_material_inventory_gap(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    descriptor = store.persist("owned/positive", proof(), context=context())
    with pytest.raises(LocalEvidenceError, match="inventory"):
        complete_local_observations(subject(), [descriptor], expected_producers={"owned/positive", "owned/negative"})


def test_record_quota_failure_is_not_replaced_by_a_summary_or_one_sided_result(tmp_path):
    store = EvidenceStore(tmp_path / "records", max_bytes=3000)
    descriptor = store.persist("owned/positive", proof(), context=context())
    oversized = proof("REFUTED").model_copy(update={"content": "x" * 4000})
    with pytest.raises(LocalEvidenceBudgetError):
        store.persist("owned/negative", oversized, context=context())
    assert len(store.descriptors) == 1
    assert store.incomplete_producers == ("owned/negative",)
    assert Path(descriptor["path"]).is_file()
    with pytest.raises(LocalEvidenceError, match="inventory"):
        store.observations(subject())


def test_sync_failure_returns_no_descriptor_or_completed_false_success(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "records")

    def failed_sync(_):
        raise OSError(errno.EIO, "owned local-record sync failure")

    monkeypatch.setattr(os, "fsync", failed_sync)
    with pytest.raises(OSError, match="owned local-record sync failure"):
        store.persist("owned/1", proof(), context=context())
    assert store.descriptors == ()
    assert list(store.directory.iterdir()) == []
    assert store.incomplete_producers == ("owned/1",)
    with pytest.raises(LocalEvidenceError, match="inventory"):
        store.observations(subject())


def test_record_write_failure_returns_no_descriptor_and_retains_inventory_gap(tmp_path, monkeypatch):
    from cv_agent.application import local_evidence
    store = EvidenceStore(tmp_path / "records")
    fdopen = os.fdopen

    class FailedWrite:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def write(self, _):
            raise OSError(errno.ENOSPC, "owned record write failure")

    monkeypatch.setattr(local_evidence.os, "fdopen", lambda fd, mode: FailedWrite(fdopen(fd, mode)))
    with pytest.raises(OSError, match="owned record write failure"):
        store.persist("owned/1", proof(), context=context())
    assert store.descriptors == () and list(store.directory.iterdir()) == []
    assert store.incomplete_producers == ("owned/1",)


def test_directory_sync_failure_after_link_returns_no_success(tmp_path, monkeypatch):
    from cv_agent.application import local_evidence
    store = EvidenceStore(tmp_path / "records")

    def failed_sync(_):
        raise OSError(errno.EIO, "owned record directory sync failure")

    monkeypatch.setattr(local_evidence, "fsync_directory", failed_sync)
    with pytest.raises(OSError, match="owned record directory sync failure"):
        store.persist("owned/1", proof(), context=context())
    assert store.descriptors == () and list(store.directory.iterdir()) == []


def test_record_is_exclusive_and_does_not_overwrite_existing_file(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    path = store.directory / (hashlib.sha256(b"owned/1").hexdigest() + ".json")
    path.write_text("owned existing historical record")
    with pytest.raises(FileExistsError):
        store.persist("owned/1", proof(), context=context())
    assert path.read_text() == "owned existing historical record"
    assert store.descriptors == ()


def test_descriptors_are_detached_and_relative_relocation_stays_in_private_store(tmp_path):
    store = EvidenceStore(tmp_path / "records")
    descriptor = store.persist("owned/1", proof(), context=context())
    descriptor["context"]["run_id"] = "changed-copy"
    assert store.descriptors[0]["context"] == context()
    relocated = dict(store.descriptors[0], path=Path(store.descriptors[0]["path"]).name)
    assert read_descriptor(relocated, directory=store.directory, subject=subject())[0] == "owned/1"
    escaping = dict(relocated, path="../outside.json")
    with pytest.raises(LocalEvidenceError, match="outside"):
        read_descriptor(escaping, directory=store.directory)
    with pytest.raises(LocalEvidenceError, match="relative"):
        read_descriptor(relocated)


def command_observation(state):
    selected = subject().model_copy(update={"property_id": "command-execution", "input_parameters": ("value",)})
    return ToolObservation(tool="inspect_command_construction", status="ok", subject=selected,
        validation_status="UNRESOLVED", citation_id="owned-command", evidence_ids=("command:entry.py",),
        content=json.dumps({"source_path": "entry.py", "function_header_lines": [1],
            "source_line_count": 3, "issues": [], "sink_facts": [{"path": "entry.py", "line": 2, "status": state}]}))


@pytest.mark.parametrize("state,label,direction,property_state", [
    ("UNSANITIZED", "VULNERABLE", "SUPPORT", "SUPPORTED"),
    ("SANITIZED", "SAFE", "REFUTE", "REFUTED"),
])
def test_shared_command_qualification_agrees_with_research_and_product(state, label, direction, property_state):
    observed = command_observation(state)
    decision = acceptance_decision(observed, observed.subject)
    assert decision.admissible and decision.direction == direction
    assert decision.method == "complete_static_analysis" and decision.coverage == "candidate"
    assert decision.original_validation_status == "UNRESOLVED"
    with pytest.raises(FrozenInstanceError):
        decision.admissible = False
    finding, receipts = reduce_observations(observed.subject, [("owned/command", observed)])
    assert finding.property_state == property_state
    assert receipts[0].validation_status == observed.validation_status == "UNRESOLVED"
    assert receipts[0].accepted_static_status == ("CONFIRMED" if direction == "SUPPORT" else "REFUTED")
    trace = [ReActStep(step=1, model_id="owned-scripted", observation=observed,
        tool_call=ModelToolCall(call_id="owned-call", name=observed.tool, arguments={}))]
    proposed = AgentExpertConclusion(expert="scan", label=label, confidence=.8,
        validation_status="UNRESOLVED", evidence_ids=(observed.citation_id,),
        supporting_observation_ids=(observed.citation_id,), rationale="Owned complete scoped command control.")
    validate_conclusion(proposed, trace, frozenset(), subject=observed.subject)


@pytest.mark.parametrize("problem", ["unknown", "clipped", "suppressed", "error", "subject", "local-line"])
def test_shared_command_qualification_rejects_unsupported_controls(problem):
    observed = command_observation("SANITIZED")
    selected = observed.subject
    if problem == "unknown":
        observed = command_observation("AMBIGUOUS")
    elif problem == "clipped":
        observed = observed.model_copy(update={"metadata": {"observation_truncated": True}})
    elif problem == "suppressed":
        observed = observed.model_copy(update={"metadata": {"model_payload_suppressed": True}})
    elif problem == "error":
        observed = observed.model_copy(update={"status": "error"})
    elif problem == "subject":
        observed = observed.model_copy(update={"subject": selected.model_copy(update={"candidate_id": "wrong"})})
    else:
        selected = selected.model_copy(update={"entry_line": 3})
        observed = observed.model_copy(update={"subject": selected})
    decision = acceptance_decision(observed, selected)
    assert not decision.admissible and decision.direction is None and decision.reasons
    finding, _ = reduce_observations(selected, [("owned/unsupported", observed)])
    assert finding.property_state == "UNKNOWN"
    proposed = AgentExpertConclusion(expert="scan", label="SAFE", confidence=.8,
        validation_status="UNRESOLVED", evidence_ids=(observed.citation_id,),
        supporting_observation_ids=(observed.citation_id,), rationale="Owned unsupported command control.")
    trace = [ReActStep(step=1, model_id="owned-scripted", observation=observed,
        tool_call=ModelToolCall(call_id="owned-call", name=observed.tool, arguments={}))]
    with pytest.raises(ValueError):
        validate_conclusion(proposed, trace, frozenset(), subject=selected)
