"""R08: public updates obey the same validation as ordinary construction."""
from __future__ import annotations

import pytest
from pydantic import Field, ValidationError

from cv_agent.domain.evidence import ToolObservation, ValidationSubject
from cv_agent.domain.product_result import FindingView, IdentityBundle, ReviewCounts, ReviewResult, property_contract
from cv_agent.domain.types import Candidate, CodeDocument, ExpertVote, FrozenModel


def _candidate():
    return Candidate(candidate_id="owned-entry", case_id="owned-case", repository_id="owned",
                     path="sample.py", line=1, query="selected mode", property_id="chmod-mode-others-write",
                     metadata={"nested": {"values": [1, 2]}}, entry_boolean_arguments={"flag": True})


def _subject():
    return ValidationSubject(candidate_id="owned-entry", repository_id="owned", entry_path="sample.py",
                             entry_line=1, source_digest="owned-source", property_id="chmod-mode-others-write")


@pytest.mark.parametrize("update", [
    {"line": 0}, {"line": "not-an-integer"}, {"entry_boolean_arguments": {"flag": "yes"}},
    {"unregistered_derived_digest": "externally-supplied"},
])
def test_candidate_copy_rejects_invalid_updates_like_construction(update):
    candidate = _candidate()
    with pytest.raises(ValidationError):
        Candidate.model_validate({**candidate.model_dump(), **update})
    with pytest.raises(ValidationError):
        candidate.model_copy(update=update)


@pytest.mark.parametrize("value", [0, "invalid"])
def test_subject_copy_rejects_invalid_location(value):
    with pytest.raises(ValidationError):
        _subject().model_copy(update={"entry_line": value})


def test_observation_copy_rejects_unregistered_status_and_subject_type():
    observation = ToolObservation(tool="inspect_permission_mode", status="ok", content="owned", subject=_subject())
    for update in ({"status": "success-ish"}, {"subject": "not-a-subject"}, {"invented": 1}):
        with pytest.raises(ValidationError):
            observation.model_copy(update=update)


def test_document_copy_rejects_invalid_registered_adapter_tier():
    document = CodeDocument(repository_id="owned", path="sample.py", text="pass\n", adapter_tier="ast")
    with pytest.raises(ValidationError):
        document.model_copy(update={"adapter_tier": "unregistered"})


def test_frozen_non_snapshot_copy_validates_scalar_constraints():
    vote = ExpertVote(expert="scan", label="ABSTAIN", confidence=0.0, rationale="owned")
    with pytest.raises(ValidationError):
        vote.model_copy(update={"confidence": 1.5})


def test_product_copy_revalidates_subject_cross_fields_and_contract_version():
    finding = FindingView(candidate_id="owned-entry", subject=_subject(),
                          contract=property_contract("chmod-mode-others-write"))
    with pytest.raises(ValidationError, match="candidate"):
        finding.model_copy(update={"candidate_id": "another-entry"})
    with pytest.raises(ValidationError, match="property"):
        finding.model_copy(update={"contract": property_contract("command-execution")})
    with pytest.raises(ValidationError):
        finding.contract.model_copy(update={"version": "unregistered-contract-v2"})
    identity = IdentityBundle(source_digest="a" * 64, analysis_contract_digest="b" * 64,
                              retrieval_view_revision="c" * 64)
    with pytest.raises(ValidationError):
        identity.model_copy(update={"source_digest": "externally-derived"})


def test_result_copy_rejects_external_derived_counts_and_unregistered_schema():
    identity = IdentityBundle(source_digest="a" * 64, analysis_contract_digest="b" * 64,
                              retrieval_view_revision="c" * 64)
    result = ReviewResult(run_id="owned-empty", run_state="COMPLETED", identity=identity)
    with pytest.raises(ValidationError, match="denominator"):
        result.model_copy(update={"counts": ReviewCounts(candidate_count=1)})
    with pytest.raises(ValidationError):
        result.model_copy(update={"schema_version": "external-derived-schema"})
    with pytest.raises(ValidationError):
        result.model_copy(update={"external_derived_summary": {"safe": True}})


@pytest.mark.parametrize("deep", [False, True])
def test_valid_public_copy_roundtrips_and_seals_nested_containers(deep):
    original = _candidate()
    supplied = {"nested": {"values": [3, 4]}}
    copied = original.model_copy(update={"line": 2, "metadata": supplied}, deep=deep)
    assert copied is not original
    assert copied.line == 2 and original.line == 1
    assert Candidate.model_validate_json(copied.model_dump_json()) == copied
    assert Candidate.model_validate(copied.model_dump(mode="python")) == copied
    supplied["nested"]["values"].append(9)
    copied.metadata["nested"]["values"].append(8)
    assert copied.metadata == {"nested": {"values": [3, 4]}}
    assert original.metadata == {"nested": {"values": [1, 2]}}


def test_valid_finding_copy_updates_cross_fields_together_and_roundtrips():
    finding = FindingView(candidate_id="owned-entry", subject=_subject(),
                          contract=property_contract("chmod-mode-others-write"))
    subject = finding.subject.model_copy(update={"candidate_id": "owned-renamed"})
    updated = finding.model_copy(update={"candidate_id": "owned-renamed", "subject": subject})
    assert updated.subject.candidate_id == updated.candidate_id == "owned-renamed"
    assert FindingView.model_validate_json(updated.model_dump_json()) == updated
    assert finding.model_copy() == finding


def test_copy_preserves_declared_constructor_coercion_and_rejects_bad_nested_dict():
    candidate = _candidate()
    copied = candidate.model_copy(update={"line": "2"})
    constructed = Candidate.model_validate({**candidate.model_dump(), "line": "2"})
    assert copied == constructed and type(copied.line) is int and copied.line == 2
    observation = ToolObservation(tool="owned", status="ok", content="owned", subject=_subject())
    with pytest.raises(ValidationError):
        observation.model_copy(update={"subject": {**_subject().model_dump(), "entry_line": 0}})


def test_valid_updates_preserve_declared_constructor_aliases():
    class AliasedConfiguration(FrozenModel):
        config_path: str = Field(alias="config")
        limit: int = Field(ge=1)
    original = AliasedConfiguration(config="owned.json", limit=1)
    updated = original.model_copy(update={"limit": 2})
    relocated = original.model_copy(update={"config_path": "renamed.json"})
    assert updated.config_path == original.config_path and updated.limit == 2
    assert relocated.config_path == "renamed.json"
    assert AliasedConfiguration.model_validate_json(updated.model_dump_json(by_alias=True)) == updated
    with pytest.raises(ValidationError):
        original.model_copy(update={"limit": 0})
