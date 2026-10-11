"""Authority snapshots do not drift through ordinary nested-container aliases."""
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject, repository_source_digest


def candidate(values=None):
    return Candidate(candidate_id="owned", case_id="owned", repository_id="r", path="entry.py",
                     line=1, query="constant", property_id="chmod-mode-others-write",
                     entry_value_assumptions={} if values is None else values)


def test_original_nested_input_cannot_change_candidate_or_subject():
    values = {"settings": {"items": [1, 2]}}
    item = candidate(values)
    index = RepositoryIndex([CodeDocument(repository_id="r", path="entry.py", text="constant")])
    subject = candidate_subject(index, item)
    snapshot = subject.model_dump_json()
    values["settings"]["items"].append(3)
    assert item.entry_value_assumptions == {"settings": {"items": [1, 2]}}
    assert subject.model_dump_json() == snapshot


def test_public_candidate_and_subject_views_do_not_mutate_authority():
    item = candidate({"settings": {"items": [1]}})
    index = RepositoryIndex([CodeDocument(repository_id="r", path="entry.py", text="constant")])
    subject = candidate_subject(index, item)
    before = subject.model_dump_json()
    item.entry_value_assumptions["settings"]["items"].append(2)
    subject.entry_value_assumptions["settings"]["items"].append(3)
    assert item.entry_value_assumptions == {"settings": {"items": [1]}}
    assert subject.model_dump_json() == before


def test_observation_metadata_alias_cannot_change_delivery_status():
    metadata = {"delivery": {"complete": True}, "items": ["one"]}
    observation = ToolObservation(tool="owned", status="ok", content="constant", metadata=metadata)
    before = observation.model_dump_json()
    metadata["delivery"]["complete"] = False
    observation.metadata["items"].append("two")
    assert observation.model_dump_json() == before


def test_model_copy_seals_updates_without_changing_original_or_json_types():
    original = candidate({"settings": {"items": [1]}})
    update = {"settings": {"items": [2]}}
    changed = original.model_copy(update={"entry_value_assumptions": update})
    update["settings"]["items"].append(3)
    assert original.entry_value_assumptions == {"settings": {"items": [1]}}
    assert changed.entry_value_assumptions == {"settings": {"items": [2]}}
    dumped = changed.model_dump(mode="json")
    assert type(dumped["entry_value_assumptions"]) is dict
    assert type(dumped["entry_value_assumptions"]["settings"]["items"]) is list
    assert Candidate.model_validate(dumped) == changed


def test_code_document_alias_cannot_change_index_identity_but_new_version_can():
    document = CodeDocument(repository_id="r", path="entry.py", text="constant", import_aliases={"m": "module"})
    index = RepositoryIndex([document])
    before = repository_source_digest(index)
    document.import_aliases["m"] = "other"
    assert repository_source_digest(index) == before
    changed = document.model_copy(update={"import_aliases": {"m": "other"}})
    assert repository_source_digest(RepositoryIndex([changed])) != before
    assert repository_source_digest(RepositoryIndex([document])) == before
