"""A witness producer cannot advertise or emit candidate SAFE evidence."""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.evaluation.diagnostics.bounded_execution_witness import SourceFileBinding, WitnessManifest
from cv_agent.evaluation.diagnostics import witness_contract
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject


class _MeasuredResult:
    def __init__(self, status: ValidationStatus, raw_status: str, gaps=()):
        self.status = status
        self.raw_status = raw_status
        self.gaps = gaps

    def model_dump(self, *, mode: str):
        return {
            "status": self.status.value,
            "raw_status": self.raw_status,
            "gaps": list(self.gaps),
        }


def test_witness_scope_type_rejects_refuted_and_extra_statuses():
    proof = witness_contract.PositiveOnlyWitnessProofScope()
    assert proof.supported_statuses == (ValidationStatus.CONFIRMED,)
    for statuses in (
        (ValidationStatus.REFUTED,),
        (ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    ):
        with pytest.raises(ValidationError):
            witness_contract.PositiveOnlyWitnessProofScope(supported_statuses=statuses)


@pytest.mark.parametrize(
    "status,raw_status,gaps",
    [
        (ValidationStatus.REFUTED, "LITERAL_OBSERVED", ()),
        (ValidationStatus.CONFIRMED, "LITERAL_OBSERVED", ()),
        (ValidationStatus.CONFIRMED, "EXPANDED_OBSERVED", ("source_mismatch",)),
    ],
)
def test_witness_producer_rejects_inconsistent_strong_status(monkeypatch, status, raw_status, gaps):
    monkeypatch.setattr(
        witness_contract,
        "run_witness",
        lambda _: _MeasuredResult(status, raw_status, gaps),
    )
    with pytest.raises(ValueError):
        witness_contract._fixture_outcome(None)


def test_witness_producer_preserves_literal_only_as_raw_diagnostic(monkeypatch):
    monkeypatch.setattr(
        witness_contract,
        "run_witness",
        lambda _: _MeasuredResult(ValidationStatus.UNRESOLVED, "LITERAL_OBSERVED"),
    )
    outcome = witness_contract._fixture_outcome(None)
    assert outcome.status == ValidationStatus.UNRESOLVED
    assert outcome.details["raw_status"] == "LITERAL_OBSERVED"


def test_witness_producer_preserves_complete_positive(monkeypatch):
    monkeypatch.setattr(
        witness_contract,
        "run_witness",
        lambda _: _MeasuredResult(ValidationStatus.CONFIRMED, "EXPANDED_OBSERVED"),
    )
    assert witness_contract._fixture_outcome(None).status == ValidationStatus.CONFIRMED


def _bound_case(tmp_path):
    source = "class Entry:\n    def serve(self, model_uri):\n        return model_uri\n"
    entry = tmp_path / "entry.py"
    entry.write_text(source)
    file_sha256 = hashlib.sha256(entry.read_bytes()).hexdigest()
    index = RepositoryIndex((CodeDocument(
        repository_id="synthetic-repo", path="entry.py::Entry.serve@2-3",
        text="".join(source.splitlines(keepends=True)[1:3]),
        language="python", defines=("Entry.serve",),
    ),))
    candidate = Candidate(
        property_id="command-execution", candidate_id="synthetic-entry",
        case_id="synthetic-case", repository_id="synthetic-repo",
        path="entry.py::Entry.serve@2-3", line=2, query="Synthetic command boundary",
        input_parameters=("model_uri",),
    )
    manifest = WitnessManifest(
        subject=candidate_subject(index, candidate),
        checkout_root=tmp_path,
        module_name="entry",
        class_name="Entry",
        method_name="serve",
        entry_relative_path="entry.py",
        entry_file_sha256=file_sha256,
        entry_first_line=2,
        source_modules=(SourceFileBinding(
            module_name="entry", relative_path="entry.py", sha256=file_sha256,
        ),),
        probe_argument="model_uri",
        recorder_command="sink",
    )
    return index, candidate, manifest, entry


def test_registration_binds_index_digest_and_independent_file_sha(tmp_path):
    index, candidate, manifest, entry = _bound_case(tmp_path)
    case = witness_contract.bounded_witness_fixture_case(index, candidate, manifest)
    assert case.subject == candidate_subject(index, candidate)
    assert case.proof_scope.supported_statuses == (ValidationStatus.CONFIRMED,)

    changed_index = RepositoryIndex((*index.documents.values(), CodeDocument(
        repository_id="synthetic-repo", path="unrelated.py", text="x = 1\n",
    )))
    with pytest.raises(ValueError, match="subject"):
        witness_contract.bounded_witness_fixture_case(changed_index, candidate, manifest)

    stale_index = RepositoryIndex((CodeDocument(
        repository_id="synthetic-repo", path="entry.py::Entry.serve@2-3",
        text="".join(entry.read_text().splitlines(keepends=True)[1:3]).replace(
            "return model_uri", "return 'stale'",
        ),
        language="python", defines=("Entry.serve",),
    ),))
    stale_manifest = manifest.model_copy(update={
        "subject": candidate_subject(stale_index, candidate),
    })
    with pytest.raises(ValueError, match="indexed source"):
        witness_contract.bounded_witness_fixture_case(stale_index, candidate, stale_manifest)

    entry.write_text(entry.read_text() + "# changed without reindexing\n")
    with pytest.raises(ValueError, match="snapshot"):
        witness_contract.bounded_witness_fixture_case(index, candidate, manifest)


def test_registration_rejects_other_method_in_same_file(tmp_path):
    source = (
        "class Good:\n"
        "    def serve(self, model_uri):\n"
        "        return model_uri\n"
        "\n"
        "class Bad:\n"
        "    def serve(self, model_uri):\n"
        "        return model_uri\n"
    )
    entry = tmp_path / "entry.py"
    entry.write_text(source)
    digest = hashlib.sha256(entry.read_bytes()).hexdigest()
    path = "entry.py::Good.serve@2-3"
    index = RepositoryIndex((CodeDocument(
        repository_id="synthetic-repo", path=path,
        text="".join(source.splitlines(keepends=True)[1:3]),
        language="python", defines=("Good.serve",),
    ),))
    candidate = Candidate(
        property_id="command-execution", candidate_id="good-case",
        case_id="good-case", repository_id="synthetic-repo",
        path=path, line=2, query="Good.serve",
        input_parameters=("model_uri",),
    )
    manifest = WitnessManifest(
        subject=candidate_subject(index, candidate),
        checkout_root=tmp_path,
        module_name="entry", class_name="Bad", method_name="serve",
        entry_relative_path="entry.py", entry_file_sha256=digest,
        entry_first_line=6,
        source_modules=(SourceFileBinding(
            module_name="entry", relative_path="entry.py", sha256=digest,
        ),),
        probe_argument="model_uri", recorder_command="sink",
    )
    with pytest.raises(ValueError, match="entry method"):
        witness_contract.bounded_witness_fixture_case(index, candidate, manifest)


def test_registration_rejects_helper_hash_from_different_index_snapshot(tmp_path):
    entry_source = (
        "import helper\n"
        "class Entry:\n"
        "    def serve(self, model_uri):\n"
        "        return helper.build(model_uri)\n"
    )
    helper_safe = "import shlex\ndef build(value):\n    return shlex.quote(value)\n"
    helper_unsafe = "def build(value):\n    return value\n"
    entry = tmp_path / "entry.py"
    helper = tmp_path / "helper.py"
    entry.write_text(entry_source)
    helper.write_text(helper_safe)
    entry_digest = hashlib.sha256(entry.read_bytes()).hexdigest()
    helper_digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    index = RepositoryIndex((
        CodeDocument(
            repository_id="synthetic-repo", path="entry.py::Entry.serve@3-4",
            text="".join(entry_source.splitlines(keepends=True)[2:4]),
            language="python", defines=("Entry.serve",),
        ),
        CodeDocument(
            repository_id="synthetic-repo", path="helper.py::<module>@1-3",
            text=helper_safe, language="python", defines=("build",),
        ),
    ))
    candidate = Candidate(
        property_id="command-execution", candidate_id="helper-case",
        case_id="helper-case", repository_id="synthetic-repo",
        path="entry.py::Entry.serve@3-4", line=3, query="Entry.serve",
        input_parameters=("model_uri",),
    )
    manifest = WitnessManifest(
        subject=candidate_subject(index, candidate), checkout_root=tmp_path,
        module_name="entry", class_name="Entry", method_name="serve",
        entry_relative_path="entry.py", entry_file_sha256=entry_digest,
        entry_first_line=3,
        source_modules=(
            SourceFileBinding(module_name="entry", relative_path="entry.py", sha256=entry_digest),
            SourceFileBinding(module_name="helper", relative_path="helper.py", sha256=helper_digest),
        ),
        probe_argument="model_uri", recorder_command="sink",
    )
    witness_contract.bounded_witness_fixture_case(index, candidate, manifest)

    helper.write_text(helper_unsafe)
    unsafe_digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    unsafe_manifest = manifest.model_copy(update={
        "source_modules": (
            manifest.source_modules[0],
            SourceFileBinding(module_name="helper", relative_path="helper.py", sha256=unsafe_digest),
        ),
    })
    with pytest.raises(ValueError, match="indexed snapshot"):
        witness_contract.bounded_witness_fixture_case(index, candidate, unsafe_manifest)
