"""Measured v2-only digest caching, with mutable legacy positive controls."""
import importlib
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools import identity


def owned_documents():
    return [CodeDocument(repository_id="owned", path="entry.py", text="eval('1')\n", language="python"),
            CodeDocument(repository_id="owned", path="helper.py", text="value = 7\n", language="python")]


def frozen(documents):
    cls = getattr(importlib.import_module("cv_agent.retrieval.index"), "FrozenRepositoryIndex")
    return cls(documents)


def test_mutable_legacy_index_edits_recompute_digest():
    index = RepositoryIndex(owned_documents())
    before = identity.repository_source_digest(index)
    index.documents["entry.py"] = index.documents["entry.py"].model_copy(update={"text": "eval('2')\n"})
    assert identity.repository_source_digest(index) != before


def test_arbitrary_index_digest_attribute_is_never_trusted():
    index = RepositoryIndex(owned_documents())
    expected = identity.repository_source_digest(index)
    index.source_digest = "0" * 64
    assert identity.repository_source_digest(index) == expected
    assert expected != index.source_digest


def test_frozen_digest_matches_exact_legacy_serialization():
    documents = owned_documents()
    assert identity.repository_source_digest(frozen(documents)) == identity.repository_source_digest(RepositoryIndex(documents))


def test_nonempty_original_file_binding_is_retained_in_cached_digest():
    original = owned_documents()
    bound = [original[0].model_copy(update={"source_sha256": "a" * 64}), original[1]]
    assert identity.repository_source_digest(frozen(bound)) == identity.repository_source_digest(RepositoryIndex(bound))
    assert identity.repository_source_digest(frozen(bound)) != identity.repository_source_digest(frozen(original))


def test_frozen_documents_and_digest_refuse_public_mutation():
    index = frozen(owned_documents())
    with pytest.raises(TypeError):
        index.documents["entry.py"] = owned_documents()[0]
    with pytest.raises(AttributeError):
        index.documents = {}
    with pytest.raises(AttributeError):
        index.source_digest = "0" * 64
    with pytest.raises(ValidationError):
        index.documents["entry.py"].text = "changed"
    aliases = index.documents["entry.py"].import_aliases
    if type(aliases) is dict:
        aliases["eval"] = "owned.fake"
    assert index.documents["entry.py"].import_aliases == {}


def test_frozen_documents_refuse_public_deletion():
    index = frozen(owned_documents())
    before = identity.repository_source_digest(index)
    with pytest.raises(AttributeError):
        del index.documents
    assert set(index.documents) == {"entry.py", "helper.py"}
    assert identity.repository_source_digest(index) == before


def test_cached_digest_serializes_once_for_many_candidate_consumers(monkeypatch):
    original = identity.json
    calls = []

    def dumps(*args, **kwargs):
        serialized = original.dumps(*args, **kwargs)
        calls.append(len(serialized.encode()))
        return serialized

    monkeypatch.setattr(identity, "json", SimpleNamespace(dumps=dumps))
    index = frozen(owned_documents())
    expected = index.source_digest
    assert len(calls) == 1
    for _ in range(100):
        assert identity.repository_source_digest(index) == expected
    assert len(calls) == 1


def test_subclasses_cannot_supply_a_forged_cache():
    cls = getattr(importlib.import_module("cv_agent.retrieval.index"), "FrozenRepositoryIndex")

    class UnrecognizedIndex(cls):
        @property
        def source_digest(self):
            return "0" * 64

    index = UnrecognizedIndex(owned_documents())
    assert identity.repository_source_digest(index) == identity.repository_source_digest(RepositoryIndex(owned_documents()))
    assert identity.repository_source_digest(index) != index.source_digest


def test_snapshot_discovery_builds_one_frozen_index_and_preserves_legacy_values(tmp_path):
    from cv_agent.agents.discovery import discover_python_repository
    from cv_agent.application.source_snapshot import freeze_source_snapshot

    (tmp_path / "entry.py").write_text("eval('1')\n")
    original = discover_python_repository(tmp_path, "owned")
    sealed = discover_python_repository(tmp_path, "owned", snapshot=freeze_source_snapshot(tmp_path))
    cls = getattr(importlib.import_module("cv_agent.retrieval.index"), "FrozenRepositoryIndex")
    assert type(sealed.index) is cls
    assert type(original.index) is RepositoryIndex
    assert original.candidates == sealed.candidates
    assert identity.repository_source_digest(original.index) == identity.repository_source_digest(sealed.index)
