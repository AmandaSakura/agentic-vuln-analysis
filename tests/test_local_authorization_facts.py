"""Local resource-flow evidence without assuming unobserved caller policy."""
import json

import pytest

from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.registry import ToolExecutionScope
from test_validation_tools import _invoke, _registry


def inspect(body, parameters="session, resource_id"):
    doc = CodeDocument(repository_id="r", path="service.py::remove@1-20",
                       text=f"async def remove({parameters}):\n    {body}\n")
    observation = _invoke(_registry(RepositoryIndex([doc])), "get_guards", {"path": doc.path},
                          ToolExecutionScope(admitted_paths=frozenset({doc.path}), max_observation_tokens=20000))
    assert observation.status == "ok"
    assert observation.validation_status is None
    return json.loads(observation.content)


def test_local_resource_lookup_delete_preserves_key_and_principal_facts():
    payload = inspect("record = await session.get(Resource, resource_id)\n"
                      "    if record is None:\n        raise ValueError('missing')\n"
                      "    await session.delete(record)")
    fact, = payload["local_resource_operations"]
    assert fact["lookup_key_parameters"] == ["resource_id"]
    assert fact["principal_parameters"] == []
    assert fact["operation"] == "session.delete"
    assert fact["owner_comparisons"] == []
    assert fact["lookup_line"] < fact["operation_line"]
    assert "caller" in fact["scope_note"]


def test_local_owner_comparison_is_reported_without_claiming_dominance():
    payload = inspect("record = await session.get(Resource, resource_id)\n"
                      "    if record.user_id != user_id:\n        raise ValueError('denied')\n"
                      "    await session.delete(record)", "session, resource_id, user_id")
    fact, = payload["local_resource_operations"]
    assert fact["principal_parameters"] == ["user_id"]
    assert fact["owner_comparisons"] == ["record.user_id != user_id"]
    assert "does not establish" in fact["scope_note"]


def test_rebound_resource_clears_prior_owner_comparison():
    payload = inspect(
        "record = await session.get(Resource, resource_id)\n"
        "    if record.user_id != user_id:\n        raise ValueError('denied')\n"
        "    record = await session.get(Resource, other_id)\n"
        "    await session.delete(record)",
        "session, resource_id, other_id, user_id"
    )
    fact, = payload["local_resource_operations"]
    assert fact["lookup_key_parameters"] == ["other_id"]
    assert fact["owner_comparisons"] == []


def test_rebound_resource_preserves_only_current_owner_comparison():
    payload = inspect(
        "record = await session.get(Resource, resource_id)\n"
        "    if record.user_id != user_id:\n        raise ValueError('denied')\n"
        "    record = await session.get(Resource, other_id)\n"
        "    if record.owner_id == user_id:\n        pass\n"
        "    await session.delete(record)",
        "session, resource_id, other_id, user_id"
    )
    fact, = payload["local_resource_operations"]
    assert fact["lookup_key_parameters"] == ["other_id"]
    assert fact["owner_comparisons"] == ["record.owner_id == user_id"]


@pytest.mark.parametrize("tail", [
    "return record",
    "await session.delete(other)",
    "record = other\n    await session.delete(record)",
    "await other_session.delete(record)",
    "if enabled:\n        record = other\n    await session.delete(record)",
    "return record\n    await session.delete(record)",
    "session = other_session\n    await session.delete(record)",
])
def test_unmatched_or_rebound_resource_has_no_claimed_local_chain(tail):
    payload = inspect("record = await session.get(Resource, resource_id)\n    " + tail)
    assert payload.get("local_resource_operations", []) == []
