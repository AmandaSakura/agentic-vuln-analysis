"""Candidate-bound command facts must survive real helper semantics."""

import json

import pytest

from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep, ValidationSubject
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.models import CommandConstructionInput
from test_review_followup import vote


def _download_observation(helper_body: str, *, quoted: bool = False):
    value = "shlex.quote(local_path)" if quoted else "local_path"
    caller = CodeDocument(
        repository_id="r",
        path="entry.py",
        language="python",
        text=(
            "def entry(model_uri):\n"
            "    import os, shlex\n"
            "    local_path = _download_artifact_from_uri(model_uri)\n"
            f"    os.system('echo ' + {value})\n"
        ),
        defines=("entry",),
        calls=("_download_artifact_from_uri", "os.system"),
    )
    helper = CodeDocument(
        repository_id="r",
        path="mlflow/tracking/artifact_utils.py::_download_artifact_from_uri@1-20",
        language="python",
        text=(
            "def _download_artifact_from_uri(artifact_uri):\n"
            "    # get_artifact_repository download_artifacts (comments are not behavior)\n"
            + helper_body
        ),
        defines=("_download_artifact_from_uri",),
    )
    index = RepositoryIndex([caller, helper])
    subject = ValidationSubject(
        property_id="command-execution",
        input_parameters=("model_uri",),
        candidate_id="c",
        repository_id="r",
        entry_path=caller.path,
        entry_line=1,
        source_digest=repository_source_digest(index),
        entry_condition_assumptions={
            "os.path.exists(artifact_uri)": True,
            "is_windows()": False,
        },
    )
    observation = command_construction(
        index,
        CommandConstructionInput(source_path=caller.path),
        ToolExecutionScope(
            candidate_path=caller.path,
            admitted_paths=frozenset(index.documents),
            subject=subject,
            max_observation_tokens=100_000,
        ),
    ).model_copy(update={"citation_id": "command:download"})
    assert observation.status == "ok"
    trace = [ReActStep(
        step=1,
        model_id="offline",
        tool_call=ModelToolCall(
            call_id="download",
            name=observation.tool,
            arguments={"source_path": caller.path},
        ),
        observation=observation,
    )]
    return json.loads(observation.content), trace, subject


@pytest.mark.parametrize("helper_body, quoted", [
    (
        "    repo = get_artifact_repository(artifact_uri)\n"
        "    return repo.download_artifacts(artifact_uri)\n",
        False,
    ),
    (
        "    repo = get_artifact_repository(artifact_uri)\n"
        "    local_path = repo.download_artifacts(artifact_uri)\n"
        "    return 'fixed-' + local_path\n",
        False,
    ),
    (
        "    audit(artifact_uri)\n"
        "    repo = get_artifact_repository(artifact_uri)\n"
        "    return repo.download_artifacts(artifact_uri)\n",
        True,
    ),
    (
        "    repo = plugin.get_artifact_repository(artifact_uri)\n"
        "    return repo.download_artifacts(artifact_uri)\n",
        False,
    ),
])
def test_download_summary_requires_verified_dispatch_return_and_effects(helper_body, quoted):
    # The helper source alone does not identify the dispatched repository or
    # prove that downloading is pure and returns the original URI. The other
    # rows also mutate the returned value or have earlier effects.
    data, trace, subject = _download_observation(helper_body, quoted=quoted)
    assert data["command_construction_status"] == "AMBIGUOUS"
    assert data["issues"] or data["unresolved_calls"]
    with pytest.raises(ValueError):
        vote(trace, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        vote(trace, subject, "SAFE")


def test_download_helper_command_side_effect_is_not_hidden_by_quoted_outer_sink():
    data, trace, subject = _download_observation(
        "    runner = os.system\n"
        "    runner(artifact_uri)\n"
        "    repo = get_artifact_repository(artifact_uri)\n"
        "    return repo.download_artifacts(artifact_uri)\n",
        quoted=True,
    )
    assert any(fact["call"] == "os.system" and fact["status"] == "UNSANITIZED"
               for fact in data["sink_facts"])
    # This independent dangerous execution path may support VULNERABLE even
    # though the later repository return remains unresolved.
    vote(trace, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        vote(trace, subject, "SAFE")


@pytest.mark.parametrize("helper_body,quoted,label,expected_status", [
    ("    return artifact_uri\n", False, "VULNERABLE", "UNSANITIZED"),
    ("    return artifact_uri\n", True, "SAFE", "SANITIZED"),
    ("    return 'fixed'\n", False, "SAFE", "SANITIZED"),
])
def test_download_helper_fully_resolved_positive_controls(helper_body, quoted, label, expected_status):
    data, trace, subject = _download_observation(helper_body, quoted=quoted)
    assert data["command_construction_status"] == expected_status
    assert data["issues"] == []
    vote(trace, subject, label)
    with pytest.raises(ValueError):
        vote(trace, subject, "SAFE" if label == "VULNERABLE" else "VULNERABLE")
