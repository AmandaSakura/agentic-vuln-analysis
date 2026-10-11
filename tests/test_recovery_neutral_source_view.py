"""Neutral detector inputs are validated source views, not invalid case copies."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairCase
from cv_agent.evaluation.datasets.advisory_source import NeutralDetectorSourceCase


def _private_case(role="vulnerable"):
    return PythonHeldoutPairCase(case_id="hp901_a" if role == "vulnerable" else "hp901_b",
        revision_role=role, commit="a" * 40, checkout="owned-source", file_path="package/entry.py", line_hint=4)


@pytest.mark.parametrize("role", ["vulnerable", "fixed"])
def test_neutral_source_view_retains_source_selection_and_excludes_revision_label(role):
    private = _private_case(role)
    neutral = NeutralDetectorSourceCase.from_case(private)
    assert neutral.case_id == "neutral-entry"
    assert set(neutral.model_dump()) == {"case_id", "commit", "checkout", "file_path", "line_hint"}
    assert not hasattr(neutral, "revision_role")
    assert (neutral.commit, neutral.checkout, neutral.file_path, neutral.line_hint) == (
        private.commit, private.checkout, private.file_path, private.line_hint)
    assert NeutralDetectorSourceCase.model_validate_json(neutral.model_dump_json()) == neutral
    assert private.case_id == ("hp901_a" if role == "vulnerable" else "hp901_b")
    assert private.revision_role == role
    with pytest.raises(ValidationError):
        private.model_copy(update={"case_id": "neutral-entry"})


@pytest.mark.parametrize("update", [
    {"case_id": "hp901_a"}, {"revision_role": "fixed"}, {"commit": "not-a-commit"},
    {"checkout": "../escape"}, {"file_path": "/entry.py"}, {"file_path": "package/binary.bin"},
    {"line_hint": 0},
])
def test_neutral_source_view_cannot_accept_labels_or_invalid_source_selection(update):
    neutral = NeutralDetectorSourceCase.from_case(_private_case())
    with pytest.raises(ValidationError):
        NeutralDetectorSourceCase.model_validate({**neutral.model_dump(), **update})
    with pytest.raises(ValidationError):
        neutral.model_copy(update=update)
