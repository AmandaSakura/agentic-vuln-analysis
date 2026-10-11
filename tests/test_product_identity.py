import pytest

from cv_agent.application.identity import canonical_digest, source_digest, execution_digest, view_revision


def test_source_identity_ignores_presentation_order_and_tracks_every_file():
    hashes = {"entry.py": "a"*64, "helper.py": "b"*64}
    assert source_digest(hashes) == source_digest(dict(reversed(list(hashes.items()))))
    assert source_digest(hashes) != source_digest({**hashes, "helper.py": "c"*64})
    assert source_digest(hashes) != source_digest({**hashes, "imports.py": "d"*64})


def test_view_and_approved_environment_are_independent_layers():
    hashes = {"entry.py": "a"*64}
    original = source_digest(hashes)
    assert view_revision([("entry.py", 1, 3)]) != view_revision([("entry.py", 1, 7)])
    assert source_digest(hashes) == original
    assert execution_digest({"interpreter": "a"*64, "scratch": "disabled"}) != execution_digest(
        {"interpreter": "b"*64, "scratch": "disabled"})


@pytest.mark.parametrize("path", ["../outside.py", "/absolute.py", "entry\\other.py", "a/./b.py"])
def test_unsafe_identity_paths_are_rejected(path):
    with pytest.raises(ValueError, match="path"):
        source_digest({path: "a"*64})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_canonical_inputs_are_rejected(value):
    with pytest.raises(ValueError):
        canonical_digest("owned-v1", {"value": value})
