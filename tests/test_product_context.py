import hashlib
import json

import pytest

from cv_agent.application.context import ReadGrant, SourceReadView, ContextAdmissionError


def owned_view(tmp_path, budget=8192):
    text = "def entry():\n    return helper()\n\ndef helper():\n    return 7\n"
    (tmp_path / "entry.py").write_text(text)
    hashes = {"entry.py": hashlib.sha256(text.encode()).hexdigest()}
    view = SourceReadView(tmp_path, hashes, byte_budget=budget)
    view.admit(ReadGrant(path="entry.py", start_line=1, end_line=2, reason="selected candidate"))
    return view


def test_same_path_is_not_free_permission_to_read_another_span(tmp_path):
    view = owned_view(tmp_path)
    first = view.read("entry.py", 1, 2)
    assert first["text"] == "def entry():\n    return helper()\n"
    assert view.used_bytes == len(json.dumps(first, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode())
    with pytest.raises(ContextAdmissionError, match="span"):
        view.read("entry.py", 4, 5)
    original_identity = view.source_digest
    original_revision = view.revision
    view.admit(ReadGrant(path="entry.py", start_line=4, end_line=5,
                        reason="explicit owned helper context"))
    second = view.read("entry.py", 4, 5)
    assert "return 7" in second["text"]
    assert view.source_digest == original_identity
    assert view.revision != original_revision
    assert view.used_bytes > len(json.dumps(first).encode())


def test_each_delivery_is_billed_and_budget_failure_retains_receipt(tmp_path):
    view = owned_view(tmp_path, budget=700)
    result = view.read("entry.py", 1, 2)
    size = view.used_bytes
    view.read("entry.py", 1, 2)
    assert view.used_bytes == 2 * size
    with pytest.raises(ContextAdmissionError, match="budget"):
        view.read("entry.py", 1, 2)
    assert view.receipts[-1].state == "REJECTED"
    assert view.receipts[-1].reason_code == "context_budget_exhausted"


def test_drift_and_outside_root_cannot_extend_the_authorized_snapshot(tmp_path):
    view = owned_view(tmp_path)
    (tmp_path / "entry.py").write_text("changed source\n")
    with pytest.raises(ContextAdmissionError, match="snapshot"):
        view.read("entry.py", 1, 2)
    with pytest.raises(ValueError, match="path"):
        view.admit(ReadGrant(path="../outside.py", start_line=1, end_line=1, reason="unapproved"))


def test_symlink_and_uninventoried_sources_are_rejected(tmp_path):
    view = owned_view(tmp_path)
    (tmp_path / "link.py").symlink_to(tmp_path / "entry.py")
    with pytest.raises(ContextAdmissionError):
        view.admit(ReadGrant(path="link.py", start_line=1, end_line=1, reason="unapproved"))


def test_non_granted_source_is_absent_from_analysis_paths(tmp_path):
    view = owned_view(tmp_path)
    assert view.covers("entry.py", 1, 2)
    assert not view.covers("entry.py", 1, 5)
    assert not view.covers("entry.py", 4, 5)


def test_failed_extension_does_not_admit_unpaid_source_range(tmp_path):
    view = owned_view(tmp_path, budget=1)
    prior = view.revision
    with pytest.raises(ContextAdmissionError, match="budget"):
        view.extend(ReadGrant(path="entry.py", start_line=4, end_line=5, reason="owned helper"))
    assert not view.covers("entry.py", 4, 5)
    assert view.revision == prior
    assert view.used_bytes == 0
    assert view.receipts[-1].state == "REJECTED"
