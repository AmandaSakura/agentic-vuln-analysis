"""Failure windows use fake providers and owned durable journals only."""
from concurrent.futures import ThreadPoolExecutor
import io
import json
from threading import Barrier
import urllib.error

import pytest

from cv_agent.domain.chat import ChatMessage
from cv_agent.runtime.budget import BudgetExceeded, LockedBudget
from cv_agent.runtime.journal import Journal, Trial, audit_journal
from cv_agent.runtime.model import OpenAICompatibleChatModel


def test_last_request_slot_is_admitted_once_and_cancellation_admits_none(tmp_path):
    budget = LockedBudget(requests=1, seconds=30)
    journal = Journal(tmp_path / "events.jsonl")
    trial = Trial("owned", "offline-test", journal)
    observer = budget.observer(trial, "owned")
    barrier = Barrier(6)
    def request(number):
        barrier.wait(timeout=5)
        try:
            observer({"event": "model_start", "request_id": f"owned-{number}"})
        except BudgetExceeded:
            return False
        return True
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert sum(pool.map(request, range(6))) == 1
    assert budget.used == trial.model_calls == 1
    budget.stop()
    with pytest.raises(BudgetExceeded):
        observer({"event": "model_start", "request_id": "after-cancel"})
    assert budget.used == 1


def test_partial_tail_and_sent_no_response_are_explicitly_uncertain(tmp_path):
    path = tmp_path / "events.jsonl"
    journal = Journal(path)
    journal.write({"event": "model_start", "request_id": "owned-1"})
    with path.open("ab") as stream:
        stream.write(b'{"event":"model_response_received","request_id":"owned-1",')
    audit = audit_journal(path)
    assert audit["requests_started"] == 1
    assert audit["uncertain_request_ids"] == ["owned-1"]
    assert audit["reported_tokens"] is None
    assert audit["automatic_retry_allowed"] is False
    assert audit["issues"][0]["reason_code"] == "unterminated_record"
    assert audit["issues"][0]["line"] == 2


def test_uncommitted_valid_json_response_cannot_release_unknown_usage(tmp_path):
    path = tmp_path / "events.jsonl"
    Journal(path).write({"event": "model_start", "request_id": "owned-1"})
    with path.open("ab") as stream:
        stream.write(json.dumps({"event": "model_response_received", "request_id": "owned-1",
                                "summary": {"usage": {"total_tokens": 5}}}).encode())
    audit = audit_journal(path)
    assert audit["uncertain_request_ids"] == ["owned-1"]
    assert audit["reported_tokens"] is None


def test_known_usage_survives_content_parse_failure_and_bad_middle_record(tmp_path):
    path = tmp_path / "events.jsonl"
    journal = Journal(path)
    journal.write({"event": "model_start", "request_id": "owned-1"})
    journal.write({"event": "model_response_received", "request_id": "owned-1",
                   "summary": {"usage": {"total_tokens": 5}}})
    journal.write({"event": "model_invalid_response", "request_id": "owned-1"})
    with path.open("ab") as stream: stream.write(b"not-json\n")
    journal.write({"event": "model_start", "request_id": "owned-2"})
    audit = audit_journal(path)
    assert audit["known_reported_tokens"] == 5
    assert audit["reported_tokens"] is None
    assert audit["uncertain_request_ids"] == ["owned-2"]
    assert audit["issues"][0]["reason_code"] == "invalid_record"


def fake_model(events):
    return OpenAICompatibleChatModel(base_url="https://owned.invalid/v1", model="offline-only",
        api_key="fake-key-for-redaction", temperature=0, timeout_seconds=1, observer=events.append)


def test_transport_error_redacts_known_fake_key_in_public_error_and_event(monkeypatch):
    events = []
    def error(*_, **__):
        raise urllib.error.URLError("diagnostic fake-key-for-redaction")
    monkeypatch.setattr("urllib.request.urlopen", error)
    with pytest.raises(RuntimeError) as caught:
        fake_model(events).complete([ChatMessage(role="user", content="owned constant")], [])
    assert "fake-key-for-redaction" not in str(caught.value)
    assert "fake-key-for-redaction" not in json.dumps(events)
    assert len([e for e in events if e["event"] == "model_start"]) == 1


def test_start_journal_failure_sends_no_request_and_keeps_reserved_slot(tmp_path, monkeypatch):
    class FailedJournal(Journal):
        def write(self, event):
            raise OSError("owned injected write failure")
    budget = LockedBudget(requests=1, seconds=30)
    trial = Trial("owned", "offline", FailedJournal(tmp_path / "events.jsonl"))
    sent = []
    monkeypatch.setattr("urllib.request.urlopen", lambda *_, **__: sent.append(True))
    model = fake_model([])
    model.observer = budget.observer(trial, "owned")
    with pytest.raises(OSError):
        model.complete([ChatMessage(role="user", content="owned constant")], [])
    assert not sent and budget.used == trial.model_calls == 1
    with pytest.raises(BudgetExceeded):
        model.complete([ChatMessage(role="user", content="owned constant")], [])
    assert not sent and budget.used == 1


def test_malformed_model_content_still_persists_usage(monkeypatch, tmp_path):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps({"model": "offline-only", "usage": {"total_tokens": 9},
            "choices": [{"message": {"tool_calls": [{"id": "owned", "function": {
                "name": "owned", "arguments": "not-json"}}]}}]}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda *_, **__: Response())
    journal = Journal(tmp_path / "events.jsonl")
    model = fake_model([])
    model.observer = journal.write
    with pytest.raises(ValueError):
        model.complete([ChatMessage(role="user", content="owned constant")], [])
    audit = audit_journal(journal.path)
    assert audit["requests_started"] == 1
    assert audit["reported_tokens"] == 9
    assert not audit["uncertain_request_ids"]
