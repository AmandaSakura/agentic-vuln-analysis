from cv_agent.tools.validation import FixtureCase, FixtureOutcome, ValidationStatus, LoopbackCase, LoopbackResponse
from cv_agent.tools.validation.fixtures import _run_fixture_case, _run_loopback_case


def test_registered_read_root_is_readable_but_cannot_be_written(tmp_path):
    subject = tmp_path / "subject"
    subject.mkdir()
    source = subject / "source.py"
    source.write_text("original")
    outside = tmp_path / "outside.txt"
    outside.write_text("external-marker")
    link = subject / "link.txt"
    link.symlink_to(outside)

    def runner():
        assert source.read_text() == "original"
        for operation in (
            lambda: outside.read_text(),
            lambda: link.read_text(),
            lambda: source.write_text("changed"),
            lambda: source.unlink(),
            lambda: (subject / "new.txt").write_text("new"),
        ):
            try:
                operation()
            except PermissionError:
                continue
            return FixtureOutcome(status=ValidationStatus.CONFIRMED, summary="unexpected access")
        return FixtureOutcome(status=ValidationStatus.REFUTED, summary="all forbidden accesses denied")

    outcome = _run_fixture_case(
        FixtureCase("filesystem", runner, read_roots=(subject,)), 2
    )
    assert outcome.status == ValidationStatus.REFUTED, outcome
    assert source.read_text() == "original"
    assert outside.read_text() == "external-marker"
    assert not (subject / "new.txt").exists()


def test_fixture_has_no_ambient_read_permission(tmp_path):
    marker = tmp_path / "marker.txt"
    marker.write_text("review marker")

    def runner():
        marker.read_text()
        return FixtureOutcome(status=ValidationStatus.CONFIRMED, summary="unexpected read")

    result = _run_fixture_case(FixtureCase("no-roots", runner), 2)
    assert result.status == ValidationStatus.UNRESOLVED
    assert "PermissionError" in result.details["error"]


def test_missing_isolation_stops_before_running_fixture(monkeypatch, tmp_path):
    from cv_agent.tools.validation import fixtures
    marker = tmp_path / "must-not-exist"

    def unavailable(roots):
        raise RuntimeError("Landlock unavailable")

    def runner():
        marker.write_text("should not run")
        return FixtureOutcome(status=ValidationStatus.CONFIRMED, summary="unexpected execution")

    monkeypatch.setattr(fixtures, "restrict_fixture_filesystem", unavailable)
    result = _run_fixture_case(FixtureCase("unavailable", runner), 2)
    assert result.status == ValidationStatus.UNRESOLVED
    assert not marker.exists()


def test_loopback_callback_cannot_read_unregistered_files(tmp_path):
    marker = tmp_path / "private.txt"
    marker.write_text("review marker")

    def application(request):
        marker.read_text()
        return LoopbackResponse(200)

    result = _run_loopback_case(LoopbackCase("no-read", application), 3)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["unauthorized_status"] == 500
    assert result.details["authorized_status"] == 500


def test_loopback_callbacks_share_state_and_can_read_registered_roots(tmp_path):
    source = tmp_path / "fixture.txt"
    source.write_text("fixture")
    requests = []

    def application(request):
        assert source.read_text() == "fixture"
        requests.append(request)
        if not request.headers.get("Authorization"):
            return LoopbackResponse(403)
        return LoopbackResponse(200 if len(requests) == 2 else 500)

    result = _run_loopback_case(
        LoopbackCase("stateful", application, read_roots=(tmp_path,)), 3
    )
    assert result.status == ValidationStatus.REFUTED
    assert requests == []  # Callback state belongs to the restricted child.


def test_loopback_requests_do_not_follow_redirects():
    def application(request):
        return LoopbackResponse(302, headers=(("Location", "http://127.0.0.1:1/"),))

    result = _run_loopback_case(LoopbackCase("redirect", application), 3)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["unauthorized_status"] == 302
