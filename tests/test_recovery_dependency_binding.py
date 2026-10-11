from pathlib import Path
from cv_agent.application.identity import analysis_implementation_digest


def test_subject_helper_bytes_are_bound_to_analyzer_identity(monkeypatch):
    original=Path.read_bytes
    before=analysis_implementation_digest()
    def changed(path):
        raw=original(path)
        return raw+b'\n# owned identity coverage control\n' if path.as_posix().endswith('/cv_agent/tools/identity.py')else raw
    monkeypatch.setattr(Path,'read_bytes',changed)
    assert analysis_implementation_digest()!=before


def test_static_tool_registration_bytes_are_bound_to_analyzer_identity(monkeypatch):
    original=Path.read_bytes
    before=analysis_implementation_digest()
    def changed(path):
        raw=original(path)
        return raw+b'\n# owned registry coverage control\n' if path.as_posix().endswith('/cv_agent/tools/validation/registry.py')else raw
    monkeypatch.setattr(Path,'read_bytes',changed)
    assert analysis_implementation_digest()!=before
