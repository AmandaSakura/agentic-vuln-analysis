from pathlib import Path

import pytest

import cv_agent.vulngym_retrieval as retrieval
from cv_agent.python_ast import PythonDocumentSpan, parse_python_source
from cv_agent.provenance import GitIdentity
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import CodeDocument, Evidence
from cv_agent.vulngym_retrieval import _hit


def test_subject_checkout_revision_must_match_selection(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(
        retrieval,
        "git_identity",
        lambda _: GitIdentity(revision="actual", dirty=False),
    )

    with pytest.raises(ValueError, match="expected expected, found actual"):
        retrieval._verified_subject_identity(tmp_path, "expected")


def test_python_ast_resolves_self_field_method_to_typed_receiver():
    loader_spans = parse_python_source(
        "google__adk-python",
        "src/google/adk/cli/agent_loader.py",
        (
            "class BaseAgentLoader:\n"
            "    pass\n"
            "\n"
            "class AgentLoader(BaseAgentLoader):\n"
            "    def load_agent(self, app_name):\n"
            "        return app_name\n"
        ),
    )
    server_spans = parse_python_source(
        "google__adk-python",
        "src/google/adk/cli/adk_web_server.py",
        (
            "from .agent_loader import BaseAgentLoader\n"
            "\n"
            "class AdkWebServer:\n"
            "    def __init__(self, agent_loader: BaseAgentLoader):\n"
            "        self.agent_loader = agent_loader\n"
            "\n"
            "    def run_agent(self, app_name):\n"
            "        return self.agent_loader.load_agent(app_name)\n"
        ),
    )
    documents = tuple(span.document for span in (*loader_spans, *server_spans))
    index = RepositoryIndex(documents)
    caller = next(document for document in documents if "run_agent" in document.path)
    callee = next(
        document for document in documents if "AgentLoader.load_agent" in document.path
    )

    assert "BaseAgentLoader.load_agent" in caller.calls
    assert "AdkWebServer.load_agent" not in caller.calls
    assert callee.path in index.graph_neighbors(caller.path, direction="forward")


def test_retrieval_hit_requires_critical_line_inside_retained_context():
    document = CodeDocument(
        repository_id="repo",
        path="service.py::run@10-20",
        text="def run():\n    first()\n    critical()",
        defines=("run",),
    )
    span = PythonDocumentSpan(
        relative_path="service.py",
        start_line=10,
        end_line=20,
        document=document,
    )
    truncated = Evidence(
        evidence_id="graph:service.py::run@10-20",
        path=document.path,
        text="def run():\n    first()",
        retrieval="graph",
        score=1.0,
    )
    partial_critical_line = truncated.model_copy(
        update={"text": "def run():\n    first()\n    crit"}
    )
    centered_critical_line = truncated.model_copy(update={"text": "    critical()\n"})
    full = truncated.model_copy(update={"text": document.text})
    assert _hit([truncated], span, 12) is False
    assert _hit([partial_critical_line], span, 12) is False
    assert _hit([centered_critical_line], span, 12) is True
    assert _hit([full], span, 12) is True
