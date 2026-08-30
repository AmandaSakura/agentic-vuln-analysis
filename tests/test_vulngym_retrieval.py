from cv_agent.python_ast import PythonDocumentSpan
from cv_agent.types import CodeDocument, Evidence
from cv_agent.vulngym_retrieval import _hit


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
    full = truncated.model_copy(update={"text": document.text})
    assert _hit([truncated], span, 12) is False
    assert _hit([partial_critical_line], span, 12) is False
    assert _hit([full], span, 12) is True
