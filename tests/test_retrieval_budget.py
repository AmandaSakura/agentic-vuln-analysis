from cv_agent.retrieval import context_token_count, limit_evidence_context
from cv_agent.types import Evidence


def _evidence(path: str, text: str) -> Evidence:
    return Evidence(
        evidence_id=f"text:{path}",
        path=path,
        text=text,
        retrieval="text",
        score=1.0,
    )


def test_context_budget_is_shared_across_ranked_documents():
    evidence = [
        _evidence("one.py", "alpha = beta + gamma"),
        _evidence("two.py", "delta = epsilon"),
    ]
    limited = limit_evidence_context(evidence, token_budget=7)
    assert context_token_count(limited) == 7
    assert [item.path for item in limited] == ["one.py", "two.py"]
    assert limited[1].text == "delta ="


def test_context_budget_truncates_before_lower_ranked_evidence():
    evidence = [
        _evidence("one.py", "alpha beta gamma delta"),
        _evidence("two.py", "epsilon zeta"),
    ]
    limited = limit_evidence_context(evidence, token_budget=3)
    assert context_token_count(limited) == 3
    assert [item.path for item in limited] == ["one.py"]
    assert limited[0].text == "alpha beta gamma"
