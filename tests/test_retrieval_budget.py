from cv_agent.harness import RetrievalBudget, RetrievalMode
from cv_agent.retrieval import RepositoryIndex, context_token_count, limit_evidence_context
from cv_agent.types import Candidate, CodeDocument, Evidence


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


def test_retrieve_context_focuses_long_local_span_on_query_line():
    filler = "\n".join(f"    filler_{index} = 0" for index in range(80))
    text = f"def configure():\n{filler}\n    danger_marker = JWTIssuer(audience=value)\n"
    document = CodeDocument(
        repository_id="repo",
        path="long.py::configure@1-82",
        text=text,
        defines=("configure",),
        calls=("JWTIssuer",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=document.path,
        line=1,
        query="JWTIssuer danger_marker",
    )
    budget = RetrievalBudget(
        top_k=0,
        base_context_tokens=32,
        augmentation_context_tokens=0,
        graph_hops=1,
    )

    context = RepositoryIndex([document]).retrieve_context(
        candidate,
        mode=RetrievalMode.LOCAL,
        budget=budget,
    )

    assert len(context) == 1
    assert "danger_marker = JWTIssuer" in context[0].text
    assert context_token_count(context) <= budget.base_context_tokens


def test_focused_local_context_expands_around_selected_line():
    before = "\n".join(f"    pre_filler_{index} = 0" for index in range(40))
    after = "\n".join(f"    post_filler_{index} = 0" for index in range(40))
    text = (
        "def configure():\n"
        f"{before}\n"
        "    before_context = keep_me\n"
        "    danger_marker = JWTIssuer(audience=value)\n"
        "    after_context = keep_too\n"
        f"{after}\n"
    )
    document = CodeDocument(
        repository_id="repo",
        path="long.py::configure@1-84",
        text=text,
        defines=("configure",),
        calls=("JWTIssuer",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=document.path,
        line=1,
        query="JWTIssuer danger_marker",
    )
    budget = RetrievalBudget(
        top_k=0,
        base_context_tokens=40,
        augmentation_context_tokens=0,
        graph_hops=1,
    )

    context = RepositoryIndex([document]).retrieve_context(
        candidate,
        mode=RetrievalMode.LOCAL,
        budget=budget,
    )

    assert "before_context = keep_me" in context[0].text
    assert "danger_marker = JWTIssuer" in context[0].text
    assert "after_context = keep_too" in context[0].text
    assert context_token_count(context) <= budget.base_context_tokens


def test_focused_local_context_prefers_distinct_query_terms_over_repetition():
    before = "\n".join(f"    pre_filler_{index} = 0" for index in range(40))
    after = "\n".join(f"    post_filler_{index} = 0" for index in range(40))
    text = (
        "def configure():\n"
        f"{before}\n"
        "    redirect_path = redirect_path.startswith(redirect_path)\n"
        f"{after}\n"
        "    self._jwt_issuer = JWTIssuer(\n"
        "        audience=f\"{str(self.base_url).rstrip('/')}/mcp\",\n"
        "    )\n"
    )
    document = CodeDocument(
        repository_id="repo",
        path="long.py::configure@1-85",
        text=text,
        defines=("configure",),
        calls=("JWTIssuer", "rstrip", "startswith"),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=document.path,
        line=1,
        query="redirect_path JWTIssuer audience rstrip base_url",
    )
    budget = RetrievalBudget(
        top_k=0,
        base_context_tokens=40,
        augmentation_context_tokens=0,
        graph_hops=1,
    )

    context = RepositoryIndex([document]).retrieve_context(
        candidate,
        mode=RetrievalMode.LOCAL,
        budget=budget,
    )

    assert "self._jwt_issuer = JWTIssuer" in context[0].text
    assert "audience=" in context[0].text
    assert "redirect_path = redirect_path.startswith" not in context[0].text
    assert context_token_count(context) <= budget.base_context_tokens


def test_hybrid_context_budget_does_not_starve_graph_neighbor_after_long_seed():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.py",
        text="def entry():\n    return target()\n",
        defines=("entry",),
        calls=("target",),
    )
    long_seed = CodeDocument(
        repository_id="repo",
        path="long_seed.py",
        text="def long_seed():\n" + "\n".join("    needle = needle + 1" for _ in range(80)),
        defines=("long_seed",),
    )
    target = CodeDocument(
        repository_id="repo",
        path="target.py",
        text="def target():\n    return critical_sink()\n",
        defines=("target",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path="entry.py",
        line=1,
        query="needle target",
    )
    budget = RetrievalBudget(
        top_k=2,
        base_context_tokens=32,
        augmentation_context_tokens=32,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, long_seed, target]).retrieve_context(
        candidate,
        mode=RetrievalMode.HYBRID,
        budget=budget,
    )

    assert "target.py" in {item.path for item in context}
    assert any("critical_sink" in item.text for item in context)
    assert context_token_count(context) <= budget.total_context_tokens
