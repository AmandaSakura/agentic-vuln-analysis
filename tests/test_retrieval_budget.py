from cv_agent.harness import RetrievalBudget, RetrievalMode
from cv_agent.retrieval import RepositoryIndex, context_token_count, limit_evidence_context
from cv_agent.types import Candidate, CodeDocument, Evidence


def test_explicit_bidirectional_graph_budget_admits_caller_only_when_requested():
    service = CodeDocument(repository_id="r", path="service.py", text="def remove(key): return key", defines=("service.remove",))
    route = CodeDocument(repository_id="r", path="route.py", text="def route(key): return remove(key)", calls=("service.remove",))
    unrelated = CodeDocument(repository_id="r", path="unrelated.py", text="route remove key")
    index = RepositoryIndex([service, route, unrelated])
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path=service.path, line=1, query="remove")
    budget = RetrievalBudget(top_k=1, base_context_tokens=32, augmentation_context_tokens=32, graph_hops=1)
    original = index.retrieve_context(candidate, mode=RetrievalMode.GRAPH, budget=budget)
    assert [item.path for item in original] == [service.path]
    both = RetrievalBudget(**{**budget.model_dump(), "graph_direction": "both"})
    result = index.retrieve_context(candidate, mode=RetrievalMode.GRAPH, budget=both)
    assert [item.path for item in result] == [service.path, route.path]
    assert context_token_count(result) <= both.total_context_tokens
    assert result[0] == original[0]


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


def test_focused_graph_context_prefers_security_sink_over_source_only_line():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00012.java::BenchmarkTest00012.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00012.doGet",),
        calls=("BenchmarkTest00012.doPost",),
    )
    filler = "\n".join(f"    int filler{index} = {index};" for index in range(80))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00012.java::BenchmarkTest00012.doPost@5-92",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = request.getHeader("vector");\n'
            f"{filler}\n"
            '    String filter = "(&(uid=" + param + "))";\n'
            "    ctx.search(base, filter, sc);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00012.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=96,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "ctx.search(base, filter, sc)" in augmentation.text
    assert "request.getHeader" in augmentation.text
    assert 'String filter = "(&(uid=" + param + "))"' in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_keeps_sink_assignment_dependencies():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00107.java::BenchmarkTest00107.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00107.doGet",),
        calls=("BenchmarkTest00107.doPost",),
    )
    first_filler = "\n".join(f"    int firstFiller{index} = {index};" for index in range(60))
    second_filler = "\n".join(f"    int secondFiller{index} = {index};" for index in range(60))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00107.java::BenchmarkTest00107.doPost@5-132",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = request.getHeader("vector");\n'
            f"{first_filler}\n"
            '    String g17188 = "barbarians_at_the_gate";\n'
            "    String bar = thing.doSomething(g17188);\n"
            f"{second_filler}\n"
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00107.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=144,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "request.getHeader" in augmentation.text
    assert 'String g17188 = "barbarians_at_the_gate"' in augmentation.text
    assert "String bar = thing.doSomething(g17188)" in augmentation.text
    assert "String sql =" in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_keeps_switch_selector_dependencies():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00192.java::BenchmarkTest00192.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00192.doGet",),
        calls=("BenchmarkTest00192.doPost",),
    )
    first_filler = "\n".join(f"    int firstFiller{index} = {index};" for index in range(40))
    second_filler = "\n".join(f"    int secondFiller{index} = {index};" for index in range(40))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00192.java::BenchmarkTest00192.doPost@5-120",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = request.getHeader("vector");\n'
            f"{first_filler}\n"
            '    String guess = "ABC";\n'
            "    char switchTarget = guess.charAt(2);\n"
            "    switch (switchTarget) {\n"
            "    case 'A':\n"
            "        bar = param;\n"
            "        break;\n"
            "    case 'B':\n"
            '        bar = "safe";\n'
            "        break;\n"
            "    case 'C':\n"
            "    case 'D':\n"
            "        bar = param;\n"
            "        break;\n"
            "    default:\n"
            '        bar = "safe";\n'
            "        break;\n"
            "    }\n"
            f"{second_filler}\n"
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00192.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=256,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert 'String guess = "ABC"' in augmentation.text
    assert "char switchTarget = guess.charAt(2)" in augmentation.text
    assert "switch (switchTarget)" in augmentation.text
    assert "case 'C':" in augmentation.text
    assert "bar = param" in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_keeps_parameter_map_dependencies_into_switch():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00516.java::BenchmarkTest00516.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00516.doGet",),
        calls=("BenchmarkTest00516.doPost",),
    )
    first_filler = "\n".join(f"    int firstFiller{index} = {index};" for index in range(35))
    second_filler = "\n".join(f"    int secondFiller{index} = {index};" for index in range(35))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00516.java::BenchmarkTest00516.doPost@5-120",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            "    java.util.Map<String,String[]> map = request.getParameterMap();\n"
            '    String[] values = map.get("vector");\n'
            '    String param = "";\n'
            "    if (values != null) param = values[0];\n"
            f"{first_filler}\n"
            '    String guess = "ABC";\n'
            "    char switchTarget = guess.charAt(2);\n"
            "    switch (switchTarget) {\n"
            "    case 'C':\n"
            "        bar = param;\n"
            "        break;\n"
            "    default:\n"
            '        bar = "safe";\n'
            "        break;\n"
            "    }\n"
            f"{second_filler}\n"
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00516.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=256,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "request.getParameterMap()" in augmentation.text
    assert 'String[] values = map.get("vector")' in augmentation.text
    assert "param = values[0]" in augmentation.text
    assert "switch (switchTarget)" in augmentation.text
    assert "bar = param" in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_compacts_many_assignment_dependencies():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00839.java::BenchmarkTest00839.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00839.doGet",),
        calls=("BenchmarkTest00839.doPost",),
    )
    filler = "\n".join(f"    int filler{index} = {index};" for index in range(80))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00839.java::BenchmarkTest00839.doPost@5-120",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            "    String queryString = request.getQueryString();\n"
            '    String paramval = "vector"+"=";\n'
            "    int paramLoc = -1;\n"
            "    if (queryString != null) paramLoc = queryString.indexOf(paramval);\n"
            "    String param = queryString.substring(paramLoc + paramval.length());\n"
            "    int ampersandLoc = queryString.indexOf(\"&\", paramLoc);\n"
            "    if (ampersandLoc != -1) {\n"
            "        param = queryString.substring(paramLoc + paramval.length(), ampersandLoc);\n"
            "    }\n"
            "    param = java.net.URLDecoder.decode(param, \"UTF-8\");\n"
            f"{filler}\n"
            "    int num = 106;\n"
            '    bar = (7*42) - num > 200 ? "never" : param;\n'
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00839.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=192,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "request.getQueryString()" in augmentation.text
    assert "queryString.substring" in augmentation.text
    assert "URLDecoder.decode" in augmentation.text
    assert "bar = (7*42) - num > 200" in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_keeps_same_key_collection_put_dependencies():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00113.java::BenchmarkTest00113.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00113.doGet",),
        calls=("BenchmarkTest00113.doPost",),
    )
    first_filler = "\n".join(f"    int firstFiller{index} = {index};" for index in range(40))
    second_filler = "\n".join(f"    int secondFiller{index} = {index};" for index in range(40))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00113.java::BenchmarkTest00113.doPost@5-120",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = request.getHeader("vector");\n'
            f"{first_filler}\n"
            '    map.put("keyA", "safe");\n'
            '    map.put("keyB", param);\n'
            '    bar = (String)map.get("keyB");\n'
            '    bar = (String)map.get("keyA");\n'
            f"{second_filler}\n"
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00113.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=192,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert 'map.put("keyA", "safe")' in augmentation.text
    assert 'map.put("keyB", param)' in augmentation.text
    assert 'map.get("keyA")' in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_keeps_if_condition_dependencies():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00343.java::BenchmarkTest00343.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00343.doGet",),
        calls=("BenchmarkTest00343.doPost",),
    )
    filler = "\n".join(f"    int filler{index} = {index};" for index in range(80))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00343.java::BenchmarkTest00343.doPost@5-120",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = request.getHeader("vector");\n'
            f"{filler}\n"
            "    int num = 86;\n"
            "    if ( (7*42) - num > 200 )\n"
            '        bar = "constant";\n'
            "    else bar = param;\n"
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00343.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=144,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "int num = 86" in augmentation.text
    assert "if ( (7*42) - num > 200 )" in augmentation.text
    assert "else bar = param" in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_focused_graph_context_prioritizes_deep_parameter_name_flow():
    entry = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00594.java::BenchmarkTest00594.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    doPost(request, response);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00594.doGet",),
        calls=("BenchmarkTest00594.doPost",),
    )
    filler = "\n".join(f"    int filler{index} = {index};" for index in range(80))
    do_post = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00594.java::BenchmarkTest00594.doPost@5-120",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = "";\n'
            "    java.util.Enumeration<String> names = request.getParameterNames();\n"
            "    String name = (String) names.nextElement();\n"
            "    param = name;\n"
            f"{filler}\n"
            '    String bar = "safe!";\n'
            "    java.util.HashMap<String,Object> map = new java.util.HashMap<String,Object>();\n"
            '    map.put("keyB", param);\n'
            '    bar = (String)map.get("keyB");\n'
            "    String sql = \"SELECT * FROM users WHERE name='\" + bar + \"'\";\n"
            "    statement.execute(sql);\n"
            "}\n"
        ),
        defines=("BenchmarkTest00594.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=248,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "request.getParameterNames()" in augmentation.text
    assert "names.nextElement()" in augmentation.text
    assert "param = name" in augmentation.text
    assert 'map.put("keyB", param)' in augmentation.text
    assert 'map.get("keyB")' in augmentation.text
    assert "statement.execute(sql)" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_text_context_keeps_query_focus_without_security_sink_boost():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.java::Entry.doGet@1-3",
        text=(
            "public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
            "    response.getWriter();\n"
            "}\n"
        ),
        defines=("Entry.doGet",),
    )
    filler = "\n".join(f"    int filler{index} = {index};" for index in range(80))
    similar_text = CodeDocument(
        repository_id="repo",
        path="similar.java::Similar.doPost@5-92",
        text=(
            "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
            '    String param = request.getHeader("vector");\n'
            f"{filler}\n"
            '    String filter = "(&(uid=" + param + "))";\n'
            "    ctx.search(base, filter, sc);\n"
            "}\n"
        ),
        defines=("Similar.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=48,
        graph_hops=0,
    )

    context = RepositoryIndex([entry, similar_text]).retrieve_context(
        candidate,
        mode=RetrievalMode.TEXT,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == similar_text.path][0]

    assert "request.getHeader" in augmentation.text
    assert "ctx.search(base, filter, sc)" not in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_graph_context_keeps_complete_multiline_security_sink_statement():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.java::Entry.doGet@1-3",
        text="void doGet() { doPost(); }",
        defines=("Entry.doGet",),
        calls=("Entry.doPost",),
    )
    filler = "\n".join(f"int filler{index} = {index};" for index in range(40))
    do_post = CodeDocument(
        repository_id="repo",
        path="entry.java::Entry.doPost@5-60",
        text=(
            "void doPost() {\n"
            'String param = request.getHeader("vector");\n'
            f"{filler}\n"
            'String sql = "SELECT " + param;\n'
            "CallableStatement statement = connection.prepareCall( sql,\n"
            "    ResultSet.TYPE_FORWARD_ONLY,\n"
            "    ResultSet.CONCUR_READ_ONLY );\n"
            "}\n"
        ),
        defines=("Entry.doPost",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=128,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, do_post]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "connection.prepareCall( sql," in augmentation.text
    assert "ResultSet.CONCUR_READ_ONLY );" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


def test_graph_context_prioritizes_entry_callee_under_shared_budget():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.java::Entry.doGet@1-3",
        text="void doGet() { doPost(); }",
        defines=("Entry.doGet",),
        calls=("Entry.doPost",),
    )
    filler = "\n".join(f"int filler{index} = {index};" for index in range(90))
    helper_calls = tuple(f"Helper{index}.run" for index in range(5))
    do_post = CodeDocument(
        repository_id="repo",
        path="entry.java::Entry.doPost@5-150",
        text=(
            "void doPost() {\n"
            'String param = request.getParameterNames().nextElement();\n'
            f"{filler}\n"
            'String guess = "ABC";\n'
            "char switchTarget = guess.charAt(2);\n"
            "switch (switchTarget) {\n"
            "case 'A': bar = param; break;\n"
            'case \'B\': bar = "safe"; break;\n'
            "case 'C': bar = param; break;\n"
            "default: bar = \"safe\"; break;\n"
            "}\n"
            'String sql = "SELECT " + bar;\n'
            "CallableStatement statement = connection.prepareCall( sql,\n"
            "    ResultSet.TYPE_FORWARD_ONLY,\n"
            "    ResultSet.CONCUR_READ_ONLY );\n"
            "}\n"
        ),
        defines=("Entry.doPost",),
        calls=helper_calls,
    )
    helpers = [
        CodeDocument(
            repository_id="repo",
            path=f"Helper{index}.java::Helper{index}.run@1-20",
            text=("void run() {\n" + "int value = 1;\n" * 30 + "}\n"),
            defines=(f"Helper{index}.run",),
        )
        for index in range(5)
    ]
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    budget = RetrievalBudget(
        top_k=6,
        base_context_tokens=32,
        augmentation_context_tokens=1488,
        graph_hops=2,
    )

    context = RepositoryIndex([entry, do_post, *helpers]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=budget,
    )
    augmentation = [item for item in context if item.path == do_post.path][0]

    assert "request.getParameterNames()" in augmentation.text
    assert "switchTarget = guess.charAt(2)" in augmentation.text
    assert "connection.prepareCall( sql," in augmentation.text
    assert "ResultSet.CONCUR_READ_ONLY );" in augmentation.text
    assert context_token_count(context) <= budget.total_context_tokens


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


def test_hybrid_context_combines_text_and_graph_under_shared_budget():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.py",
        text="def entry():\n    return graph_target()\n",
        defines=("entry",),
        calls=("graph_target",),
    )
    graph_target = CodeDocument(
        repository_id="repo",
        path="graph_target.py",
        text="def graph_target():\n    return graph_sink()\n",
        defines=("graph_target",),
    )
    text_only = CodeDocument(
        repository_id="repo",
        path="text_only.py",
        text="def disconnected():\n    return text_sink(needle)\n",
        defines=("disconnected",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path="entry.py",
        line=1,
        query="graph_target needle",
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=48,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, graph_target, text_only]).retrieve_context(
        candidate,
        mode=RetrievalMode.HYBRID,
        budget=budget,
    )

    assert "graph_target.py" in {item.path for item in context}
    assert "text_only.py" in {item.path for item in context}
    assert context_token_count(context) <= budget.total_context_tokens


def test_hybrid_top_k_zero_keeps_only_base_context():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.py",
        text="def entry():\n    return graph_target()\n",
        defines=("entry",),
        calls=("graph_target",),
    )
    graph_target = CodeDocument(
        repository_id="repo",
        path="graph_target.py",
        text="def graph_target():\n    return graph_sink()\n",
        defines=("graph_target",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path="entry.py",
        line=1,
        query="graph_target",
    )
    budget = RetrievalBudget(
        top_k=0,
        base_context_tokens=32,
        augmentation_context_tokens=48,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, graph_target]).retrieve_context(
        candidate,
        mode=RetrievalMode.HYBRID,
        budget=budget,
    )

    assert [item.path for item in context] == ["entry.py"]
    assert context_token_count(context) <= budget.base_context_tokens


def test_hybrid_branch_top_k_is_applied_after_candidate_filtering():
    entry = CodeDocument(
        repository_id="repo",
        path="entry.py",
        text="def entry():\n    return None\n",
        defines=("entry",),
    )
    first_text = CodeDocument(
        repository_id="repo",
        path="a_text.py",
        text="def first():\n    return needle\n",
        defines=("first",),
    )
    second_text = CodeDocument(
        repository_id="repo",
        path="b_text.py",
        text="def second():\n    return needle\n",
        defines=("second",),
    )
    candidate = Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path="entry.py",
        line=1,
        query="needle",
    )
    budget = RetrievalBudget(
        top_k=1,
        base_context_tokens=32,
        augmentation_context_tokens=48,
        graph_hops=1,
    )

    context = RepositoryIndex([entry, first_text, second_text]).retrieve_context(
        candidate,
        mode=RetrievalMode.HYBRID,
        budget=budget,
    )

    assert "a_text.py" in {item.path for item in context}
    assert "b_text.py" not in {item.path for item in context}
    assert context_token_count(context) <= budget.total_context_tokens
