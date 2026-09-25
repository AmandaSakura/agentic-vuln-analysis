"""Regression tests for semantic consistency across discovery, validation, and evidence policy."""

import json
import pytest

from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import (
    ReActStep,
    ToolObservation,
    ValidationStatus,
    ValidationSubject,
)
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.agents.scanner import StaticScanner
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.dataflow import trace_dataflow
from cv_agent.tools.validation.models import (
    CommandConstructionInput,
    TraceDataflowInput,
)
from cv_agent.tools.validation.patterns import (
    SANITIZER_RULES,
    SINK_RULES,
    _matching_lines,
)
from cv_agent.tools.validation.registry import validation_tools


def test_commented_sanitizers_do_not_produce_findings_or_pass_safe_evidence():
    code_with_comment = """def entry(request):
    # int(value) was considered but is NOT applied
    # shlex.quote(value) is also commented out
    return eval(request.args["x"])
"""
    code_real_sanitizer = """def entry(request):
    val = int(request.args["x"])
    return val
"""
    doc_comment = CodeDocument(
        repository_id="test", path="test.py", text=code_with_comment, language="python"
    )
    doc_real = CodeDocument(
        repository_id="test", path="test.py", text=code_real_sanitizer, language="python"
    )

    findings_comment = _matching_lines(doc_comment, SANITIZER_RULES)
    findings_real = _matching_lines(doc_real, SANITIZER_RULES)

    assert findings_comment == [], "Comments must not be treated as sanitizer findings"
    assert len(findings_real) == 1
    assert findings_real[0]["category"] == "numeric-validation"

    obs = ToolObservation(
        tool="find_sanitizers",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({"findings": findings_comment, "path": "test.py"}),
        citation_id="tool:find_sanitizers:1",
        evidence_ids=("tool:find_sanitizers:1",),
    )
    step = ReActStep(
        step=1,
        model_id="test",
        tool_call=ModelToolCall(call_id="c1", name="find_sanitizers", arguments={"path": "test.py"}),
        observation=obs,
    )
    vote = AgentExpertConclusion(
        expert="taint",
        label="SAFE",
        confidence=0.95,
        rationale="Sanitizer found in code",
        evidence_ids=["tool:find_sanitizers:1"],
        supporting_observation_ids=["tool:find_sanitizers:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        validation_status=ValidationStatus.UNRESOLVED,
    )

    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        validate_conclusion(vote, [step], frozenset(["tool:find_sanitizers:1"]))


def test_string_literal_sanitizers_do_not_produce_findings_or_pass_safe_evidence():
    code_with_string = """def entry(request):
    note = "int(value)"
    return eval(request.args["x"])
"""
    doc = CodeDocument(
        repository_id="test", path="test.py", text=code_with_string, language="python"
    )
    findings = _matching_lines(doc, SANITIZER_RULES)
    assert findings == [], "String literals must not be treated as sanitizer findings"

    obs = ToolObservation(
        tool="find_sanitizers",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({"findings": findings, "path": "test.py"}),
        citation_id="tool:find_sanitizers:1",
        evidence_ids=("tool:find_sanitizers:1",),
    )
    step = ReActStep(
        step=1,
        model_id="test",
        tool_call=ModelToolCall(call_id="c1", name="find_sanitizers", arguments={"path": "test.py"}),
        observation=obs,
    )
    vote = AgentExpertConclusion(
        expert="taint",
        label="SAFE",
        confidence=0.95,
        rationale="Sanitizer found in code",
        evidence_ids=["tool:find_sanitizers:1"],
        supporting_observation_ids=["tool:find_sanitizers:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        validation_status=ValidationStatus.UNRESOLVED,
    )

    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        validate_conclusion(vote, [step], frozenset(["tool:find_sanitizers:1"]))


def test_javascript_urls_and_private_fields_are_not_falsely_treated_as_comments():
    # URL containing '//' must not mask the following statement
    js_url = 'const url="https://example.test"; child_process.exec(req.query.cmd);'
    doc_url = CodeDocument(repository_id="test", path="test.js", text=js_url, language="javascript")
    sinks_url = _matching_lines(doc_url, SINK_RULES)
    assert len(sinks_url) == 1
    assert sinks_url[0]["category"] == "command-execution"

    # JS private field with '#' must not be treated as a line comment
    js_private = 'class Foo {\n    #eval = eval(req);\n}'
    doc_priv = CodeDocument(repository_id="test", path="test.js", text=js_private, language="javascript")
    sinks_priv = _matching_lines(doc_priv, SINK_RULES)
    assert len(sinks_priv) == 1
    assert sinks_priv[0]["category"] == "code-execution"

    # JS regex literal containing quote must not mask subsequent code
    js_regex = 'const regex = /"/; eval(req.query.x); const text = "ok";'
    doc_regex = CodeDocument(repository_id="test", path="test.js", text=js_regex, language="javascript")
    sinks_regex = _matching_lines(doc_regex, SINK_RULES)
    assert len(sinks_regex) == 1
    assert sinks_regex[0]["category"] == "code-execution"

    # JS regex containing '}' inside template interpolation must not mask code
    js_regex_tmpl = "const t = `${ /}/ ; eval(req.query.y) };`;"
    doc_regex_tmpl = CodeDocument(repository_id="test", path="test.js", text=js_regex_tmpl, language="javascript")
    sinks_regex_tmpl = _matching_lines(doc_regex_tmpl, SINK_RULES)
    assert len(sinks_regex_tmpl) == 1
    assert sinks_regex_tmpl[0]["category"] == "code-execution"

    # Non-ASCII characters in JS strings must not cause byte-to-char offset misalignment
    js_cjk = 'const x = "中文"; eval(req.query.x);'
    doc_cjk = CodeDocument(repository_id="test", path="test.js", text=js_cjk, language="javascript")
    sinks_cjk = _matching_lines(doc_cjk, SINK_RULES)
    assert len(sinks_cjk) == 1
    assert sinks_cjk[0]["category"] == "code-execution"


def test_deeply_nested_ast_iterative_traversal_avoids_recursion_error():
    # 1200 layers of parentheses + comment must be handled iteratively without RecursionError or silent fallback
    code_1200 = "(" * 1200 + "1" + ")" * 1200 + " // int(value)"
    doc_1200 = CodeDocument(repository_id="test", path="test.js", text=code_1200, language="javascript")
    findings_1200 = _matching_lines(doc_1200, SANITIZER_RULES)
    assert findings_1200 == [], "Deeply nested JS comment must be ignored and produce 0 sanitizer findings"


@pytest.mark.parametrize("helper_name", ["build_cmd", "make_cmd", "get_cmd"])
def test_command_construction_helper_name_independence(helper_name):
    caller_code = f"""
def entry(request):
    cmd = {helper_name}(request.args["arg"])
    import os
    os.system(cmd)
"""
    callee_code = f"""
def {helper_name}(val):
    return "ls " + val
"""
    doc_caller = CodeDocument(
        repository_id="test",
        path="caller.py",
        text=caller_code,
        language="python",
        defines=("entry",),
        calls=(helper_name, "os.system"),
    )
    doc_callee = CodeDocument(
        repository_id="test",
        path="callee.py",
        text=callee_code,
        language="python",
        defines=(helper_name,),
    )
    index = RepositoryIndex([doc_caller, doc_callee])
    tools = validation_tools(index)
    inspect_tool = next((t for t in tools if t.name == "inspect_command_construction"), None)
    assert inspect_tool is not None
    assert inspect_tool.available is True, f"Tool should be available for {helper_name}"

    registry = ToolRegistry(tools, max_output_bytes=4096)
    scope = ToolExecutionScope(
        candidate_path="caller.py",
        admitted_paths=frozenset(["caller.py", "callee.py"]),
        max_observation_tokens=2000,
    )
    call = ModelToolCall(
        call_id="c1",
        name="inspect_command_construction",
        arguments={"source_path": "caller.py"},
    )
    res = registry.invoke(call, allowed=["inspect_command_construction"], scope=scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert len(content["helpers"]) == 1
    assert content["helpers"][0]["status"] == "UNSANITIZED"


@pytest.mark.parametrize("loop_code", [
    """def entry(request):
    for _ in [1]:
        value = request.args["x"]
        break
    eval(value)
""",
    """def entry(request):
    while True:
        value = request.args["x"]
        break
    eval(value)
""",
    """def entry(request):
    for item in [1, 2]:
        if item == 1:
            value = request.args["x"]
            break
    eval(value)
""",
])
def test_taint_propagation_across_loop_break(loop_code):
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=loop_code,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    inp = TraceDataflowInput(source_path="test.py")
    res = trace_dataflow(index, inp, scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "MAY_REACH", f"Expected MAY_REACH for loop with break:\n{loop_code}"


def test_loop_break_state_does_not_leak_into_loop_else():
    # Break path bypasses else: so eval(value) in else should NOT be tainted
    code_break_else = """def entry(request):
    for _ in [1]:
        value = request.args["x"]
        break
    else:
        eval(value)
"""
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code_break_else,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    inp = TraceDataflowInput(source_path="test.py")
    res = trace_dataflow(index, inp, scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "NOT_ESTABLISHED", "Break path must not execute loop else"


def test_try_finally_overwrites_break_taint():
    # Finally runs before break exits, so value="0" clears the taint
    code_finally_clears = """def entry(request):
    while True:
        try:
            value = request.args["x"]
            break
        finally:
            value = "0"
    eval(value)
"""
    doc_clears = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code_finally_clears,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc_clears])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    inp = TraceDataflowInput(source_path="test.py")
    res = trace_dataflow(index, inp, scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "NOT_ESTABLISHED", "finally: value='0' should clear taint"

    # Finally without reassignment preserves the taint
    code_finally_preserves = """def entry(request):
    while True:
        try:
            value = request.args["x"]
            break
        finally:
            pass
    eval(value)
"""
    doc_preserves = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code_finally_preserves,
        language="python",
        defines=("entry",),
    )
    index2 = RepositoryIndex([doc_preserves])
    res2 = trace_dataflow(index2, inp, scope)
    assert res2.status == "ok"
    content2 = json.loads(res2.content)
    assert content2["flow_status"] == "MAY_REACH", "finally without reassignment should preserve taint"


def test_returned_branch_in_try_does_not_leak_into_normal_successor():
    # value is '0'. A conditional branch inside try taints value and returns.
    # The normal path that reaches eval(value) has value == '0' and should NOT be tainted.
    code = """def entry(request):
    value = "0"
    try:
        if request.args.get("flag"):
            value = request.args["x"]
            return
    finally:
        pass
    eval(value)
"""
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    res = trace_dataflow(index, TraceDataflowInput(source_path="test.py"), scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "NOT_ESTABLISHED", "Taint from returned branch in try must not leak into normal successor"


@pytest.mark.parametrize("call_expr", [
    "subprocess.check_output(request.args['x'], shell=True)",
    "subprocess.check_call(request.args['x'], shell=True)",
    "subprocess.getoutput(request.args['x'])",
    "os.popen(request.args['x'])",
])
def test_sink_api_consistency_across_scanner_and_dataflow(call_expr):
    code = f"""
import subprocess
import os

def entry(request):
    {call_expr}
"""
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code,
        language="python",
        defines=("entry",),
    )
    scanner = StaticScanner()
    candidates = scanner.scan("test", [doc])
    assert len(candidates) == 1
    assert candidates[0].metadata["rule"] == "command-execution"

    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    inp = TraceDataflowInput(source_path="test.py")
    res = trace_dataflow(index, inp, scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "MAY_REACH", f"Dataflow should detect tainted sink for {call_expr}"


def test_static_scanner_discovers_chmod_candidates():
    code = """
import os

def apply_permissions(path):
    os.chmod(path, 0o777)
"""
    doc = CodeDocument(
        repository_id="test",
        path="perm.py",
        text=code,
        language="python",
        defines=("apply_permissions",),
    )
    scanner = StaticScanner()
    candidates = scanner.scan("test", [doc])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.metadata["rule"] == "permission-mode"
    assert "os.chmod" in candidate.query
    assert "os.chmod" in candidate.analysis_scope


def test_return_into_finally_preserves_taint():
    code = """def entry(request):
    value = request.args["x"]
    try:
        return 0
    finally:
        eval(value)
"""
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    res = trace_dataflow(index, TraceDataflowInput(source_path="test.py"), scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "MAY_REACH", "Return into finally should preserve taint in finally block"


def test_finally_return_dead_code_no_type_error():
    code = """def entry(request):
    for _ in [1]:
        try:
            break
        finally:
            return 0
        eval(value)
"""
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    res = trace_dataflow(index, TraceDataflowInput(source_path="test.py"), scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "NOT_ESTABLISHED", "Dead code after finally return should not be analyzed"


def test_js_template_interpolation_detects_sink():
    js_interp = "const x = `${eval(req.query.x)}`;"
    doc_interp = CodeDocument(repository_id="test", path="test.js", text=js_interp, language="javascript")
    sinks_interp = _matching_lines(doc_interp, SINK_RULES)
    assert len(sinks_interp) == 1
    assert sinks_interp[0]["category"] == "code-execution"

    js_plain = "const x = `eval(req.query.x)`;"
    doc_plain = CodeDocument(repository_id="test", path="test.js", text=js_plain, language="javascript")
    sinks_plain = _matching_lines(doc_plain, SINK_RULES)
    assert len(sinks_plain) == 0, "Plain template literal text must not match as a sink"


def test_safe_vote_with_not_established_command_inspection_rejected():
    subject = ValidationSubject(
        candidate_id="c1",
        repository_id="r1",
        entry_path="test.py",
        source_digest="abc",
    )
    obs_sanitizer = ToolObservation(
        tool="find_sanitizers",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({"findings": [{"text": "int(request.args['x'])"}], "path": "test.py"}),
        citation_id="tool:sanitizer:1",
        evidence_ids=("tool:sanitizer:1",),
    )
    obs_cmd_inspection = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({"command_construction_status": "NOT_ESTABLISHED", "path": "test.py"}),
        citation_id="tool:cmd:1",
        evidence_ids=("tool:cmd:1",),
    )
    obs_static = ToolObservation(
        tool="run_static_check",
        status="ok",
        content=json.dumps({"findings": [{"category": "command-execution"}]}),
        citation_id="tool:static:1",
        evidence_ids=("tool:static:1",),
    )

    step_san = ReActStep(
        step=1, model_id="m",
        tool_call=ModelToolCall(call_id="c1", name="find_sanitizers", arguments={}),
        observation=obs_sanitizer,
    )
    step_cmd = ReActStep(
        step=2, model_id="m",
        tool_call=ModelToolCall(call_id="c2", name="inspect_command_construction", arguments={}),
        observation=obs_cmd_inspection,
    )
    step_stat = ReActStep(
        step=3, model_id="m",
        tool_call=ModelToolCall(call_id="c3", name="run_static_check", arguments={}),
        observation=obs_static,
    )

    vote = AgentExpertConclusion(
        expert="scan",
        label="SAFE",
        confidence=0.85,
        rationale="Sanitized and no command execution established",
        evidence_ids=["tool:sanitizer:1", "tool:cmd:1", "tool:static:1"],
        supporting_observation_ids=["tool:sanitizer:1", "tool:cmd:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=["tool:static:1"],
        validation_status=ValidationStatus.UNRESOLVED,
    )

    # Moving the static finding to unresolved citations cannot establish safety.
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(
            vote, [step_san, step_cmd, step_stat],
            frozenset(["tool:sanitizer:1", "tool:cmd:1", "tool:static:1"]),
            subject=subject,
        )


def test_implicit_exception_in_try_preserves_taint_into_finally():
    # If int(value) fails (implicit ValueError on invalid user input like "1+1"),
    # finally runs with the original un-sanitized taint
    code = """def entry(request):
    value = request.args["x"]
    try:
        value = int(value)
    finally:
        eval(value)
"""
    doc = CodeDocument(
        repository_id="test",
        path="test.py",
        text=code,
        language="python",
        defines=("entry",),
    )
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(
        candidate_path="test.py",
        admitted_paths=frozenset(["test.py"]),
        max_observation_tokens=2000,
    )
    res = trace_dataflow(index, TraceDataflowInput(source_path="test.py"), scope)
    assert res.status == "ok"
    content = json.loads(res.content)
    assert content["flow_status"] == "MAY_REACH", "Implicit exception in try must preserve taint into finally"


@pytest.mark.parametrize("status, should_accept", [
    ("NOT_ESTABLISHED", False),
    ("AMBIGUOUS", False),
    ("UNAVAILABLE", False),
    ("UNSANITIZED", True),
])
def test_command_inspection_for_vulnerable_requires_conclusive_unsanitized(status, should_accept):
    subject = ValidationSubject(
        candidate_id="c1",
        repository_id="r1",
        entry_path="test.py",
        source_digest="abc",
    )
    obs_static = ToolObservation(
        tool="run_static_check",
        status="ok",
        content=json.dumps({"findings": [{"category": "command-execution"}], "callee": "get_cmd"}),
        citation_id="tool:static:1",
        evidence_ids=("tool:static:1",),
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({"command_construction_status": status, "path": "test.py"}),
        citation_id="tool:cmd:1",
        evidence_ids=("tool:cmd:1",),
    )
    step1 = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="run_static_check", arguments={}), observation=obs_static)
    step2 = ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="inspect_command_construction", arguments={}), observation=obs_cmd)

    vote = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.85,
        rationale="Command injection assessment",
        evidence_ids=["tool:static:1", "tool:cmd:1"],
        supporting_observation_ids=["tool:static:1", "tool:cmd:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        validation_status=ValidationStatus.UNRESOLVED,
    )
    if should_accept:
        validate_conclusion(vote, [step1, step2], frozenset(["tool:static:1", "tool:cmd:1"]), subject=subject)
    else:
        with pytest.raises(ValueError, match="inspect_command_construction"):
            validate_conclusion(vote, [step1, step2], frozenset(["tool:static:1", "tool:cmd:1"]), subject=subject)


def test_svelte_template_attribute_expressions_are_not_masked():
    code = '<button on:click="{() => eval(code)}">Click</button>'
    doc = CodeDocument(repository_id="test", path="App.svelte", text=code, language="svelte")
    sinks = _matching_lines(doc, SINK_RULES)
    assert len(sinks) == 1
    assert sinks[0]["category"] == "code-execution"
    assert sinks[0]["match"] == "eval("


def test_shell_script_inline_hash_in_quotes_is_not_treated_as_comment():
    code_inline = 'python -c "marker=\'#\'; eval(input())"'
    doc_inline = CodeDocument(repository_id="test", path="script.sh", text=code_inline, language="shell")
    sinks_inline = _matching_lines(doc_inline, SINK_RULES)
    assert len(sinks_inline) == 1
    assert sinks_inline[0]["category"] == "code-execution"
    assert sinks_inline[0]["match"] == "eval("

    code_comment = '# python -c "marker=\'#\'; eval(input())"'
    doc_comment = CodeDocument(repository_id="test", path="script.sh", text=code_comment, language="shell")
    sinks_comment = _matching_lines(doc_comment, SINK_RULES)
    assert len(sinks_comment) == 0, "Line starting with # must be treated as a comment"


def test_nested_try_finally_does_not_exponentially_duplicate_sinks():
    indent = "    "
    lines = ["def entry(request):", "    value = request.args[\"x\"]"]
    depth = 10
    for i in range(depth):
        lines.append(indent * (i + 1) + "try:")
        lines.append(indent * (i + 2) + "pass")
        lines.append(indent * (i + 1) + "finally:")
    lines.append(indent * (depth + 1) + "eval(value)")
    code = "\n".join(lines)

    doc = CodeDocument(repository_id="test", path="test.py", text=code, language="python", defines=("entry",))
    index = RepositoryIndex([doc])
    scope = ToolExecutionScope(candidate_path="test.py", admitted_paths=frozenset(["test.py"]), max_observation_tokens=50000)
    res = trace_dataflow(index, TraceDataflowInput(source_path="test.py"), scope)
    data = json.loads(res.content)
    sinks = data["trace"][0]["sinks"] if data["trace"] else []
    assert len(sinks) == 1, f"Expected 1 sink without exponential duplication, got {len(sinks)}"
    assert sinks[0]["tainted"] is True


def test_nested_try_return_finally_does_not_exponentially_duplicate_bindings():
    from cv_agent.tools.analysis.python_flow import python_document_flow
    from cv_agent.tools.validation.patterns import SOURCE_RULES, SANITIZER_RULES
    indent = "    "
    lines = ["def entry(request):", "    value = request.args[\"x\"]"]
    depth = 10
    for i in range(depth):
        lines.append(indent * (i + 1) + "try:")
        lines.append(indent * (i + 2) + "return")
        lines.append(indent * (i + 1) + "finally:")
    lines.append(indent * (depth + 1) + "eval(value)")
    code = "\n".join(lines)

    doc = CodeDocument(repository_id="test", path="test.py", text=code, language="python", defines=("entry",))
    res = python_document_flow(
        doc, initial_tainted=(), sink_category="code-execution",
        source_rules=SOURCE_RULES, sink_rules=SINK_RULES, sanitizer_rules=SANITIZER_RULES,
    )
    bindings = res["call_bindings"] if res else []
    sinks = res["sinks"] if res else []
    assert len(bindings) == 1, f"Expected 1 call binding, got {len(bindings)}"
    assert len(sinks) == 1, f"Expected 1 sink, got {len(sinks)}"


def test_loop_backedge_propagates_to_subsequent_break():
    code_loop = """def entry(request):
    value = "0"
    first = True
    while True:
        if not first:
            break
        value = request.args["x"]
        first = False
    eval(value)
"""
    doc_loop = CodeDocument(repository_id="test", path="test.py", text=code_loop, language="python", defines=("entry",))
    res_loop = trace_dataflow(RepositoryIndex([doc_loop]), TraceDataflowInput(source_path="test.py"), ToolExecutionScope(candidate_path="test.py", admitted_paths=frozenset(["test.py"]), max_observation_tokens=2000))
    assert "MAY_REACH" in res_loop.content, "Loop backedge should propagate taint to subsequent break"


def test_nested_try_exception_propagates_to_outer_finally():
    code_nested_try = """def entry(request):
    try:
        value = request.args["x"]
        try:
            value = int(value)
        finally:
            pass
    finally:
        eval(value)
"""
    doc_try = CodeDocument(repository_id="test", path="test.py", text=code_nested_try, language="python", defines=("entry",))
    res_try = trace_dataflow(RepositoryIndex([doc_try]), TraceDataflowInput(source_path="test.py"), ToolExecutionScope(candidate_path="test.py", admitted_paths=frozenset(["test.py"]), max_observation_tokens=2000))
    assert "MAY_REACH" in res_try.content, "Nested try unhandled exception should propagate to outer finally"


def test_helper_internal_sinks_are_merged_into_caller():
    from cv_agent.tools.analysis.commands import analyze_command, command_status
    helper_code = """
def build_cmd(value):
    import os
    os.system(value)
    return "echo ok"
"""
    caller_code = """
def entry(value):
    import os
    cmd = build_cmd(value)
    os.system(cmd)
"""
    doc_helper = CodeDocument(repository_id="t", path="h.py", text=helper_code, language="python", defines=("build_cmd",))
    doc_caller = CodeDocument(repository_id="t", path="c.py", text=caller_code, language="python", defines=("entry",), calls=("build_cmd", "os.system"))

    analysis = analyze_command(doc_caller, (doc_helper,))
    status = command_status(analysis)
    assert status == "UNSANITIZED", f"Expected UNSANITIZED, got {status}"


def test_unsupported_helper_semantics_are_preserved_in_command_analysis():
    from cv_agent.tools.analysis.commands import analyze_command, command_status
    audit_code = """
def audit(msg):
    try:
        pass
    except Exception:
        pass
"""
    caller_code = """
def entry(value):
    import os
    audit("starting")
    os.system("echo " + value)
"""
    doc_audit = CodeDocument(repository_id="t", path="a.py", text=audit_code, language="python", defines=("audit",))
    doc_caller = CodeDocument(repository_id="t", path="c.py", text=caller_code, language="python", defines=("entry",), calls=("audit", "os.system"))

    analysis = analyze_command(doc_caller, (doc_audit,))
    status = command_status(analysis)
    assert status == "AMBIGUOUS", f"Expected AMBIGUOUS, got {status}"
    assert analysis.issues == ["helper: unsupported statement: Try"]
