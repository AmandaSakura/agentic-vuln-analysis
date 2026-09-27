"""Offline regressions for permission completeness and command argv semantics."""

import json

import pytest

from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep, ValidationStatus, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.analysis.commands import analyze_command, command_status
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope
from test_taint_regressions import trace
from test_validation_tools import _invoke, _registry


def permission_result(body, *, booleans=None):
    document = CodeDocument(
        repository_id="diagnostic",
        path="permission.py::entry@1-20",
        text="def entry(path, enabled):\n    " + body + "\n",
    )
    index = RepositoryIndex([document])
    subject = ValidationSubject(
        # C1: these controls assert only the declared literal mode property.
        property_id="chmod-mode-others-write",
        entry_boolean_arguments=booleans or {},
        candidate_id="diagnostic", repository_id="diagnostic",
        entry_path=document.path, source_digest=repository_source_digest(index),
    )
    result = _invoke(
        _registry(index), "validate_permission_mode", {"path": document.path},
        ToolExecutionScope(
            admitted_paths=frozenset({document.path}), candidate_path=document.path,
            subject=subject, max_observation_tokens=20000,
        ),
    )
    assert result.status == "ok"
    return result


@pytest.mark.parametrize("prefix", [
    "if enabled:\n        os.chmod(path, 0o750)",
    "os.chmod(path, 0o750)\n    if enabled:\n        pass",
    "os.chmod(path, 0o750)\n    try:\n        pass\n    finally:\n        pass",
], ids=["branch-narrow-mode", "branch-pass", "try-finally-pass"])
def test_permission_does_not_refute_unconditional_later_world_write(prefix):
    result = permission_result(prefix + "\n    os.chmod(path, 0o777)")
    # In all cases the final chmod is reachable and unconditional. Unsupported
    # control flow may remain unresolved, but cannot justify a safety refutation.
    assert result.validation_status.value != "REFUTED", json.loads(result.content)
    if result.validation_status.value == "UNRESOLVED":
        assert result.subject is None
        assert json.loads(result.content)["issues"]


@pytest.mark.parametrize("body, expected", [
    ("os.chmod(path, 0o777)", "CONFIRMED"),
    ("os.chmod(path, 0o750)", "REFUTED"),
    ("os.chmod(path, 0o750)\n    return\n    os.chmod(path, 0o777)", "REFUTED"),
    ("os.chmod(path, 0o750)\n    if False:\n        os.chmod(path, 0o777)", "REFUTED"),
], ids=["unsafe", "safe", "dead-after-return", "dead-branch"])
def test_permission_diagnostic_controls(body, expected):
    result = permission_result(body)
    assert result.validation_status.value == expected
    assert result.subject is not None


@pytest.mark.parametrize("statement", [
    "wrapper(os.chmod(path, 0o777))",
    "x = wrapper(os.chmod(path, 0o777))",
    "x: int = wrapper(os.chmod(path, 0o777))",
    "x += wrapper(os.chmod(path, 0o777))",
    "x = wrapper(mode=os.chmod(path, 0o777))",
    "wrapper(path)",
    "x = wrapper(path)",
])
def test_permission_statement_calls_preserve_effects_and_block_safe_vote(statement):
    # C3/T03/T05: assignment and post-chmod calls obey the same effect rules
    # as conditions. Inspect arguments before treating the callee as unknown.
    result = permission_result("x = 0\n    os.chmod(path, 0o750)\n    " + statement)
    assessment = json.loads(result.content)
    assert result.validation_status == ValidationStatus.UNRESOLVED
    assert result.subject is None
    assert assessment["issues"]
    expected_modes = ["0o750", "0o777"] if "0o777" in statement else ["0o750"]
    assert [call["mode_text"] for call in assessment["calls"]] == expected_modes
    with pytest.raises(ValueError, match="validate_permission_mode"):
        validate_conclusion(
            AgentExpertConclusion(
                expert="scan", label="SAFE", confidence=0.9,
                validation_status=ValidationStatus.UNRESOLVED,
                evidence_ids=result.evidence_ids, rationale="Only the first mode is safe.",
            ),
            [ReActStep(step=1, model_id="test", observation=result,
                       tool_call=ModelToolCall(call_id="permission", name=result.tool, arguments={}))],
            frozenset(),
        )


@pytest.mark.parametrize("statement", [
    "os.makedirs('/tmp/work', exist_ok=True)",
    "x = os.makedirs('/tmp/work', exist_ok=True)",
    "if False:\n        wrapper(os.chmod(path, 0o777))",
    "x = lambda: wrapper(os.chmod(path, 0o777))",
])
@pytest.mark.parametrize("mode, expected", [("0o750", "REFUTED"), ("0o777", "CONFIRMED")])
def test_permission_statement_effect_controls(statement, mode, expected):
    # C3/T04: preserve existing supported summaries and genuinely deferred/dead
    # effects; making every statement unresolved is not a valid repair.
    result = permission_result(f"os.chmod(path, {mode})\n    " + statement)
    assert result.validation_status.value == expected, result.content
    assert result.subject is not None
    assert [call["mode_text"] for call in json.loads(result.content)["calls"]] == [mode]


@pytest.mark.parametrize("body, expected", [
    ("if enabled:\n        os.chmod(path, 0o750)\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    if enabled:\n        pass\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    try:\n        pass\n    finally:\n        pass\n    os.chmod(path, 0o777)", "CONFIRMED"),
    ("try:\n        os.chmod(path, 0o750)\n    finally:\n        os.chmod(path, 0o777)", "CONFIRMED"),
    # C3: assigned and cleanup calls lack effect summaries; retain gaps.
    ("if enabled:\n        try:\n            root = get_root()\n        except Exception:\n            root = os.path.join('/tmp', 'local')\n        path = os.path.join(root, 'cache')\n        os.makedirs(path, exist_ok=True)\n    else:\n        path = tempfile.mkdtemp()\n        os.chmod(path, 0o777)\n        atexit.register(shutil.rmtree, path, ignore_errors=True)\n    return path", "UNRESOLVED"),
    ("if enabled:\n        try:\n            root = get_root()\n        except Exception:\n            root = os.path.join('/tmp', 'local')\n        path = os.path.join(root, 'cache')\n        os.makedirs(path, exist_ok=True)\n    else:\n        path = tempfile.mkdtemp()\n        os.chmod(path, 0o750)\n        atexit.register(shutil.rmtree, path, ignore_errors=True)\n    return path", "UNRESOLVED"),
    ("if enabled:\n        return\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    try:\n        return\n    finally:\n        os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    try:\n        os = replacement\n    except Exception:\n        pass\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("if enabled:\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)\n    return path", "UNRESOLVED"),
    ("try:\n        pass\n    except replace_bindings():\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("try:\n        pass\n    except Exception:\n        os.chmod(path, 0o777)", "UNRESOLVED"),
    ("try:\n        os.chmod(path, 0o750)\n    except Exception:\n        os.chmod(path, 0o777)", "UNRESOLVED"),
    ("if os.chmod(path, 0o777):\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("if os.chmod(path, 0o777) or enabled:\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    # Only the shape of the branch test is subsumed by the unresolved branch. An
    # os.chmod the test actually evaluates keeps its own binding and arity limits.
    ("if os.chmod(path):\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("import pathlib as os\n    if os.chmod(path, 0o750):\n        pass", "UNRESOLVED"),
])
def test_permission_complete_structured_control_flow(body, expected):
    result = permission_result(body)
    assert result.validation_status.value == expected, json.loads(result.content)
    assert (result.subject is not None) == (expected != "UNRESOLVED")


SHARED_TMP_DIR_BODY = (
    "if %s:\n"
    "        try:\n"
    "            root = get_databricks_local_temp_dir()\n"
    "        except Exception:\n"
    "            root = os.path.join('/tmp', 'repl_tmp_data', get_repl_id())\n"
    "        path = os.path.join(root, 'mlflow')\n"
    "        os.makedirs(path, exist_ok=True)\n"
    "    else:\n"
    "        path = tempfile.mkdtemp()\n"
    "        os.chmod(path, %s)\n"
    "        atexit.register(shutil.rmtree, path, ignore_errors=True)\n"
    "    return path"
)


@pytest.mark.parametrize("guard", [
    "enabled",
    "sys.platform == 'win32'",
], ids=["bare-name", "comparison"])
@pytest.mark.parametrize("mode, expected", [("0o777", "CONFIRMED"), ("0o750", "REFUTED")])
@pytest.mark.parametrize("has_unknown_body_calls", [False, True])
def test_permission_verdict_does_not_depend_on_the_guard_expression_shape(
    guard, mode, expected, has_unknown_body_calls,
):
    # C3 migration: a pure guard cannot discharge unknown effects in the body.
    # Keep the original production-shaped case, plus a literal-body control so
    # conservative handling cannot hide a blanket loss of mode analysis.
    body = SHARED_TMP_DIR_BODY if has_unknown_body_calls else (
        "if %s:\n        pass\n    os.chmod(path, %s)"
    )
    result = permission_result(body % (guard, mode))
    # C3: bare input truth and sys attribute/comparison lack type/effect proofs.
    expected = "UNRESOLVED"
    assert result.validation_status.value == expected, json.loads(result.content)
    assert result.subject is None


@pytest.mark.parametrize("guard", [
    "is_in_databricks_runtime() and get_repl_id() is not None",
    "not is_in_databricks_runtime()",
    "settings.get('shared_tmp')",
], ids=["short-circuit-call", "negated-call", "attribute-call"])
@pytest.mark.parametrize("mode", ["0o777", "0o750"])
def test_permission_call_shaped_guard_without_summary_stays_unresolved(guard, mode):
    # C2/C3 migration (was: call-guard shape also yielded typed verdicts): an
    # unknown call in a guard has no verified purity summary, so its possible
    # side effects on bindings/termination are a fatal gap, not a bounded
    # control note. History (hp001 scores) is not a constraint per contract.
    result = permission_result(SHARED_TMP_DIR_BODY % (guard, mode))
    assert result.validation_status.value == "UNRESOLVED", json.loads(result.content)
    assert result.subject is None
    assert json.loads(result.content)["issues"]


@pytest.mark.parametrize("mode", ["0o777", "0o750"])
def test_production_guard_shape_without_summary_forces_abstention(mode):
    # C2/C3 migration (was: call-shaped guard yielded CONFIRMED/REFUTED and a
    # material prediction): without a verified purity summary the guard call is
    # a fatal gap, so the expert must abstain instead of voting materially.
    result = permission_result(SHARED_TMP_DIR_BODY % (
        "is_in_databricks_runtime() and get_repl_id() is not None", mode,
    ))
    assert result.validation_status == ValidationStatus.UNRESOLVED
    assert result.subject is None
    step = ReActStep(step=1, model_id="test", observation=result,
                     tool_call=ModelToolCall(call_id="permission", name=result.tool,
                                             arguments={}))
    for label in ("VULNERABLE", "SAFE"):
        with pytest.raises(ValueError, match="validate_permission_mode"):
            validate_conclusion(
                AgentExpertConclusion(
                    expert="scan", label=label, confidence=0.9,
                    validation_status=ValidationStatus.UNRESOLVED,
                    evidence_ids=result.evidence_ids,
                    rationale=f"The candidate span uses the literal mode {mode}.",
                ),
                [step],
                frozenset(),
                required_validators=("validate_permission_mode",),
                subject=result.subject,
            )
    validate_conclusion(
        AgentExpertConclusion(
            expert="scan", label="ABSTAIN", confidence=0.0,
            validation_status=ValidationStatus.UNRESOLVED,
            evidence_ids=[],
            rationale="Guard calls lack purity summaries; modes unjudgeable.",
        ),
        [step],
        frozenset(),
        required_validators=("validate_permission_mode",),
        subject=result.subject,
    )


def test_permission_lambda_default_arguments_execute_immediately():
    """[P1 反例] lambda 默认参数在定义时求值，函数体才延迟执行.

    `if (lambda x=os.chmod(path, 0o777): True)` 的默认值调用必然执行；
    整体跳过 lambda 会漏掉 0o777 而返回 REFUTED。HEAD 返回 UNRESOLVED。
    定义时效果与调用时效果必须分离（C2/C3）。
    """
    result = permission_result(
        "if (lambda x=os.chmod(path, 0o777): True):\n"
        "        pass\n"
        "    os.chmod('/tmp/other', 0o750)"
    )
    assert result.validation_status.value == "UNRESOLVED", json.loads(result.content)
    assert result.subject is None
    assert json.loads(result.content)["issues"]


def test_permission_uninvoked_lambda_body_is_not_collected():
    """C3 对照：从未调用的 lambda 函数体不得被算作已执行操作."""
    result = permission_result(
        "f = lambda: os.chmod(path, 0o777)\n"
        "    os.chmod(path, 0o750)"
    )
    assert result.validation_status.value == "REFUTED", json.loads(result.content)
    assert result.subject is not None


def test_permission_chained_comparison_short_circuit_is_honored():
    """[P2 反例] 链式比较必须遵守短路，不能把可能执行当确定证明.

    `if 2 < 1 < os.chmod(path, 0o777)` 中 chmod 确定不会执行；访问所有
    操作数可用于保守收集可能效果，但未经可达性检查不得进入 CONFIRMED。
    HEAD 是 UNRESOLVED（无调用被收集）。已知比较结果应短路；未解析的
    比较关系保留限制（C2/C3）。
    """
    result = permission_result(
        "if 2 < 1 < os.chmod(path, 0o777):\n"
        "        pass"
    )
    assert result.validation_status.value == "UNRESOLVED", json.loads(result.content)
    assert result.subject is None


def test_permission_syntax_error_returns_unresolved():
    """[P2 回归] 语法错误分支的返回元数必须与正常路径一致.

    无法解析的代码不得以解包异常代替 UNRESOLVED。
    """
    result = permission_result("if enabled:\n        os.chmod(path, ")
    assert result.status == "ok"
    assert result.validation_status.value == "UNRESOLVED", json.loads(result.content)


def test_permission_short_circuit_skipped_chmod_stays_unresolved():
    """[P2 反例] 条件表达式短路跳过的 os.chmod 不得被静默丢弃.

    `if enabled and os.chmod(path, 0o777)` 在遇到 `enabled` 时停止检查后续
    操作数；被跳过的危险 chmod 若不留痕，分析器只收集到另一条安全 chmod 而
    返回候选绑定的 REFUTED，可支持错误 SAFE。修改前返回 UNRESOLVED。
    已有测试把 chmod 放在短路首位（仍会被收集），没覆盖第二个操作数。
    """
    result = permission_result(
        "if enabled and os.chmod(path, 0o777):\n"
        "        pass\n"
        "    os.chmod(path, 0o750)"
    )
    assert result.validation_status.value == "UNRESOLVED", json.loads(result.content)
    assert result.subject is None
    assert json.loads(result.content)["issues"]


@pytest.mark.parametrize("body", [
    # T03: chmod in every executable position of boolean/conditional shapes.
    "if enabled and os.chmod(path, 0o777):\n        pass\n    os.chmod(path, 0o750)",
    "if os.chmod(path, 0o777) and enabled:\n        pass\n    os.chmod(path, 0o750)",
    "if enabled or os.chmod(path, 0o777):\n        pass\n    os.chmod(path, 0o750)",
    "os.chmod(path, 0o777) if enabled else None\n    os.chmod(path, 0o750)",
    "if (os.chmod(path, 0o777) == 0):\n        pass\n    os.chmod(path, 0o750)",
    "if (m := os.chmod(path, 0o777)):\n        pass\n    os.chmod(path, 0o750)",
    "check(os.chmod(path, 0o777))\n    os.chmod(path, 0o750)",
    # An unknown call guard is itself an unproven side effect (C3): it cannot
    # be exempted just for sitting in a condition.
    "if check(path):\n        pass\n    os.chmod(path, 0o750)",
])
def test_permission_condition_positions_with_chmod_stay_unresolved(body):
    """C2/C3, T03: 条件中任何可执行位置的 chmod 或未知调用都不得静默消失."""
    result = permission_result(body)
    assert result.validation_status.value == "UNRESOLVED", (body, json.loads(result.content))
    assert result.subject is None
    assert json.loads(result.content)["issues"], body


@pytest.mark.parametrize("body", [
    # Same positions, dead code or provably pure shapes: still analyzable (T04).
    "if False and os.chmod(path, 0o777):\n        pass\n    os.chmod(path, 0o750)",
    "x = 1 if enabled else 2\n    os.chmod(path, 0o750)",
    "directory = '/tmp/x'\n    if directory == '/tmp/x':\n        pass\n    os.chmod(path, 0o750)",
    "if (n := 5):\n        pass\n    os.chmod(path, 0o750)",
    "if enabled:\n        pass\n    os.chmod(path, 0o750)",
])
@pytest.mark.parametrize("enabled", [False, True])
def test_permission_pure_condition_positions_stay_typed(body, enabled):
    """C3, T04: 死代码不虚构危险；无调用的纯条件形状继续给出类型化结论."""
    result = permission_result(body, booleans={"enabled": enabled})
    assert result.validation_status.value == "REFUTED", (body, json.loads(result.content))
    assert result.subject is not None


def test_permission_assessment_records_the_branch_condition_of_each_collected_call():
    # C2/C3 migration (was: REFUTED): the bare-call guard has no verified
    # purity summary, so the verdict is UNRESOLVED; per-call branch_conditions
    # recording itself is unchanged and still asserted below.
    result = permission_result(
        "if is_in_databricks_runtime():\n"
        "        os.chmod(path, 0o750)\n"
        "    else:\n"
        "        os.chmod(path, 0o750)\n"
        "    return path"
    )
    assert result.validation_status == ValidationStatus.UNRESOLVED
    assert result.subject is None
    assessment = json.loads(result.content)
    assert [call["branch_conditions"] for call in assessment["calls"]] == [
        ["is_in_databricks_runtime()"],
        ["not (is_in_databricks_runtime())"],
    ]


def test_known_length_destructuring_mismatch_aborts_command_analysis():
    """[P2 反例] 确定会失败的解包不得产生无 issue 的漏洞汇点.

    `a, b = (1,)` 在 Python 中必然先抛 ValueError，执行不到后面的命令；
    当前分析器却生成无任何 issue 的 UNSANITIZED 汇点证据。修改前保守中止。
    已知成功解包（正例对照）保留可达汇点；未知迭代另测副作用缺口。
    """
    doomed = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-4",
        text="def entry(value):\n    a, b = (1,)\n    import os\n    os.system(value)\n",
        defines=("entry",),
    )
    doomed_analysis = analyze_command(doomed)
    assert doomed_analysis.issues, doomed_analysis.sinks
    assert command_status(doomed_analysis) != "UNSANITIZED"

    live = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-4",
        text="def entry(value):\n    a, b = (1, value)\n    import os\n    os.system(b)\n",
        defines=("entry",),
    )
    live_analysis = analyze_command(live)
    assert command_status(live_analysis) == "UNSANITIZED"


def _unpack_case(text):
    document = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-9",
        text=text,
        defines=("entry",),
    )
    return analyze_command(document)


@pytest.mark.parametrize("exit_statement", ["pass", "continue", "break"])
@pytest.mark.parametrize("dangerous", [False, True])
def test_literal_loop_retains_condition_binding_after_exit(exit_statement, dangerous):
    condition = "not flag" if dangerous else "flag"
    analysis = _unpack_case(
        "def entry(value, flag):\n"
        "    for item in [0]:\n"
        "        if flag:\n            command = 'echo ' + shlex.quote(value)\n"
        "        else:\n            command = value\n"
        f"        {exit_statement}\n"
        f"    if {condition}:\n        os.system(command)\n"
    )
    assert not analysis.issues
    assert {fact["status"] for fact in analysis.sinks} == {"UNSANITIZED" if dangerous else "SANITIZED"}


@pytest.mark.parametrize("exit_statement", ["continue", "break"])
def test_literal_loop_exit_preserves_else_and_skips_dead_sink(exit_statement):
    analysis = _unpack_case(
        "def entry(value):\n"
        "    for item in [1, 2]:\n"
        f"        {exit_statement}\n"
        "        os.system(value)\n"
        "    else:\n        os.system('fixed')\n"
        "    os.system('after')\n"
    )
    assert not analysis.issues
    assert [fact["status"] for fact in analysis.sinks] == ["SANITIZED"] * (2 if exit_statement == "continue" else 1)


@pytest.mark.parametrize("exit_statement", ["break", "continue"])
def test_nested_loop_else_exit_targets_enclosing_loop(exit_statement):
    analysis = _unpack_case(
        "def entry(value):\n"
        "    for item in [0, 1]:\n"
        "        for inner in []:\n            pass\n"
        f"        else:\n            {exit_statement}\n"
        "        os.system(value)\n"
        "    os.system('fixed')\n"
    )
    assert not analysis.issues
    assert [fact["status"] for fact in analysis.sinks] == ["SANITIZED"]


@pytest.mark.parametrize("target", ["loop", "chain"])
@pytest.mark.parametrize("valid", [False, True])
def test_helper_tuple_alternatives_execute_loop_and_chained_unpack_per_path(target, valid):
    helper = CodeDocument(
        repository_id="r", path="helper.py", defines=("build_pair",),
        text="def build_pair(value, flag):\n    if flag:\n        return "
             + ("(0, value)" if valid else "(0,)") + "\n    return (1,)\n",
    )
    continuation = ("    for a, b in [pair]:\n        os.system(b)\n" if target == "loop" else
                    "    copy = a, b = pair\n    os.system(b)\n")
    caller = CodeDocument(
        repository_id="r", path="entry.py", defines=("entry",), calls=("build_pair",),
        text="def entry(value, flag):\n    pair = build_pair(value, flag)\n" + continuation,
    )
    analysis = analyze_command(caller, (helper,))
    if valid:
        assert not analysis.issues
        assert [item["status"] for item in analysis.sinks] == ["UNSANITIZED"]
    else:
        assert analysis.issues
        assert not analysis.sinks


def test_destructuring_success_and_failure_branches_keep_the_live_path():
    """C2, T06: 成功＋失败备选：失败路径终止，成功路径的汇点必须保留."""
    analysis = _unpack_case(
        "def entry(value, flag):\n"
        "    if flag:\n"
        "        pair = (\"echo\", value)\n"
        "    else:\n"
        "        pair = (\"echo\",)\n"
        "    import os\n"
        "    a, b = pair\n"
        "    os.system(a + b)\n"
    )
    assert not analysis.issues, analysis.issues
    assert [sink["status"] for sink in analysis.sinks] == ["UNSANITIZED"]
    assert command_status(analysis) == "UNSANITIZED"


def test_destructuring_success_and_unknown_branches_stay_separate():
    """C2/C3: 成功路径保留汇点，未知迭代保留缺口，不生成假后继."""
    analysis = _unpack_case(
        "def entry(value, flag):\n"
        "    if flag:\n"
        "        pair = (\"echo\", value)\n"
        "    else:\n"
        "        pair = missing\n"
        "    import os\n"
        "    a, b = pair\n"
        "    os.system(a + b)\n"
    )
    assert "unresolved destructuring iteration effects" in analysis.issues
    assert [sink["status"] for sink in analysis.sinks] == ["UNSANITIZED"]
    assert command_status(analysis) == "AMBIGUOUS"


def test_nested_destructuring_binds_per_alternative():
    """C2, T06: 嵌套解包按备选绑定，内层关联不跨备选混合."""
    analysis = _unpack_case(
        "def entry(value, flag):\n"
        "    if flag:\n"
        "        trio = (\"x\", (\"y\", value))\n"
        "    else:\n"
        "        trio = (\"x\", (\"y\", \"fixed\"))\n"
        "    import os\n"
        "    a, (b, c) = trio\n"
        "    os.system(b + c)\n"
    )
    assert not analysis.issues, analysis.issues
    assert sorted(sink["status"] for sink in analysis.sinks) == ["SANITIZED", "UNSANITIZED"]
    assert command_status(analysis) == "UNSANITIZED"


def test_destructuring_inside_unsupported_try_stays_unresolved():
    """C2, T06: 不支持的异常处理边界：保持未解析，不声称不可达也不给干净结论."""
    analysis = _unpack_case(
        "def entry(value):\n"
        "    try:\n"
        "        a, b = (1,)\n"
        "    except ValueError:\n"
        "        pass\n"
        "    import os\n"
        "    os.system(value)\n"
    )
    assert analysis.issues, analysis.sinks
    assert command_status(analysis) == "AMBIGUOUS"


@pytest.mark.parametrize("api", ["run", "Popen"])
@pytest.mark.parametrize("assigned", [False, True], ids=["inline", "assigned"])
@pytest.mark.parametrize("argv, expected", [
    ('["bash", "-c", value]', "MAY_REACH"),
    ('["sh", "-c", value]', "MAY_REACH"),
    ('["python3.12", "-c", value]', "MAY_REACH"),
    ('["python.exe", "-c", value]', "MAY_REACH"),
    ('["env", "bash", "-c", value]', "MAY_REACH"),
    ('["env", "-i", "python3.12", "-c", value]', "MAY_REACH"),
    ('["/usr/bin/env", "sh", "-c", value]', "MAY_REACH"),
    ('["sudo", "bash", "-c", value]', "MAY_REACH"),
    ('["su", "root", "-c", value]', "MAY_REACH"),
    ('["sudo", "--user", "root", "bash", "-c", value]', "MAY_REACH"),
    ('["sudo", "-u", "root", "bash", "-c", value]', "MAY_REACH"),
    ('["sudo", "MODE=test", "bash", "-c", value]', "MAY_REACH"),
    ('["env", "--split-string=sh -c", "eval \\"$1\\"", "sh", value]', "MAY_REACH"),
    ('["env", "--", "FOO=bar", "bash", "-c", value]', "MAY_REACH"),
    ('["awk", value]', "MAY_REACH"),
    ('["git", "commit", "-m", value]', "MAY_REACH"),
    ('["git", "-c", "alias.review=" + value, "review"]', "MAY_REACH"),
    ('["env", "git", "status", value]', "MAY_REACH"),
    ('["echo", value]', "NOT_ESTABLISHED"),
    ('["env", "echo", value]', "NOT_ESTABLISHED"),
    ('["env", "--", "echo", value]', "NOT_ESTABLISHED"),
    ('["env", "FOO=bar", "echo", value]', "NOT_ESTABLISHED"),
    ('["sudo", "--user", "root", "echo", value]', "NOT_ESTABLISHED"),
    ('["bash", "-c", "echo fixed"]', "NOT_ESTABLISHED"),
], ids=["bash-command", "sh-command", "python312-command", "python-exe-command",
        "env-bash", "env-i-python", "usr-bin-env-sh", "sudo-bash",
        "su-root-c", "sudo-long-user-bash", "sudo-short-user-bash", "sudo-envvar-bash", "env-split-string", "env-dashdash-envvar-bash",
        "awk-unestablished", "git-commit-unestablished", "git-alias-unestablished", "env-git-unestablished",
        "ordinary-echo", "env-echo", "env-dashdash-echo", "env-var-echo", "sudo-user-echo", "constant-command"])
def test_command_flow_preserves_argv_semantics(api, assigned, argv, expected):
    setup = f"    command = {argv}\n" if assigned else ""
    argument = "command" if assigned else argv
    result = trace({"entry.py": (
        "import subprocess\n\ndef entry(request):\n"
        "    value = request.args['value']\n"
        + setup + f"    return subprocess.{api}({argument})\n"
    )})
    assert result["status"] == "UNRESOLVED"
    assert result["flow_status"] == expected, result


@pytest.mark.parametrize("body, expected", [
    ('return subprocess.run(args=["/bin/bash", "-c", value])', "MAY_REACH"),
    ('command = ("echo", value)\n    return subprocess.run(args=command)', "NOT_ESTABLISHED"),
    ('command = ["echo", value]\n    command = ["bash", "-c", value]\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    if request.args["flag"]:\n        command = ["bash", "-c", value]\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    command[0] = "bash"\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    alias = command\n    alias[0] = "bash"\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    mutate(command)\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    return subprocess.run(command, shell=True)', "MAY_REACH"),
    ('return subprocess.run(["echo", "-c", value], executable="bash")', "MAY_REACH"),
    ('command = ["echo", "-c", value]\n    return subprocess.Popen(command, -1, "/bin/bash")', "MAY_REACH"),
    ('return subprocess.Popen(["echo", "-c", value], -1, "/bin/bash")', "MAY_REACH"),
    ('command = ["echo", value]\n    return subprocess.Popen(command, -1, None)', "NOT_ESTABLISHED"),
    ('command = ["echo", value]\n    return subprocess.run(command, shell=request.args["flag"])', "MAY_REACH"),
], ids=["absolute-shell-keyword", "tuple-keyword", "reassign", "branch-reassign",
        "mutation", "alias-mutation", "escape", "shell-true", "executable-override",
        "positional-executable-var", "positional-executable-inline", "positional-executable-none",
        "unknown-shell"])
def test_command_argv_structure_boundaries(body, expected):
    result = trace({"entry.py": (
        "import subprocess\n\ndef entry(request):\n"
        "    value = request.args['value']\n    " + body + "\n"
    )})
    assert result["status"] == "UNRESOLVED"
    assert result["flow_status"] == expected, result


@pytest.mark.parametrize('line', [1, 4])
def test_permission_fact_cannot_confirm_an_undeclared_command_property(line):
    from cv_agent.tools.validation.permissions import permission_mode
    from cv_agent.tools.validation.models import PathInput

    doc = CodeDocument(repository_id='r', path='entry.py', language='python',
                       text="def entry(value):\n    os.chmod('target', 0o777)\n    if False:\n        os.system(value)\n")
    index = RepositoryIndex([doc])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=doc.path,
                                entry_line=line, source_digest=repository_source_digest(index),
                                analysis_scope='command execution at os.system')
    result = permission_mode(index, PathInput(path=doc.path), ToolExecutionScope(
        candidate_path=doc.path, admitted_paths=frozenset({doc.path}), subject=subject,
        max_observation_tokens=4000,
    )).model_copy(update={'citation_id': 'mode'})
    step = ReActStep(step=1, model_id='offline', observation=result,
                    tool_call=ModelToolCall(call_id='mode', name=result.tool, arguments={}))
    with pytest.raises(ValueError):
        validate_conclusion(AgentExpertConclusion(
            expert='scan', label='VULNERABLE', validation_status='CONFIRMED', confidence=.9,
            evidence_ids=('mode',), supporting_observation_ids=('mode',),
            rationale='A different property must not prove this command candidate.',
        ), [step], frozenset(), subject=subject)


@pytest.mark.parametrize('identifier, path', [('command-candidate', 'entry.py'), ('c', 'command.py')])
def test_command_proof_obligation_is_not_inferred_from_identity(identifier, path):
    from cv_agent.agents.evidence_policy import _candidate_is_command_weakness

    subject = ValidationSubject(candidate_id=identifier, repository_id='r', entry_path=path,
                                source_digest='same-source', analysis_scope='Assess an authorization boundary.')
    assert not _candidate_is_command_weakness([], subject)


@pytest.mark.parametrize('offset', [0, 39])
@pytest.mark.parametrize('line, status', [(2, 'CONFIRMED'), (3, 'REFUTED')])
def test_permission_proof_selects_declared_call_not_another_mode(offset, line, status):
    from cv_agent.tools.validation.permissions import permission_mode
    from cv_agent.tools.validation.models import PathInput

    doc = CodeDocument(repository_id='r', path=f'entry.py::entry@{offset + 1}-{offset + 4}',
                       text="def entry():\n    os.chmod('first', 0o777)\n    os.chmod('second', 0o750)\n")
    index = RepositoryIndex([doc])
    subject = ValidationSubject(candidate_id='neutral', repository_id='r', entry_path=doc.path,
                                entry_line=offset + line, source_digest=repository_source_digest(index),
                                property_id='chmod-mode-others-write')
    scope = ToolExecutionScope(candidate_path=doc.path, admitted_paths=frozenset({doc.path}),
                               subject=subject, max_observation_tokens=4000)
    result = permission_mode(index, PathInput(path=doc.path), scope).model_copy(update={'citation_id': 'mode'})
    assert result.validation_status == status
    assert result.subject == subject
    assert [call['line'] for call in json.loads(result.content)['calls']] == [line]
    step = ReActStep(step=1, model_id='offline', observation=result,
                    tool_call=ModelToolCall(call_id='mode', name=result.tool, arguments={}))
    label = 'VULNERABLE' if status == 'CONFIRMED' else 'SAFE'
    output = AgentExpertConclusion(expert='scan', label=label, validation_status=status,
                                  confidence=.9, evidence_ids=('mode',), supporting_observation_ids=('mode',),
                                  rationale='Only the specified chmod mode property.')
    validate_conclusion(output, [step], frozenset(), subject=subject)
    with pytest.raises(ValueError):
        validate_conclusion(output.model_copy(update={'label': 'SAFE' if label == 'VULNERABLE' else 'VULNERABLE'}),
                            [step], frozenset(), subject=subject)
    # A proof for the other call is not interchangeable, even in the same file.
    with pytest.raises(ValueError):
        validate_conclusion(output, [step], frozenset(),
                            subject=subject.model_copy(update={'entry_line': offset + (3 if line == 2 else 2)}))


@pytest.mark.parametrize('property_id', [None, 'command-execution', 'authorization'])
def test_permission_local_fact_is_preserved_without_candidate_property_proof(property_id):
    from cv_agent.tools.validation.permissions import permission_mode
    from cv_agent.tools.validation.models import PathInput

    doc = CodeDocument(repository_id='r', path='entry.py', text="def entry():\n    os.chmod('target', 0o777)\n")
    index = RepositoryIndex([doc])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=doc.path, entry_line=1,
                                source_digest=repository_source_digest(index), property_id=property_id)
    result = permission_mode(index, PathInput(path=doc.path), ToolExecutionScope(
        candidate_path=doc.path, admitted_paths=frozenset({doc.path}), subject=subject,
        max_observation_tokens=4000,
    ))
    assert result.validation_status == ValidationStatus.CONFIRMED  # local bounded fact is not discarded
    assert json.loads(result.content)['property_id'] == 'chmod-mode-others-write'
    assert result.subject is None
    result = result.model_copy(update={'citation_id': 'mode'})
    step = ReActStep(step=1, model_id='offline', observation=result,
                    tool_call=ModelToolCall(call_id='mode', name=result.tool, arguments={}))
    for claimed_status in ('UNRESOLVED', 'CONFIRMED'):
        with pytest.raises(ValueError):
            validate_conclusion(AgentExpertConclusion(
                expert='scan', label='VULNERABLE', validation_status=claimed_status, confidence=.9,
                evidence_ids=('mode',), supporting_observation_ids=('mode',), rationale='Local mode only.',
            ), [step], frozenset(), subject=subject)


def test_scanner_and_identity_preserve_explicit_proof_property():
    from cv_agent.agents.scanner import StaticScanner
    from cv_agent.tools.identity import candidate_subject

    doc = CodeDocument(repository_id='r', path='neutral.py', language='python',
                       text="def entry():\n    os.chmod('target', 0o777)\n")
    index = RepositoryIndex([doc])
    candidate, = StaticScanner().scan('r', [doc])
    assert candidate.property_id == 'chmod-mode-others-write'
    assert candidate_subject(index, candidate).property_id == candidate.property_id


@pytest.mark.parametrize('change', [
    {'repository_id': 'other'}, {'entry_path': 'other.py'}, {'source_digest': 'stale'}, {'entry_line': 200},
])
def test_permission_proof_checks_source_identity_before_binding(change):
    from cv_agent.tools.validation.permissions import permission_mode
    from cv_agent.tools.validation.models import PathInput

    doc = CodeDocument(repository_id='r', path='entry.py', text="def entry():\n    os.chmod('target', 0o777)\n")
    index = RepositoryIndex([doc])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=doc.path, entry_line=2,
                                source_digest=repository_source_digest(index), property_id='chmod-mode-others-write')
    scope = ToolExecutionScope(candidate_path=doc.path, admitted_paths=frozenset({doc.path}),
                               subject=subject, max_observation_tokens=4000)
    assert permission_mode(index, PathInput(path=doc.path), scope).subject == subject
    scope.subject = subject.model_copy(update=change)
    assert permission_mode(index, PathInput(path=doc.path), scope).status == 'blocked'


@pytest.mark.parametrize('enabled,expected', [(False, 'REFUTED'), (True, 'CONFIRMED')])
@pytest.mark.parametrize('shape', ['if', 'and', 'or', 'ternary', 'not', 'compare'])
def test_permission_declared_boolean_selects_only_executable_modes(enabled, expected, shape):
    statements = {
        'if': "if enabled:\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)",
        'and': "os.chmod(path, 0o750)\n    enabled and os.chmod(path, 0o777)",
        'or': "os.chmod(path, 0o750)\n    (not enabled) or os.chmod(path, 0o777)",
        'ternary': "os.chmod(path, 0o777) if enabled else os.chmod(path, 0o750)",
        'not': "if not enabled:\n        os.chmod(path, 0o750)\n    else:\n        os.chmod(path, 0o777)",
        'compare': "if enabled == True:\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)",
    }
    result = permission_result(statements[shape], booleans={'enabled': enabled})
    assert result.validation_status.value == expected
    modes = [call['mode_text'] for call in json.loads(result.content)['calls']]
    assert ('0o777' in modes) == enabled
    assert result.subject is not None


@pytest.mark.parametrize('prefix,expected', [
    ('enabled = True', 'CONFIRMED'),
    ('enabled = False', 'REFUTED'),
    ('enabled = not enabled', 'CONFIRMED'),
    ('enabled = path', 'UNRESOLVED'),
])
def test_permission_boolean_rebinding_does_not_keep_entry_value(prefix, expected):
    result = permission_result(prefix + "\n    if enabled:\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)", booleans={'enabled': False})
    assert result.validation_status.value == expected


@pytest.mark.parametrize('prefix,expected', [
    ('alias = enabled\n    enabled = not alias', 'CONFIRMED'),
    ('(enabled := True)', 'CONFIRMED'),
    ('False and (enabled := True)', 'REFUTED'),
    ('True or (enabled := True)', 'REFUTED'),
    ('path and (enabled := True)', 'UNRESOLVED'),
    ('path or (enabled := True)', 'UNRESOLVED'),
    ('(enabled := True) if path else False', 'UNRESOLVED'),
    ('if path:\n        enabled = True', 'UNRESOLVED'),
    ('if path:\n        enabled = True\n    else:\n        enabled = True', 'UNRESOLVED'),
    ('try:\n        enabled = True\n    except Exception:\n        enabled = False', 'UNRESOLVED'),
    ('try:\n        pass\n    finally:\n        enabled = True', 'CONFIRMED'),
    ('False == True == (enabled := True)', 'REFUTED'),
    ('path == True == (enabled := True)', 'UNRESOLVED'),
])
def test_permission_scenario_binding_follows_expression_and_branch_execution(prefix, expected):
    result = permission_result(
        prefix + '\n    if enabled:\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)',
        booleans={'enabled': False},
    )
    assert result.validation_status.value == expected, result.content


def test_permission_disabled_only_sink_has_no_candidate_confirmation():
    result = permission_result('if enabled:\n        os.chmod(path, 0o777)', booleans={'enabled': False})
    assert result.validation_status.value == 'UNRESOLVED'
    assert json.loads(result.content)['calls'] == []
    assert result.subject is None


def test_permission_invalid_boolean_parameter_cannot_stamp_candidate_proof():
    result = permission_result('os.chmod(path, 0o777)', booleans={'missing': False})
    assert result.validation_status.value == 'UNRESOLVED'
    assert result.subject is None


@pytest.mark.parametrize('argument', ['path', 'enabled', '42', 'None'])
@pytest.mark.parametrize('before', [True, False])
def test_makedirs_summary_requires_proven_builtin_path(argument, before):
    call = f'os.makedirs({argument}, exist_ok=True)'
    chmod = 'os.chmod(path, 0o750)'
    result = permission_result((call + '\n    ' + chmod) if before else (chmod + '\n    ' + call))
    assert result.validation_status == ValidationStatus.UNRESOLVED
    assert result.subject is None
    assert json.loads(result.content)['issues']


@pytest.mark.parametrize('statement', [
    "os.makedirs('/tmp/work', exist_ok=True)",
    "directory = '/tmp/work'\n    os.makedirs(directory, exist_ok=True)",
    "os.makedirs(b'/tmp/work', exist_ok=True)",
])
@pytest.mark.parametrize('mode,status', [('0o750', 'REFUTED'), ('0o777', 'CONFIRMED')])
def test_makedirs_builtin_path_summary_preserves_literal_mode_controls(statement, mode, status):
    result = permission_result(f'os.chmod(path, {mode})\n    ' + statement)
    assert result.validation_status.value == status
    assert result.subject is not None


def test_makedirs_normal_return_cannot_enter_truthy_branch():
    result = permission_result("if os.makedirs('/tmp/work', exist_ok=True):\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)")
    assert result.validation_status == ValidationStatus.REFUTED
    assert [call['mode_text'] for call in json.loads(result.content)['calls']] == ['0o750']


def test_unknown_makedirs_path_can_execute_user_code_before_filesystem_write():
    import os
    effects = []
    class CustomPath:
        def __fspath__(self):
            effects.append('custom path code executed')
            raise ValueError('stop before any filesystem operation')
    with pytest.raises(ValueError, match='stop before'):
        os.makedirs(CustomPath(), exist_ok=True)
    assert effects == ['custom path code executed']


@pytest.mark.parametrize('operation', [
    'if enabled:\n        pass',
    'if path == "/tmp/work":\n        pass',
    'unused = path.permission',
])
@pytest.mark.parametrize('before', [True, False])
def test_unknown_object_protocols_cannot_supply_permission_safety(operation, before):
    chmod = 'os.chmod(path, 0o750)'
    result = permission_result((operation + '\n    ' + chmod) if before else (chmod + '\n    ' + operation))
    assert result.validation_status == ValidationStatus.UNRESOLVED
    assert result.subject is None
    assert json.loads(result.content)['issues']


@pytest.mark.parametrize('protocol', ['truth', 'equality', 'attribute'])
def test_python_unknown_object_protocols_really_execute_user_code(protocol):
    effects = []
    class Value:
        def __bool__(self):
            effects.append('truth')
            return False
        def __eq__(self, other):
            effects.append('equality')
            return False
        @property
        def permission(self):
            effects.append('attribute')
            return None
    value = Value()
    if protocol == 'truth':
        bool(value)
    elif protocol == 'equality':
        value == '/tmp/work'
    else:
        value.permission
    assert effects == [protocol]


POSIX_PATH_ASSUMPTIONS = {
    "sys.platform.startswith('linux')": True,
    "is_windows()": False,
}


def inspect_path_command(body, *, assumptions=None, inputs=("value",), imports="import os, shlex"):
    """Exercise the registered command validator with a candidate-bound subject."""
    document = CodeDocument(
        repository_id="path-diagnostic",
        path="entry.py::entry@1-8",
        text=f"def entry(value, obj):\n    {imports}\n    " + body + "\n",
        defines=("entry",),
    )
    index = RepositoryIndex([document])
    subject = ValidationSubject(
        property_id="command-execution",
        candidate_id="path-diagnostic",
        repository_id=document.repository_id,
        entry_path=document.path,
        source_digest=repository_source_digest(index),
        input_parameters=inputs,
        entry_condition_assumptions=assumptions or {},
    )
    observation = _invoke(
        _registry(index), "inspect_command_construction", {"source_path": document.path},
        ToolExecutionScope(
            admitted_paths=frozenset({document.path}), candidate_path=document.path,
            subject=subject, max_observation_tokens=20000,
        ),
    )
    assert observation.status == "ok", observation.content
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    return json.loads(observation.content)


@pytest.mark.parametrize("operation", ["basename", "dirname", "normpath", "join"])
def test_posix_subject_resolves_canonical_os_path_lexical_calls(operation):
    argument = "value, '/fixed'" if operation == "join" else "value"
    payload = inspect_path_command(
        f'os.system("echo " + shlex.quote(os.path.{operation}({argument})))',
        assumptions=POSIX_PATH_ASSUMPTIONS,
    )
    assert payload["command_construction_status"] == "SANITIZED", payload
    assert not payload["issues"]
    assert len(payload["sink_facts"]) == 1


def test_posix_absolute_join_discards_earlier_input_at_real_sink():
    payload = inspect_path_command(
        'os.system("echo " + os.path.join(value, "/fixed"))',
        assumptions=POSIX_PATH_ASSUMPTIONS,
    )
    assert payload["command_construction_status"] == "SANITIZED", payload
    assert payload["sink_facts"][0]["status"] == "SANITIZED"


def test_canonical_os_path_import_alias_keeps_posix_summary():
    payload = inspect_path_command(
        'from os import path as path_module\n    '
        'os.system("echo " + shlex.quote(path_module.basename(value)))',
        assumptions=POSIX_PATH_ASSUMPTIONS,
    )
    assert payload["command_construction_status"] == "SANITIZED", payload


def test_os_path_summary_requires_executed_stdlib_import():
    payload = inspect_path_command(
        'os.system("echo " + shlex.quote(os.path.basename(value)))',
        assumptions=POSIX_PATH_ASSUMPTIONS,
        imports="import shlex",
    )
    assert payload["command_construction_status"] in {"AMBIGUOUS", "UNAVAILABLE"}, payload
    assert payload["analysis_gaps"][0]["call"] == "os.path.basename"


@pytest.mark.parametrize("assumptions", [
    {},
    {"is_windows()": False},
    {"sys.platform.startswith('linux')": True},
    {"sys.platform.startswith('linux')": False, "is_windows()": True},
    {"sys.platform.startswith('linux')": True, "is_windows()": True},
])
def test_os_path_summary_requires_explicit_consistent_posix_subject(assumptions):
    payload = inspect_path_command(
        'os.system("echo " + shlex.quote(os.path.dirname(value)))',
        assumptions=assumptions,
    )
    assert payload["command_construction_status"] in {"AMBIGUOUS", "UNAVAILABLE"}, payload
    assert payload["analysis_gaps"][0]["call"] == "os.path.dirname"
    assert payload["issues"]


@pytest.mark.parametrize("body", [
    'import pathlib as os\n    os.system("echo " + shlex.quote(os.path.basename(value)))',
    'os.path = obj\n    os.system("echo " + shlex.quote(os.path.basename(value)))',
    'os.system("echo " + shlex.quote(os.path.basename(obj)))',
    'os.system("echo " + shlex.quote(os.path.basename(42)))',
    'os.system("echo " + shlex.quote(os.path.basename(effect(value))))',
    'os.system("echo " + os.path.join(effect(value), "/fixed"))',
])
def test_posix_path_summary_requires_canonical_binding_builtin_string_and_resolved_effects(body):
    payload = inspect_path_command(body, assumptions=POSIX_PATH_ASSUMPTIONS)
    assert payload["command_construction_status"] in {"AMBIGUOUS", "UNAVAILABLE"}, payload
    assert payload["issues"]
