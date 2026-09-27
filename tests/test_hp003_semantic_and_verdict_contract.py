"""Rigorous semantic and verdict-contract tests for command-injection and hp003 diagnostics.

Offline tests only; follows Phase 4 specifications without relaxing evidence contracts.
Covers regression counterexamples:
1. Helper sanitized return status cannot mask caller's unsanitized sink.
2. Omitting ambiguous/unavailable command inspection citation cannot bypass VULNERABLE gate.
3. JSON tool budget exhaustion structured flag triggers immediate finalization and closes tool calls.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.analysis.commands import analyze_command, command_status, shell_status
from cv_agent.tools.identity import candidate_subject, repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.models import CommandConstructionInput, PathInput
from cv_agent.tools.validation.patterns import static_check
from cv_agent.tools.validation.registry import repository_tools, validation_tools
from cv_agent.agents.react import ReActEngine, run_expert
from cv_agent.agents.evidence_policy import validate_conclusion, _candidate_local_line, _command_status
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS


# ==============================================================================
# 6.1 分析器语义测试 (Analyzer Semantic Tests)
# ==============================================================================

def test_helper_internal_unprocessed_execution_cannot_support_safe():
    """Helper 内部执行未经处理的输入：不得错误支持 SAFE."""
    caller = CodeDocument(
        repository_id="r",
        path="caller.py::entry@1-4",
        text="def entry(value):\n    run_it(value)\n",
        defines=("entry",),
        calls=("run_it",),
    )
    helper = CodeDocument(
        repository_id="r",
        path="helper.py::run_it@1-4",
        text="def run_it(cmd):\n    import subprocess\n    subprocess.Popen(cmd, shell=True)\n",
        defines=("run_it",),
    )
    analysis = analyze_command(caller, (helper,))
    assert command_status(analysis) in {"UNSANITIZED", "AMBIGUOUS"}
    assert command_status(analysis) != "SANITIZED"


def test_unresolved_helper_with_unused_return_retains_unresolved_impact():
    """Helper 未解析，但返回值未使用：内部副作用不能因此被忽略（不能盲目判安全）."""
    caller = CodeDocument(
        repository_id="r",
        path="caller.py::entry@1-6",
        text="def entry(value):\n    opaque_helper(value)\n    import subprocess\n    subprocess.Popen(['ls', '-la'])\n",
        defines=("entry",),
        calls=("opaque_helper",),
    )
    helper = CodeDocument(
        repository_id="r",
        path="helper.py::opaque_helper@1-6",
        text="def opaque_helper(val):\n    try:\n        pass\n    except Exception:\n        pass\n",
        defines=("opaque_helper",),
    )
    analysis = analyze_command(caller, (helper,))
    # Helper failure must keep the whole candidate from claiming SANITIZED
    assert command_status(analysis) != "SANITIZED"


def test_helper_modifying_command_container_taints_subsequent_execution():
    """Helper 修改命令容器：污染能影响后续命令分析."""
    caller = CodeDocument(
        repository_id="r",
        path="caller.py::entry@1-6",
        text="def entry(val):\n    cmd = ['echo']\n    mutate(cmd, val)\n    import subprocess\n    subprocess.Popen(cmd)\n",
        defines=("entry",),
        calls=("mutate",),
    )
    helper = CodeDocument(
        repository_id="r",
        path="helper.py::mutate@1-4",
        text="def mutate(container, val):\n    container[0] = val\n",
        defines=("mutate",),
    )
    analysis = analyze_command(caller, (helper,))
    assert command_status(analysis) != "SANITIZED"


def test_aliased_container_mutation_cannot_be_ignored():
    """通过别名修改同一容器：不能只检查原始变量名."""
    doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-7",
        text="def entry(val):\n    cmd = ['echo']\n    alias = cmd\n    alias.append(val)\n    import subprocess\n    subprocess.Popen(cmd)\n",
        defines=("entry",),
    )
    analysis = analyze_command(doc)
    # Container mutation via attribute/method call must not be silently treated as SANITIZED
    assert command_status(analysis) != "SANITIZED"


def test_unresolved_destructuring_cannot_reach_sanitized():
    """未解析解包影响命令参数：不能凭 unknown 得到安全结论."""
    doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-6",
        text="def entry(val):\n    a, b = val\n    import os\n    os.system(f'echo {a}')\n",
        defines=("entry",),
    )
    analysis = analyze_command(doc)
    # Non-literal destructuring binds unknown; unknown cannot reach SANITIZED
    assert command_status(analysis) in {"AMBIGUOUS", "UNSANITIZED"}
    assert command_status(analysis) != "SANITIZED"


def test_unknown_destructuring_retains_iteration_effect_gap():
    """已证明无关的解包：可以继续分析，且不丢其他未知行为."""
    doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-7",
        text="def entry(val):\n    import shlex, os\n    x, y = val\n    cmd = f'echo {shlex.quote(val)}'\n    os.system(cmd)\n",
        defines=("entry",),
    )
    analysis = analyze_command(doc)
    # C2/C3: an unknown iterable may execute code even if its values are unused.
    assert analysis.issues
    assert command_status(analysis) == "AMBIGUOUS"


@pytest.mark.parametrize("operation", [
    "mutate(value)", "a, b = value", "value and mutate(value)",
    "mutate(value) or value", "value == mutate(value)", "-mutate(value)",
])
def test_unknown_execution_effect_cannot_support_whole_function_safe(operation):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    {operation}\n    os.system('echo ' + shlex.quote(value))\n",
        "def build_cmd(value):\n    return value\n",
    )
    subject = subject.model_copy(update={"entry_line": 1})
    assert data["issues"]
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")


@pytest.mark.parametrize("operation", ["False and mutate(value)", "True or mutate(value)", "2 < 1 < mutate(value)"])
def test_dead_expression_effect_does_not_block_safe_command(operation):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    {operation}\n    os.system('echo ' + shlex.quote(value))\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["issues"]
    vote(steps, subject.model_copy(update={"entry_line": 1}), "SAFE")


@pytest.mark.parametrize("operation", ["mutate(value)", "a, b = value"])
def test_unknown_effect_after_independent_unsafe_sink_preserves_witness(operation):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    os.system(value)\n    {operation}\n",
        "def build_cmd(value):\n    return value\n",
    )
    subject = subject.model_copy(update={"entry_line": 1})
    assert data["issues"]
    assert any(fact["status"] == "UNSANITIZED" for fact in data["sink_facts"])
    vote(steps, subject, "VULNERABLE")


@pytest.mark.parametrize("second_condition, expected", [
    ("flag", "SANITIZED"), ("not flag", "UNSANITIZED"),
])
@pytest.mark.parametrize("rebind", [False, True])
@pytest.mark.parametrize("ternary", [False, True])
def test_repeated_condition_preserves_path_binding_in_real_admission(second_condition, expected, rebind, ternary):
    from test_review_followup import inspect_and_trace, vote

    reassignment = "    flag = not flag\n" if rebind else ""
    if rebind:
        expected = "UNSANITIZED" if expected == "SANITIZED" else "SANITIZED"
    construction = ("    cmd = 'echo ' + shlex.quote(value) if flag else value\n" if ternary else
                    "    if flag:\n        cmd = 'echo ' + shlex.quote(value)\n"
                    "    else:\n        cmd = value\n")
    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n" + construction
        + reassignment + f"    if {second_condition}:\n        os.system(cmd)\n",
        "def build_cmd(value):\n    return value\n",
    )
    subject = subject.model_copy(update={"entry_line": 1})
    assert not data["issues"]
    assert {fact["status"] for fact in data["sink_facts"]} == {expected}
    vote(steps, subject, "SAFE" if expected == "SANITIZED" else "VULNERABLE")
    with pytest.raises(ValueError):
        vote(steps, subject, "VULNERABLE" if expected == "SANITIZED" else "SAFE")


@pytest.mark.parametrize("label", ["SAFE", "VULNERABLE"])
@pytest.mark.parametrize("change", [
    {"source_digest": "different-source"}, {"candidate_id": "different-candidate"},
    {"entry_boolean_arguments": {"enabled": True}},
])
def test_real_command_observation_cannot_transfer_between_subjects(label, change):
    from test_review_followup import inspect_and_trace, vote

    command = "'echo ' + shlex.quote(value)" if label == "SAFE" else "value"
    _, steps, subject = inspect_and_trace(
        f"def entry(value):\n    os.system({command})\n",
        "def build_cmd(value):\n    return value\n",
    )
    vote(steps, subject, label)
    with pytest.raises(ValueError):
        vote(steps, subject.model_copy(update=change), label)


@pytest.mark.parametrize("target", ["loop", "chain"])
@pytest.mark.parametrize("valid", [False, True])
def test_real_unpack_paths_support_only_surviving_command_witness(target, valid):
    from test_review_followup import inspect_and_trace, vote

    tail = ("    for a, b in [pair]:\n        os.system(b)\n" if target == "loop" else
            "    copy = a, b = pair\n    os.system(b)\n")
    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n    pair = build_cmd(value, flag)\n" + tail,
        "def build_cmd(value, flag):\n    if flag:\n        return "
        + ("(0, value)" if valid else "(0,)") + "\n    return (1,)\n",
    )
    if valid:
        assert not data["issues"]
        vote(steps, subject, "VULNERABLE")
    else:
        assert data["issues"]
        assert not data["sink_facts"]
        with pytest.raises(ValueError):
            vote(steps, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")


@pytest.mark.parametrize("guard", ["flag and enabled", "flag or enabled", "flag and not enabled"])
@pytest.mark.parametrize("opposite", [False, True])
def test_repeated_boolean_expression_keeps_feasible_paths(guard, opposite):
    from test_review_followup import inspect_and_trace, vote

    consumer = f"not ({guard})" if opposite else guard
    data, steps, subject = inspect_and_trace(
        "def entry(value, flag, enabled):\n"
        f"    if {guard}:\n        command = 'echo ' + shlex.quote(value)\n"
        "    else:\n        command = value\n"
        f"    if {consumer}:\n        os.system(command)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["issues"]
    assert {item["status"] for item in data["sink_facts"]} == {"UNSANITIZED" if opposite else "SANITIZED"}
    vote(steps, subject, "VULNERABLE" if opposite else "SAFE")
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE" if opposite else "VULNERABLE")


@pytest.mark.parametrize("rebind", [False, True])
@pytest.mark.parametrize("opposite", [False, True])
@pytest.mark.parametrize("inline", [False, True])
@pytest.mark.parametrize("keyword", [False, True])
def test_helper_return_conditions_follow_actual_arguments(rebind, opposite, inline, keyword):
    from test_review_followup import inspect_and_trace, vote

    call = "build_cmd(text=value, enabled=flag)" if keyword else "build_cmd(value, flag)"
    setup = "" if inline else f"    command = {call}\n"
    if rebind:
        setup += "    flag = not flag\n"
    consumer = call if inline else "command"
    condition = "not flag" if opposite else "flag"
    dangerous = opposite if inline else opposite != rebind
    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n" + setup
        + f"    if {condition}:\n        os.system({consumer})\n",
        "def build_cmd(text, enabled):\n"
        "    if enabled:\n        return 'echo ' + shlex.quote(text)\n"
        "    return text\n",
    )
    assert not data["issues"]
    assert {item["status"] for item in data["sink_facts"]} == {"UNSANITIZED" if dangerous else "SANITIZED"}
    vote(steps, subject, "VULNERABLE" if dangerous else "SAFE")
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE" if dangerous else "VULNERABLE")


@pytest.mark.parametrize("setup,condition", [
    ("flag = not flag", "flag"),
    ("alias = flag", "flag and not alias"),
])
def test_boolean_value_identity_survives_negation_and_aliasing(setup, condition):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value, flag):\n    {setup}\n"
        "    command = build_cmd(value, flag)\n"
        f"    if {condition}:\n        os.system(command)\n"
        "    os.system('fixed')\n",
        "def build_cmd(value, flag):\n    if flag:\n        return 'echo ' + shlex.quote(value)\n"
        "    return value\n",
    )
    assert not data["issues"]
    assert {item["status"] for item in data["sink_facts"]} == {"SANITIZED"}
    vote(steps, subject, "SAFE")


def test_conditional_helper_return_does_not_erase_its_own_dangerous_sink():
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n    command = build_cmd(value, flag)\n"
        "    if flag:\n        os.system(command)\n",
        "def build_cmd(value, flag):\n    os.system(value)\n"
        "    if flag:\n        return 'echo ' + shlex.quote(value)\n    return value\n",
    )
    assert not data["issues"]
    assert any(item["path"] == "helper.py" and item["status"] == "UNSANITIZED" for item in data["sink_facts"])
    vote(steps, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")


@pytest.mark.parametrize("label", ["SAFE", "VULNERABLE"])
def test_command_observation_without_identity_cannot_prove_production_candidate(label):
    from test_review_followup import inspect_and_trace, vote

    command = "'echo ' + shlex.quote(value)" if label == "SAFE" else "value"
    _, steps, subject = inspect_and_trace(
        f"def entry(value):\n    os.system({command})\n",
        "def build_cmd(value):\n    return value\n",
    )
    vote(steps, subject, label)
    incomplete = [item.model_copy(update={"observation": item.observation.model_copy(update={"subject": None})})
                  for item in steps]
    with pytest.raises(ValueError):
        vote(incomplete, subject, label)


@pytest.mark.parametrize("mismatch", [{"source_digest": "stale"}, {"repository_id": "other"}])
def test_command_tool_does_not_stamp_unverified_source_identity(mismatch):
    from cv_agent.tools.identity import repository_source_digest

    document = CodeDocument(repository_id="r", path="entry.py", defines=("entry",),
                            text="def entry(value):\n    os.system(value)\n")
    index = RepositoryIndex([document])
    subject = ValidationSubject(property_id="command-execution", candidate_id="c", repository_id="r", entry_path=document.path,
                                source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(candidate_path=document.path, admitted_paths=frozenset({document.path}),
                               subject=subject, max_observation_tokens=10000)
    arguments = CommandConstructionInput(source_path=document.path)
    valid = command_construction(index, arguments, scope)
    assert valid.status == "ok"
    assert valid.subject == subject
    invalid_scope = ToolExecutionScope(candidate_path=document.path, admitted_paths=scope.admitted_paths,
                                       subject=subject.model_copy(update=mismatch), max_observation_tokens=10000)
    assert command_construction(index, arguments, invalid_scope).status == "blocked"


@pytest.mark.parametrize("mutation", [
    "alias = os\n    alias.system = replacement",
    "alias = unknown\n    alias.property = value",
    "env = {}\n    env[mutate(value)] = value",
])
def test_unknown_assignment_effects_cannot_support_safe(mutation):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    {mutation}\n    os.system('echo ' + shlex.quote(value))\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert data["issues"]
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")


def test_owned_dictionary_assignment_is_a_pure_control():
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        "def entry(value):\n    env = {}\n    alias = env\n    alias['key'] = value\n"
        "    os.system('echo ' + shlex.quote(value))\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["issues"]
    vote(steps, subject, "SAFE")


@pytest.mark.parametrize("operation", ["ignored = value.attribute", "ignored = unknown[0]", "ignored = (value,)[unknown]"])
@pytest.mark.parametrize("before_sink", [True, False])
def test_unknown_read_protocol_preserves_effect_gap_and_independent_witness(operation, before_sink):
    from test_review_followup import inspect_and_trace, vote

    body = (f"    {operation}\n    os.system('echo ' + shlex.quote(value))\n" if before_sink else
            f"    os.system(value)\n    {operation}\n")
    data, steps, subject = inspect_and_trace("def entry(value):\n" + body,
                                            "def build_cmd(value):\n    return value\n")
    assert data["issues"]
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")
    if before_sink:
        assert not data["sink_facts"]
        with pytest.raises(ValueError):
            vote(steps, subject, "VULNERABLE")
    else:
        vote(steps, subject, "VULNERABLE")


@pytest.mark.parametrize("read", ["('fixed',)[0]", "'fixed'[0]"])
def test_known_builtin_reads_keep_safe_positive_control(read):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(f"def entry(value):\n    command = {read}\n    os.system(command)\n",
                                            "def build_cmd(value):\n    return value\n")
    assert not data["issues"]
    vote(steps, subject, "SAFE")


@pytest.mark.parametrize("expression", [
    "int(unknown)", "shlex.quote(unknown)", "unknown == 1", "-unknown", "not unknown",
    "unknown + value", "f'{unknown}'", "f'{mutate(value)!r}'", "f'{value:{mutate(value)}}'",
])
def test_unknown_python_protocols_do_not_disappear_before_safe_sink(expression):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    ignored = {expression}\n    os.system('echo ' + shlex.quote(value))\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert data["issues"]
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")


@pytest.mark.parametrize("expression", ["int(value)", "value == 'x'", "-1", "not value", "f'{value}'", "'prefix' + value"])
def test_primitive_value_operations_keep_safe_control(expression):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    ignored = {expression}\n    os.system('echo ' + shlex.quote(value))\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["issues"]
    vote(steps, subject, "SAFE")


@pytest.mark.parametrize("expression", ["int('invalid')", "int((1,))", "'text' + 1"])
def test_known_primitive_failures_do_not_create_later_unsafe_witness(expression):
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        f"def entry(value):\n    ignored = {expression}\n    os.system(value)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["sink_facts"]
    with pytest.raises(ValueError):
        vote(steps, subject, "VULNERABLE")
    pure, pure_steps, pure_subject = inspect_and_trace(
        "def entry(value):\n    ignored = int('12')\n    os.system(value)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not pure["issues"]
    vote(pure_steps, pure_subject, "VULNERABLE")


def test_known_comparison_does_not_create_an_infeasible_command_path():
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        "def entry(value):\n    if 'text' == 3:\n        os.system(value)\n    os.system('fixed')\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["issues"]
    assert {item["status"] for item in data["sink_facts"]} == {"SANITIZED"}
    vote(steps, subject, "SAFE")


def test_unmodeled_comparison_relation_cannot_mint_a_dangerous_path():
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n    if flag == 'yes':\n        command = 'echo ' + shlex.quote(value)\n"
        "    else:\n        command = value\n    if flag == 'yes':\n        os.system(command)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert data["issues"] or {item["status"] for item in data["sink_facts"]} == {"SANITIZED"}
    with pytest.raises(ValueError):
        vote(steps, subject, "VULNERABLE")


@pytest.mark.parametrize("opposite", [False, True])
def test_nested_conditional_call_argument_keeps_its_guard(opposite):
    from test_review_followup import inspect_and_trace, vote

    consumer = "not flag" if opposite else "flag"
    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n"
        "    command = build_cmd('echo ' + shlex.quote(value) if flag else value)\n"
        f"    if {consumer}:\n        os.system(command)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["issues"]
    assert {item["status"] for item in data["sink_facts"]} == {"UNSANITIZED" if opposite else "SANITIZED"}
    vote(steps, subject, "VULNERABLE" if opposite else "SAFE")


def test_conditional_invalid_conversions_have_no_normal_successor():
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n    ignored = int('invalid' if flag else 'also invalid')\n    os.system(value)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert not data["sink_facts"]
    with pytest.raises(ValueError):
        vote(steps, subject, "VULNERABLE")


@pytest.mark.parametrize("label", ["SAFE", "VULNERABLE"])
@pytest.mark.parametrize("entry_line", [39, 20, 99])
def test_candidate_outside_source_slice_cannot_borrow_command_proof(label, entry_line):
    from test_review_followup import vote

    command = "'echo ' + shlex.quote(value)" if label == "SAFE" else "value"
    document = CodeDocument(repository_id="r", path="entry.py::entry@40-41", defines=("entry",),
                            text=f"def entry(value):\n    os.system({command})\n")
    index = RepositoryIndex([document])
    subject = ValidationSubject(input_parameters=('value',), property_id="command-execution", candidate_id="c", repository_id="r", entry_path=document.path,
                                entry_line=40, source_digest=repository_source_digest(index))

    def observe(current_subject):
        scope = ToolExecutionScope(candidate_path=document.path, admitted_paths=frozenset({document.path}),
                                   subject=current_subject, max_observation_tokens=10000)
        observation = command_construction(index, CommandConstructionInput(source_path=document.path), scope)
        observation = observation.model_copy(update={"citation_id": "tool:cmd"})
        return [ReActStep(step=1, model_id="offline", observation=observation,
                          tool_call=ModelToolCall(call_id="cmd", name=observation.tool, arguments={}))]

    original = observe(subject)
    vote(original, subject, label)
    exact_sink = subject.model_copy(update={"entry_line": 41})
    vote(observe(exact_sink), exact_sink, label)
    outside = subject.model_copy(update={"entry_line": entry_line})
    with pytest.raises(ValueError):
        vote(observe(outside), outside, label)
    with pytest.raises(ValueError, match="outside the inspected source slice"):
        vote(original, outside, label)


@pytest.mark.parametrize("offset", [0, 39])
@pytest.mark.parametrize("decorated", [False, True])
@pytest.mark.parametrize("label", ["SAFE", "VULNERABLE"])
def test_parsed_function_header_defines_whole_function_scope(offset, decorated, label):
    from test_review_followup import vote

    command = "'echo ' + shlex.quote(value)" if label == "SAFE" else "value"
    decorator = "@wrapper\n" if decorated else ""
    source = "import os, shlex\n\n" + decorator + f"def entry(value):\n    os.system({command})\n"
    path = f"entry.py::entry@40-{39 + len(source.splitlines())}" if offset else "entry.py"
    document = CodeDocument(repository_id="r", path=path, text=source, defines=("entry",))
    index = RepositoryIndex([document])
    subject = ValidationSubject(input_parameters=('value',), property_id="command-execution", candidate_id="c", repository_id="r", entry_path=path,
                                entry_line=offset + 3 + int(decorated), source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(candidate_path=path, admitted_paths=frozenset({path}), subject=subject,
                               max_observation_tokens=10000)
    observation = command_construction(index, CommandConstructionInput(source_path=path), scope)
    observation = observation.model_copy(update={"citation_id": "tool:cmd"})
    steps = [ReActStep(step=1, model_id="offline", observation=observation,
                       tool_call=ModelToolCall(call_id="cmd", name=observation.tool, arguments={}))]
    if decorated:
        for proposed in ("SAFE", "VULNERABLE"):
            with pytest.raises(ValueError):
                vote(steps, subject, proposed)
    else:
        vote(steps, subject, label)
        with pytest.raises(ValueError):
            vote(steps, subject, "VULNERABLE" if label == "SAFE" else "SAFE")


@pytest.mark.parametrize("ambiguous", [False, True])
def test_static_command_alone_never_substitutes_for_command_proof(ambiguous):
    from test_review_followup import inspect_and_trace, vote

    sink = "subprocess.Popen(value, shell=flag)" if ambiguous else "os.system(value)"
    _, steps, subject = inspect_and_trace(f"def entry(value, flag):\n    {sink}\n",
                                          "def build_cmd(value):\n    return value\n")
    with pytest.raises(ValueError):
        vote(steps[:1], subject, "VULNERABLE")
    if ambiguous:
        with pytest.raises(ValueError):
            vote(steps, subject, "VULNERABLE")
    else:
        vote(steps, subject, "VULNERABLE")


@pytest.mark.parametrize("quoted", [False, True])
def test_authorization_pattern_cannot_refute_command_injection(quoted):
    from cv_agent.tools.validation.authorization import guards
    from test_review_followup import vote

    command = "'echo ' + shlex.quote(value)" if quoted else "value"
    document = CodeDocument(repository_id="r", path="entry.py", defines=("entry",),
                            text=f"def entry(value, is_admin):\n    if is_admin:\n        os.system({command})\n")
    index = RepositoryIndex([document])
    subject = ValidationSubject(input_parameters=('value', 'is_admin'), property_id="command-execution", candidate_id="c", repository_id="r", entry_path=document.path,
                                entry_line=1, source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(candidate_path=document.path, admitted_paths=frozenset({document.path}),
                               subject=subject, max_observation_tokens=10000)
    observations = [command_construction(index, CommandConstructionInput(source_path=document.path), scope),
                    guards(index, PathInput(path=document.path), scope)]
    assert json.loads(observations[1].content)["guards"]
    steps = [ReActStep(step=i, model_id="offline", observation=obs.model_copy(update={"citation_id": f"tool:{i}"}),
                       tool_call=ModelToolCall(call_id=str(i), name=obs.tool, arguments={}))
             for i, obs in enumerate(observations, 1)]
    vote(steps, subject, "SAFE" if quoted else "VULNERABLE")
    with pytest.raises(ValueError):
        vote(steps, subject, "VULNERABLE" if quoted else "SAFE")


def test_secondary_shell_after_quoting_cannot_be_sanitized():
    """Quoting 后被重新拼接或解释：不能仅见 shlex.quote 就认定安全."""
    doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-6",
        text="def entry(val):\n    import shlex, os\n    quoted = shlex.quote(val)\n    os.system(f'bash -c \"echo {quoted}\"')\n",
        defines=("entry",),
    )
    analysis = analyze_command(doc)
    # Nested secondary shell invocation (bash -c) must be flagged AMBIGUOUS, never SANITIZED
    assert command_status(analysis) == "AMBIGUOUS"


def test_hp003_minimal_reproducer_distinguishes_fixed_and_vulnerable():
    """实际修复前后路径的最小复现：能区分两者，或明确指出不支持原因."""
    vuln_helper = CodeDocument(
        repository_id="r",
        path="mlflow/pyfunc/mlserver.py::get_cmd@1-4",
        text="def get_cmd(model_uri):\n    return f'mlserver start {model_uri}'\n",
        defines=("get_cmd",),
    )
    fixed_helper = CodeDocument(
        repository_id="r",
        path="mlflow/pyfunc/mlserver.py::get_cmd@1-5",
        text="def get_cmd(model_uri):\n    import shlex\n    return f'mlserver start {shlex.quote(model_uri)}'\n",
        defines=("get_cmd",),
    )
    vuln_analysis = analyze_command(vuln_helper)
    fixed_analysis = analyze_command(fixed_helper)
    assert shell_status(vuln_analysis.returned) == "UNSANITIZED"
    assert shell_status(fixed_analysis.returned) == "SANITIZED"


# ==============================================================================
# 6.2 判决契约与门禁测试 (Verdict Contract Tests)
# ==============================================================================

def test_helper_sanitized_status_cannot_mask_caller_unsanitized_sink():
    """[P1 反例] Helper 返回值安全，但调用方未使用并执行未处理输入：不得允许 SAFE."""
    code = (
        "def build_cmd(value):\n"
        "    return 'echo ' + shlex.quote(value)\n"
        "\n"
        "def entry(value):\n"
        "    build_cmd(value)\n"
        "    os.system(value)\n"
    )
    entry_doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@4-6",
        text="def entry(value):\n    build_cmd(value)\n    os.system(value)\n",
        defines=("entry",),
        calls=("build_cmd",),
    )
    helper_doc = CodeDocument(
        repository_id="r",
        path="helper.py::build_cmd@1-2",
        text="def build_cmd(value):\n    import shlex\n    return 'echo ' + shlex.quote(value)\n",
        defines=("build_cmd",),
    )
    index = RepositoryIndex([entry_doc, helper_doc])
    subject = ValidationSubject(input_parameters=('value',), property_id="command-execution",
        candidate_id="c1",
        repository_id="r",
        entry_path=entry_doc.path,
        entry_line=4,  # function header line
        source_digest=repository_source_digest(index),
        analysis_scope="subprocess/os.system command execution",
    )
    scope = ToolExecutionScope(
        candidate_path=entry_doc.path,
        admitted_paths=frozenset([entry_doc.path, helper_doc.path]),
        subject=subject,
        max_observation_tokens=10000,
    )
    obs = command_construction(index, CommandConstructionInput(source_path=entry_doc.path), scope)
    obs = obs.model_copy(update={"citation_id": "tool:1"})
    assert json.loads(obs.content)["command_construction_status"] == "UNSANITIZED"
    assert _command_status(obs, subject) == "UNSANITIZED"

    step = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs)
    vote_safe = AgentExpertConclusion(
        expert="scan",
        label="SAFE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1"],
        supporting_observation_ids=["tool:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Helper is sanitized.",
    )
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        validate_conclusion(vote_safe, [step], frozenset(["tool:1"]), subject=subject)


def test_omitting_ambiguous_command_inspection_citation_cannot_bypass_vulnerable_gate():
    """[P1 反例] subprocess.Popen(value, shell=flag) 返回 AMBIGUOUS，省略引用仍必须被拒绝."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="c",
        repository_id="r",
        entry_path="entry.py",
        entry_line=2,
        source_digest="d",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_static = ToolObservation(
        tool="run_static_check",
        status="ok",
        content=json.dumps({"finding_count": 1, "findings": [{"category": "command-execution", "line": 2, "match": "subprocess.Popen("}], "path": "entry.py"}),
        citation_id="tool:1",
        evidence_ids=("tool:1",),
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps({
            "command_construction_status": "AMBIGUOUS",
            "source_path": "entry.py",
            "helpers": [],
            "sink_facts": [{"line": 2, "path": "entry.py", "status": "AMBIGUOUS"}],
        }),
        citation_id="tool:2",
        evidence_ids=("command_construction:entry.py", "tool:2"),
    )
    steps = [
        ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="run_static_check", arguments={}), observation=obs_static),
        ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="inspect_command_construction", arguments={}), observation=obs_cmd),
    ]

    # Manner A: Model cites both static and command inspection -> REJECTED
    vote_both = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1", "tool:2"],
        supporting_observation_ids=["tool:1", "tool:2"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Command is ambiguous so injection is possible.",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote_both, steps, frozenset(["tool:1", "tool:2"]), subject=subject)

    # Manner B: Model omits command inspection citation and cites ONLY static scan -> MUST ALSO BE REJECTED
    vote_static_only = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1"],
        supporting_observation_ids=["tool:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Static scan found subprocess.Popen.",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote_static_only, steps, frozenset(["tool:1"]), subject=subject)


def test_admission_outcome_invariant_to_adding_or_removing_static_scan():
    """保持候选、命令检查结果和支持证据相同，只增删静态扫描观察，判决准入结果不应改变."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="c",
        repository_id="r",
        entry_path="entry.py",
        entry_line=2,
        source_digest="d",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps({
            "command_construction_status": "AMBIGUOUS",
            "source_path": "entry.py",
            "helpers": [],
            "sink_facts": [{"line": 2, "path": "entry.py", "status": "AMBIGUOUS"}],
        }),
        citation_id="tool:cmd",
        evidence_ids=("command_construction:entry.py", "tool:cmd"),
    )
    obs_static = ToolObservation(
        tool="run_static_check",
        status="ok",
        content=json.dumps({
            "finding_count": 1,
            "findings": [{"category": "command-execution", "line": 2, "match": "subprocess.Popen("}],
            "path": "entry.py",
        }),
        citation_id="tool:static",
        evidence_ids=("tool:static",),
    )
    vote = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:cmd"],
        supporting_observation_ids=["tool:cmd"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Command is ambiguous so injection is unconfirmed.",
    )
    step_cmd = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs_cmd)
    step_static = ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="run_static_check", arguments={}), observation=obs_static)

    # 1. Without static scan in trace: MUST BE REJECTED
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote, [step_cmd], frozenset(["tool:cmd"]), subject=subject)

    # 2. With static scan added into trace: MUST STILL BE REJECTED IDENTICALLY
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote, [step_cmd, step_static], frozenset(["tool:cmd", "tool:static"]), subject=subject)


def test_vulnerable_prediction_supported_only_by_unresolved_is_rejected():
    """只有 UNRESOLVED 支持的 VULNERABLE 被拒绝."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="c1",
        repository_id="r1",
        entry_path="test.py",
        source_digest="digest",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_static = ToolObservation(
        tool="run_static_check",
        status="ok",
        content=json.dumps({"findings": [{"category": "command-execution", "line": 2}], "callee": "get_cmd", "path": "test.py"}),
        citation_id="tool:1",
        evidence_ids=("tool:1",),
    )
    obs_unavail = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({"command_construction_status": "UNAVAILABLE", "source_path": "test.py", "helpers": []}),
        citation_id="tool:2",
        evidence_ids=("command_construction:test.py", "tool:2"),
    )
    steps = [
        ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="run_static_check", arguments={}), observation=obs_static),
        ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="inspect_command_construction", arguments={}), observation=obs_unavail),
    ]
    vote = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1", "tool:2"],
        supporting_observation_ids=["tool:1", "tool:2"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Inspector returned UNAVAILABLE so injection is unverified.",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote, steps, frozenset(["tool:1", "tool:2"]), subject=subject)


def test_vulnerable_allowed_when_sufficient_vulnerability_evidence_exists_even_with_unresolved_helper():
    """有充分漏洞证据，同时存在另一个未解析 helper，仍可判 VULNERABLE（正例实际连接到 execution sink）."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="c1",
        repository_id="r1",
        entry_path="test.py",
        source_digest="digest",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_static = ToolObservation(
        tool="run_static_check",
        status="ok",
        content=json.dumps({"findings": [{"category": "command-execution", "line": 5}], "path": "test.py"}),
        citation_id="tool:1",
        evidence_ids=("tool:1",),
    )
    obs_cmd = ToolObservation(
        subject=subject,  # C1: bind this synthetic proof to its declared candidate.
        tool="inspect_command_construction",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({
            "command_construction_status": "UNSANITIZED",
            "source_path": "test.py",
            "sink_facts": [
                {"call": "subprocess.Popen", "line": 5, "path": "test.py", "status": "UNSANITIZED"}
            ],
            "helpers": [
                {"path": "active_helper.py", "status": "UNSANITIZED"},
                {"path": "unrelated_try.py", "status": "AMBIGUOUS"},
            ],
            "issues": ["unrelated helper has unsupported semantics"],
        }),
        citation_id="tool:2",
        evidence_ids=("command_construction:test.py", "tool:2"),
    )
    steps = [
        ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="run_static_check", arguments={}), observation=obs_static),
        ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="inspect_command_construction", arguments={}), observation=obs_cmd),
    ]
    vote = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1", "tool:2"],
        supporting_observation_ids=["tool:1", "tool:2"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Sink on line 5 connects unescaped command interpolation into Popen.",
    )
    # Must succeed: affirmative connected vulnerability evidence is present
    validate_conclusion(vote, steps, frozenset(["tool:1", "tool:2"]), subject=subject)


def test_safe_rejected_when_another_relevant_path_is_unresolved():
    """一条路径安全、另一条相关路径未解析，不能给候选整体 SAFE."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="c1",
        repository_id="r1",
        entry_path="test.py",
        source_digest="digest",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=json.dumps({
            "command_construction_status": "AMBIGUOUS",
            "source_path": "test.py",
            "helpers": [
                {"path": "helper1.py", "status": "SANITIZED"},
                {"path": "helper2.py", "status": "AMBIGUOUS"},
            ],
            "issues": ["unsupported helper semantics"],
        }),
        citation_id="tool:1",
        evidence_ids=("tool:1",),
    )
    step = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs_cmd)
    vote = AgentExpertConclusion(
        expert="scan",
        label="SAFE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1"],
        supporting_observation_ids=["tool:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Helper1 is sanitized.",
    )
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        validate_conclusion(vote, [step], frozenset(["tool:1"]), subject=subject)


def test_mismatched_candidate_or_undelivered_evidence_is_rejected():
    """引用错误候选、旧快照或未投递证据，被拒绝."""
    subject = ValidationSubject(
        candidate_id="c1",
        repository_id="r1",
        entry_path="test.py",
        source_digest="digest1",
    )
    obs_blocked = ToolObservation(
        tool="read_span",
        status="blocked",
        content="budget is spent",
        citation_id="tool:1",
    )
    step = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="read_span", arguments={}), observation=obs_blocked)
    vote = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1"],
        supporting_observation_ids=["tool:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Using blocked call as evidence.",
    )
    with pytest.raises(ValueError, match="Unknown evidence reference"):
        validate_conclusion(vote, [step], frozenset(), subject=subject)


# ==============================================================================
# 6.3 执行控制与预算退出测试 (Execution Control & Budget Tests)
# ==============================================================================

def test_json_tool_budget_exhaustion_triggers_finalization_and_closes_tools():
    """[P2 反例] JSON 工具返回 error/诊断时，通过结构化状态触发收尾并关闭工具 definitions."""
    text = "def entry(value):\n    import subprocess\n    subprocess.Popen(value, shell=True)\n"
    doc = CodeDocument(repository_id="r", path="entry.py", text=text, defines=("entry",))
    index = RepositoryIndex([doc])
    reg = ToolRegistry(validation_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    subject = ValidationSubject(property_id="command-execution", candidate_id="c", repository_id="r", entry_path="entry.py", source_digest=repository_source_digest(index))
    # Budget of 50 tokens is too small for inspect_command_construction payload (~150 tokens)
    scope = ToolExecutionScope(candidate_path="entry.py", admitted_paths=frozenset(["entry.py"]), subject=subject, max_observation_tokens=50)

    conclusion = {
        "expert": "scan",
        "label": "ABSTAIN",
        "confidence": 0.0,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [],
        "supporting_observation_ids": [],
        "counter_observation_ids": [],
        "unresolved_observation_ids": [],
        "rationale": "Tool observation budget exhausted; insufficient evidence to conclude.",
    }
    model = ScriptedChatModel([
        ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={"source_path": "entry.py"}),)),
        ModelReply(model_id="test", content=json.dumps(conclusion)),
    ])
    engine = ReActEngine(
        model=model, tools=reg, scope=scope,
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )

    vote = run_expert(
        engine, expert="scan", system_prompt="scan", task_prompt="inspect",
        allowed_tools=("inspect_command_construction",),
    )

    assert vote.label == "ABSTAIN"
    assert len(vote.trace) == 1
    obs = vote.trace[0].observation
    assert obs.status == "error"
    assert obs.metadata.get("budget_exhausted") is True
    # Verify tool definitions were completely closed on finalization step (definitions == ())
    assert len(model.requests) == 2
    assert len(model.requests[1][1]) == 0


def test_react_engine_exits_bounded_when_text_budget_exhausted():
    """验证文本工具预算耗尽后：诊断可见，新工具执行被关闭，收尾次数有界，模型不陷入无限调用."""
    text_short = "def helper(): return 1\n"
    text_large = "def entry(x):\n" + "".join(f"    line_{i} = {i}\n" for i in range(2000))
    doc_short = CodeDocument(repository_id="r", path="short.py", text=text_short, defines=("helper",))
    doc_large = CodeDocument(repository_id="r", path="entry.py", text=text_large, defines=("entry",))
    index = RepositoryIndex([doc_short, doc_large])
    reg = ToolRegistry(repository_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)

    subject = ValidationSubject(candidate_id="c", repository_id="r", entry_path="entry.py", source_digest="d")
    scope = ToolExecutionScope(candidate_path="entry.py", admitted_paths=frozenset(["short.py", "entry.py"]), subject=subject, max_observation_tokens=200)

    # Step 1: short read fits (~91 tokens)
    # Step 2: large read spends remaining budget (~109 tokens, exhausts budget)
    # Step 3: next tool call is refused because remaining_tokens == 0 -> budget_exhausted flag set
    # Step 4: receives closed tools, cleanly finalizes with ABSTAIN
    conclusion = {
        "expert": "scan",
        "label": "ABSTAIN",
        "confidence": 0.0,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [],
        "supporting_observation_ids": [],
        "counter_observation_ids": [],
        "unresolved_observation_ids": [],
        "rationale": "Tool observation budget exhausted; insufficient evidence to conclude.",
    }
    model = ScriptedChatModel([
        ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id="call-1", name="read_span", arguments={"path": "short.py"}),)),
        ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id="call-2", name="read_span", arguments={"path": "entry.py"}),)),
        ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id="call-3", name="search_symbols", arguments={"query": "x"}),)),
        ModelReply(model_id="test", content=json.dumps(conclusion)),
    ])
    engine = ReActEngine(
        model=model, tools=reg, scope=scope,
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )

    vote = run_expert(
        engine, expert="scan", system_prompt="scan", task_prompt="inspect",
        allowed_tools=("read_span", "search_symbols"),
    )

    assert vote.label == "ABSTAIN"
    assert len(vote.trace) == 3
    assert vote.trace[1].observation.status == "ok"
    assert vote.trace[2].observation.status == "blocked"
    assert vote.trace[2].observation.metadata.get("budget_exhausted") is True
    assert len(model.requests) == 4
    assert len(model.requests[3][1]) == 0


# ==============================================================================
# 6.4 离线历史失败重放与负对照测试 (Historical Replay & Negative Controls)
# ==============================================================================

def test_replay_run1_e3_safe_is_rejected_without_verified_download_dispatch():
    """重放 Run 1 hp003_b E3：未知 repository 分派不能支持整函数 SAFE。"""
    from cv_agent.domain.chat import ModelUsage
    from cv_agent.evaluation.datasets.composition import load_advisory_config
    from cv_agent.evaluation.datasets.advisory_source import build_pair_input
    from cv_agent.runtime.paths import PROJECT_ROOT

    config = load_advisory_config(PROJECT_ROOT, "configs/profiles/advisory_matrix_v4.json")
    pair = next(p for p in config.pairs if p.pair_id.startswith("hp003_"))
    case_b = next(c for c in pair.cases if c.case_id == "hp003_b")
    index, candidate, _ = build_pair_input(PROJECT_ROOT, pair, case_b)

    with open("artifacts/hp003_diagnosis_2026-09-25/real_runs_repaired/run_1/events.jsonl") as f:
        events = [json.loads(line) for line in f if json.loads(line).get("case_id") == "hp003_b" and json.loads(line).get("system") == "E3"]
    scan_replies_raw = [ev["reply"] for ev in events if ev.get("event") == "model_reply" and ev.get("role") == "scan"]

    replies = []
    for r in scan_replies_raw:
        tc = [ModelToolCall(call_id=t["call_id"], name=t["name"], arguments=t.get("arguments") or {}) for t in r.get("tool_calls", [])]
        u = r.get("usage") or {}
        usg = ModelUsage(input_tokens=u.get("prompt_tokens"), output_tokens=u.get("completion_tokens"), total_tokens=u.get("total_tokens"))
        replies.append(ModelReply(model_id=r.get("model", "deepseek-flash"), content=r.get("content"), tool_calls=tuple(tc), usage=usg))
    # Replay historical proposals under today's observation budget: when the
    # harness closes tools early, reuse the recorded final SAFE proposal rather
    # than issuing a now-illegal historical tool call. C3/A3 requires the
    # unverified download dispatch to remain unresolved despite a quoted sink.
    final_proposal = replies[-1]
    assert not final_proposal.tool_calls
    model_scan = ScriptedChatModel([
        (lambda messages, tools, proposal=proposal:
         final_proposal if proposal.tool_calls and not tools else proposal)
        for proposal in replies
    ])

    tools = ToolRegistry(repository_tools(index) + validation_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    subject = candidate_subject(index, candidate)
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E3_GRAPH_SINGLE)
    budget = spec.budget.model_copy(update={"graph_direction": config.graph_direction, "graph_ranking": config.graph_ranking})
    evidence = index.retrieve_context(candidate, mode=spec.retrieval, budget=budget)
    initial_eids = frozenset(item.evidence_id for item in evidence)
    admitted_paths = frozenset([candidate.path, *(item.path for item in evidence)])
    scope = ToolExecutionScope(candidate_path=candidate.path, admitted_paths=admitted_paths, initial_evidence_ids=initial_eids, subject=subject, max_observation_tokens=8192)
    engine = ReActEngine(model=model_scan, tools=tools, scope=scope, harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")

    vote = run_expert(engine, expert="scan", system_prompt="scan", task_prompt="inspect",
                      allowed_tools=("inspect_command_construction", "read_span", "run_static_check", "get_guards", "find_references", "search_symbols"))

    assert vote.label == "ABSTAIN"
    assert vote.validation_status == ValidationStatus.UNRESOLVED
    assert vote.model_calls == FULL_SYSTEM_HARNESS.react_loop.max_steps
    assert "proposed SAFE" in vote.rationale


def test_replay_run1_e4_scan_safe_is_rejected_without_verified_download_dispatch():
    """重放 Run 1 hp003_b E4 scan：引用与必做工具不能补足未知分派。"""
    from cv_agent.domain.chat import ModelUsage
    from cv_agent.evaluation.datasets.composition import load_advisory_config
    from cv_agent.evaluation.datasets.advisory_source import build_pair_input
    from cv_agent.runtime.paths import PROJECT_ROOT

    config = load_advisory_config(PROJECT_ROOT, "configs/profiles/advisory_matrix_v4.json")
    pair = next(p for p in config.pairs if p.pair_id.startswith("hp003_"))
    case_b = next(c for c in pair.cases if c.case_id == "hp003_b")
    index, candidate, _ = build_pair_input(PROJECT_ROOT, pair, case_b)

    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    budget = spec.budget.model_copy(update={"graph_direction": config.graph_direction, "graph_ranking": config.graph_ranking})
    evidence = index.retrieve_context(candidate, mode=spec.retrieval, budget=budget)
    initial_eids = frozenset(item.evidence_id for item in evidence)

    with open("artifacts/hp003_diagnosis_2026-09-25/real_runs_repaired/run_1/events.jsonl") as f:
        events = [json.loads(line) for line in f if json.loads(line).get("case_id") == "hp003_b" and json.loads(line).get("system") == "E4"]
    scan_replies_raw = [ev["reply"] for ev in events if ev.get("event") == "model_reply" and ev.get("role") == "scan"]

    replies = []
    for r in scan_replies_raw:
        tc = [ModelToolCall(call_id=t["call_id"], name=t["name"], arguments=t.get("arguments") or {}) for t in r.get("tool_calls", [])]
        u = r.get("usage") or {}
        usg = ModelUsage(input_tokens=u.get("prompt_tokens"), output_tokens=u.get("completion_tokens"), total_tokens=u.get("total_tokens"))
        replies.append(ModelReply(model_id=r.get("model", "deepseek-flash"), content=r.get("content"), tool_calls=tuple(tc), usage=usg))
    # Replay historical proposals under today's observation budget: when the
    # harness closes tools early, reuse the recorded final SAFE proposal rather
    # than issuing a now-illegal historical tool call. The command validator
    # reports a repository dispatch gap under the configured hp003 scope.
    final_proposal = replies[-1]
    assert not final_proposal.tool_calls
    model_scan = ScriptedChatModel([
        (lambda messages, tools, proposal=proposal:
         final_proposal if proposal.tool_calls and not tools else proposal)
        for proposal in replies
    ])

    tools = ToolRegistry(repository_tools(index) + validation_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    subject = candidate_subject(index, candidate)
    admitted_paths = frozenset([candidate.path, *(item.path for item in evidence)])
    scope = ToolExecutionScope(candidate_path=candidate.path, admitted_paths=admitted_paths, initial_evidence_ids=initial_eids, subject=subject, max_observation_tokens=8192)
    engine = ReActEngine(model=model_scan, tools=tools, scope=scope, harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")

    vote = run_expert(engine, expert="scan", system_prompt="scan", task_prompt="inspect",
                      allowed_tools=("inspect_command_construction", "read_span", "get_callees", "get_callers"),
                      required_validators=("inspect_command_construction",))

    assert vote.label == "ABSTAIN"
    assert vote.model_calls == FULL_SYSTEM_HARNESS.react_loop.max_steps
    assert "proposed SAFE" in vote.rationale


def test_incomplete_validation_task_demoted_with_validator_uncompleted_record():
    """验证器因预算或轮数未完成：记录验证未完成／预算终止，不伪造为普通证据不足弃权."""
    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): pass\n", defines=("entry",))
    index = RepositoryIndex([doc])
    tools = ToolRegistry(repository_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    scope = ToolExecutionScope(candidate_path="entry.py", admitted_paths=frozenset(["entry.py"]), max_observation_tokens=8192)

    # Model executes 6 read_span calls, never executing required validator "inspect_command_construction"
    conclusion = {
        "expert": "scan",
        "label": "SAFE",
        "confidence": 0.8,
        "validation_status": "UNRESOLVED",
        "evidence_ids": ["scan/tool:1"],
        "supporting_observation_ids": ["scan/tool:1"],
        "counter_observation_ids": [],
        "unresolved_observation_ids": [],
        "rationale": "I think it is safe without running validator.",
    }
    replies = [ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id=f"c{i}", name="read_span", arguments={"path": "entry.py"}),)) for i in range(6)]
    replies.append(ModelReply(model_id="test", content=json.dumps(conclusion)))
    replies.append(ModelReply(model_id="test", content=json.dumps(conclusion)))
    model = ScriptedChatModel(replies)

    engine = ReActEngine(model=model, tools=tools, scope=scope, harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")
    vote = run_expert(
        engine, expert="scan", system_prompt="scan", task_prompt="inspect",
        allowed_tools=("read_span",),
        required_validators=("inspect_command_construction",),
    )

    assert vote.label == "ABSTAIN"
    assert "Assigned validator (inspect_command_construction) did not complete" in vote.rationale
    assert "Terminated as ABSTAIN" in vote.rationale


def test_negative_controls_unknown_citations_and_planner_errors_are_not_demoted():
    """负对照：未知 citation、身份漂移、planner 失败等非证据不足异常不得被静默吞掉或转为弃权."""
    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): pass\n", defines=("entry",))
    index = RepositoryIndex([doc])
    tools = ToolRegistry(repository_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    scope = ToolExecutionScope(candidate_path="entry.py", admitted_paths=frozenset(["entry.py"]), max_observation_tokens=8192)

    # Negative Control 1: Hallucinated/unknown citation ID on final step -> Must raise, NOT demote
    hallucinated_conclusion = {
        "expert": "scan",
        "label": "SAFE",
        "confidence": 0.8,
        "validation_status": "UNRESOLVED",
        "evidence_ids": ["hallucinated/tool:999"],
        "supporting_observation_ids": ["hallucinated/tool:999"],
        "counter_observation_ids": [],
        "unresolved_observation_ids": [],
        "rationale": "Hallucinated citation.",
    }
    replies1 = [ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id=f"c{i}", name="read_span", arguments={"path": "entry.py"}),)) for i in range(6)]
    replies1.append(ModelReply(model_id="test", content=json.dumps(hallucinated_conclusion)))
    replies1.append(ModelReply(model_id="test", content=json.dumps(hallucinated_conclusion)))
    model1 = ScriptedChatModel(replies1)
    engine1 = ReActEngine(model=model1, tools=tools, scope=scope, harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")
    with pytest.raises(RuntimeError, match="ReAct loop exhausted"):
        run_expert(engine1, expert="scan", system_prompt="scan", task_prompt="inspect", allowed_tools=("read_span",))

    # Negative Control 2: Identity drift (expert outputs "taint" when assigned "scan") -> Must raise, NOT demote
    drifted_conclusion = {
        "expert": "taint",  # wrong identity
        "label": "SAFE",
        "confidence": 0.8,
        "validation_status": "UNRESOLVED",
        "evidence_ids": ["scan/tool:1"],
        "supporting_observation_ids": ["scan/tool:1"],
        "counter_observation_ids": [],
        "unresolved_observation_ids": [],
        "rationale": "Wrong expert identity.",
    }
    replies2 = [ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id=f"c{i}", name="read_span", arguments={"path": "entry.py"}),)) for i in range(6)]
    replies2.append(ModelReply(model_id="test", content=json.dumps(drifted_conclusion)))
    replies2.append(ModelReply(model_id="test", content=json.dumps(drifted_conclusion)))
    model2 = ScriptedChatModel(replies2)
    engine2 = ReActEngine(model=model2, tools=tools, scope=scope, harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")
    with pytest.raises(RuntimeError, match="ReAct loop exhausted"):
        run_expert(engine2, expert="scan", system_prompt="scan", task_prompt="inspect", allowed_tools=("read_span",))


def _ambiguous_command_trace():
    """同一候选、同一 AMBIGUOUS 命令检查、同一段源码的共享 trace."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="hp003_command_case",
        repository_id="r",
        entry_path="entry.py",
        entry_line=2,
        source_digest="d",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps({
            "command_construction_status": "AMBIGUOUS",
            "source_path": "entry.py",
            "helpers": [],
            "sink_facts": [{"line": 2, "path": "entry.py", "status": "AMBIGUOUS"}],
            "issues": [{"kind": "unresolved"}],
        }),
        citation_id="tool:cmd",
        evidence_ids=("command_construction:entry.py", "tool:cmd"),
        validation_status=ValidationStatus.UNRESOLVED,
        subject=subject,
    )
    obs_read = ToolObservation(
        tool="read_span",
        status="ok",
        content=json.dumps({"path": "entry.py", "text": "subprocess.Popen(value, shell=flag)"}),
        citation_id="tool:read",
        evidence_ids=("read:entry.py", "tool:read"),
        validation_status=ValidationStatus.UNRESOLVED,
        subject=subject,
    )
    steps = [
        ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs_cmd),
        ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="read_span", arguments={}), observation=obs_read),
    ]
    return subject, steps


def test_citation_choice_cannot_change_admission_for_same_ambiguous_inspection():
    """同一 AMBIGUOUS 检查：引用命令检查被拒，则只引用 read_span 也必须被拒."""
    subject, steps = _ambiguous_command_trace()
    vote_cite_cmd = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.7,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["command_construction:entry.py"],
        supporting_observation_ids=["tool:cmd"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites ambiguous command inspection.",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote_cite_cmd, steps, frozenset(["tool:cmd"]), subject=subject)

    vote_read_only = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.7,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["read:entry.py"],
        supporting_observation_ids=["tool:read"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites only source read for same Popen sink.",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote_read_only, steps, frozenset(["tool:read"]), subject=subject)


def test_admission_invariant_to_tool_order_and_irrelevant_read():
    """工具顺序与无关 read_span 增删不应改变同一 AMBIGUOUS 检查的准入结果."""
    subject, steps = _ambiguous_command_trace()
    vote_read_only = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.7,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["read:entry.py"],
        supporting_observation_ids=["tool:read"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites only source read for same Popen sink.",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote_read_only, steps, frozenset(["tool:read"]), subject=subject)
    # Reversed tool order must give the identical rejection.
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(vote_read_only, list(reversed(steps)), frozenset(["tool:read"]), subject=subject)
    # Trace with only the command inspection (no read_span at all) must also reject.
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(
            AgentExpertConclusion(
                expert="scan",
                label="VULNERABLE",
                confidence=0.7,
                validation_status=ValidationStatus.UNRESOLVED,
                evidence_ids=["command_construction:entry.py"],
                supporting_observation_ids=["tool:cmd"],
                counter_observation_ids=[],
                unresolved_observation_ids=[],
                rationale="Cites ambiguous command inspection.",
            ),
            steps[:1],
            frozenset(["tool:cmd"]),
            subject=subject,
        )


def test_function_head_safety_must_retain_reachable_helper_sink():
    """[P1 反例] 整函数候选：可达 helper 内危险执行不得被 path 过滤丢弃.

    反方向覆盖：安全 helper＋危险调用方已有测试；这里是危险 helper
    （os.system(value)）＋调用方自身安全汇点（shlex.quote）。真实工具整体
    返回 UNSANITIZED；门禁若只保留 entry_path 汇点，会看到 SANITIZED 而接受
    SAFE。修改前（HEAD）会拒绝。
    """
    entry_doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-4",
        text="def entry(value):\n    run_it(value)\n    import os, shlex\n    os.system('echo ' + shlex.quote(value))\n",
        defines=("entry",),
        calls=("run_it",),
    )
    helper_doc = CodeDocument(
        repository_id="r",
        path="helper.py::run_it@1-3",
        text="def run_it(cmd):\n    import os\n    os.system(cmd)\n",
        defines=("run_it",),
    )
    index = RepositoryIndex([entry_doc, helper_doc])
    subject = ValidationSubject(input_parameters=('value',), property_id="command-execution",
        candidate_id="c1",
        repository_id="r",
        entry_path=entry_doc.path,
        entry_line=1,  # function header line: whole-function scope
        source_digest=repository_source_digest(index),
        analysis_scope="os.system command execution",
    )
    scope = ToolExecutionScope(
        candidate_path=entry_doc.path,
        admitted_paths=frozenset([entry_doc.path, helper_doc.path]),
        subject=subject,
        max_observation_tokens=10000,
    )
    obs = command_construction(index, CommandConstructionInput(source_path=entry_doc.path), scope)
    obs = obs.model_copy(update={"citation_id": "tool:1"})
    assert json.loads(obs.content)["command_construction_status"] == "UNSANITIZED"
    # The reachable helper UNSANITIZED sink must survive candidate scoping.
    assert _command_status(obs, subject) == "UNSANITIZED"

    step = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs)
    vote_safe = AgentExpertConclusion(
        expert="scan",
        label="SAFE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1"],
        supporting_observation_ids=["tool:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Caller sink is quoted.",
    )
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        validate_conclusion(vote_safe, [step], frozenset(["tool:1"]), subject=subject)


def test_both_safe_helper_and_caller_support_safe():
    """T01 正例对照：helper 返回安全、调用方无新增危险时 SAFE 可成立.

    与危险-helper 反例对称：本例无人引入未处理输入，整体 SANITIZED，
    SAFE/UNRESOLVED 引用命令检查可被接受。防止 helper 修复走向“永远禁 S”。
    """
    entry_doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-4",
        text="def entry(value):\n    cmd = build_cmd(value)\n    import os\n    os.system(cmd)\n",
        defines=("entry",),
        calls=("build_cmd",),
    )
    helper_doc = CodeDocument(
        repository_id="r",
        path="helper.py::build_cmd@1-3",
        text="def build_cmd(value):\n    import shlex\n    return 'echo ' + shlex.quote(value)\n",
        defines=("build_cmd",),
    )
    index = RepositoryIndex([entry_doc, helper_doc])
    subject = ValidationSubject(input_parameters=('value',), property_id="command-execution",
        candidate_id="c1",
        repository_id="r",
        entry_path=entry_doc.path,
        entry_line=1,
        source_digest=repository_source_digest(index),
        analysis_scope="os.system command execution",
    )
    scope = ToolExecutionScope(
        candidate_path=entry_doc.path,
        admitted_paths=frozenset([entry_doc.path, helper_doc.path]),
        subject=subject,
        max_observation_tokens=10000,
    )
    obs = command_construction(index, CommandConstructionInput(source_path=entry_doc.path), scope)
    obs = obs.model_copy(update={"citation_id": "tool:1"})
    assert json.loads(obs.content)["command_construction_status"] == "SANITIZED"
    assert _command_status(obs, subject) == "SANITIZED"

    step = ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs)
    vote_safe = AgentExpertConclusion(
        expert="scan",
        label="SAFE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:1"],
        supporting_observation_ids=["tool:1"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Quoted construction covers the whole function scope.",
    )
    validate_conclusion(vote_safe, [step], frozenset(["tool:1"]), subject=subject)


def test_unexecuted_helper_cannot_pollute_the_candidate():
    """T01/T02：只被检索到、没有实际调用的 helper 不得污染候选.

    entry 不调用任何 helper；危险 helper 即使在 admitted 范围内，也不得
    出现在 sink_facts 中，更不能把整体结论变成 UNSANITIZED。
    """
    entry_doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-3",
        text="def entry(value):\n    import os, shlex\n    os.system('echo ' + shlex.quote(value))\n",
        defines=("entry",),
        calls=(),
    )
    helper_doc = CodeDocument(
        repository_id="r",
        path="helper.py::danger@1-3",
        text="def danger(cmd):\n    import os\n    os.system(cmd)\n",
        defines=("danger",),
    )
    index = RepositoryIndex([entry_doc, helper_doc])
    subject = ValidationSubject(input_parameters=('value',), property_id="command-execution",
        candidate_id="c1",
        repository_id="r",
        entry_path=entry_doc.path,
        entry_line=1,
        source_digest=repository_source_digest(index),
        analysis_scope="os.system command execution",
    )
    scope = ToolExecutionScope(
        candidate_path=entry_doc.path,
        admitted_paths=frozenset([entry_doc.path, helper_doc.path]),
        subject=subject,
        max_observation_tokens=10000,
    )
    obs = command_construction(index, CommandConstructionInput(source_path=entry_doc.path), scope)
    content = json.loads(obs.content)
    assert content["command_construction_status"] == "SANITIZED"
    assert all(fact.get("path") == entry_doc.path for fact in content["sink_facts"])
    assert _command_status(obs, subject) == "SANITIZED"


def test_line_scoped_candidates_bind_their_own_sink_line():
    """T02：单行候选绑定声明行的汇点；同文件其他独立汇点不自动归属.

    entry 第 3 行安全汇点、第 4 行危险汇点：第 3 行候选看到 SANITIZED，
    第 4 行候选看到 UNSANITIZED；切片偏移（@10-14 + entry_line=12）映射到
    同一本地行，结果一致。
    """
    entry_doc = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-5",
        text="def entry(a, b):\n    import os, shlex\n    os.system('echo ' + shlex.quote(a))\n    os.system(b)\n",
        defines=("entry",),
    )
    index = RepositoryIndex([entry_doc])
    scope_paths = frozenset([entry_doc.path])

    def observe(entry_line):
        subject = ValidationSubject(input_parameters=('a', 'b'), property_id="command-execution",
            candidate_id="c1",
            repository_id="r",
            entry_path=entry_doc.path,
            entry_line=entry_line,
            source_digest=repository_source_digest(index),
            analysis_scope="os.system command execution",
        )
        scope = ToolExecutionScope(
            candidate_path=entry_doc.path,
            admitted_paths=scope_paths,
            subject=subject,
            max_observation_tokens=10000,
        )
        obs = command_construction(index, CommandConstructionInput(source_path=entry_doc.path), scope)
        return subject, obs

    subject3, obs3 = observe(3)
    assert _command_status(obs3, subject3) == "SANITIZED"
    subject4, obs4 = observe(4)
    assert _command_status(obs4, subject4) == "UNSANITIZED"
    # Slice offset: span @10-14 with entry_line=12 maps to the same local line 3.
    subject_off = ValidationSubject(input_parameters=('a', 'b'), property_id="command-execution",
        candidate_id="c1",
        repository_id="r",
        entry_path="entry.py::entry@10-14",
        entry_line=12,
        source_digest=repository_source_digest(index),
        analysis_scope="os.system command execution",
    )
    assert _candidate_local_line(subject_off) == 3


def test_finalization_without_successful_observation_ends_as_runtime_abstain():
    """C5/C6 迁移（曾为“顽固 VULNERABLE 最终 RuntimeError”）.

    唯一 read_span 被作用域门禁 blocked，之后反复提交引用初始检索证据的
    VULNERABLE：实质判决不得在收尾被接受；统一顺序下每次提交都以结构化
    原因 no_successful_observation 被拒，最终一步转为明确标记的运行时
    ABSTAIN（记录原 proposed label 与预算终止），不伪装成模型自愿弃权。
    非法引用/身份漂移仍走错误路径（见负对照测试），不混入证据不足。
    """
    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): pass\n", defines=("entry",))
    index = RepositoryIndex([doc])
    tools = ToolRegistry(repository_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)

    def scope():
        return ToolExecutionScope(
            candidate_path="entry.py",
            admitted_paths=frozenset(["entry.py"]),
            initial_evidence_ids=frozenset({"local:entry"}),
            max_observation_tokens=8192,
        )

    conclusion = {
        "expert": "scan",
        "label": "VULNERABLE",
        "confidence": 0.8,
        "validation_status": "UNRESOLVED",
        "evidence_ids": ["local:entry"],
        "supporting_observation_ids": [],
        "counter_observation_ids": [],
        "unresolved_observation_ids": [],
        "rationale": "Cites retrieval evidence without any tool success.",
    }
    replies = [ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id="c0", name="read_span", arguments={"path": "secret.py"}),))]
    replies.extend(ModelReply(model_id="test", content=json.dumps(conclusion)) for _ in range(8))
    model = ScriptedChatModel(replies)
    engine = ReActEngine(model=model, tools=tools, scope=scope(), harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")
    vote = run_expert(engine, expert="scan", system_prompt="scan", task_prompt="inspect", allowed_tools=("read_span",))
    # Never accepted as material: the whole step budget is consumed by
    # structured rejections, then demoted on the final step.
    assert vote.label == "ABSTAIN"
    assert vote.confidence == 0.0
    assert vote.validation_status == ValidationStatus.UNRESOLVED
    assert "Runtime rejected proposed VULNERABLE" in vote.rationale
    assert "no_successful_observation" in vote.rationale
    assert "Finalization budget exhausted" in vote.rationale
    assert len(model.requests) == FULL_SYSTEM_HARNESS.react_loop.max_steps

    abstain = dict(conclusion, label="ABSTAIN", confidence=0.0, evidence_ids=[])
    model2 = ScriptedChatModel([
        ModelReply(model_id="test", tool_calls=(ModelToolCall(call_id="c0", name="read_span", arguments={"path": "secret.py"}),)),
        ModelReply(model_id="test", content=json.dumps(abstain)),
    ])
    engine2 = ReActEngine(model=model2, tools=tools, scope=scope(), harness=FULL_SYSTEM_HARNESS.react_loop, citation_prefix="scan/tool")
    vote2 = run_expert(engine2, expert="scan", system_prompt="scan", task_prompt="inspect", allowed_tools=("read_span",))
    assert vote2.label == "ABSTAIN"
    assert "Runtime rejected" not in vote2.rationale


def test_branch_join_merges_only_actual_successor_states():
    """[P2 反例] 分支汇合只能合并实际后继状态，不能复活已被覆盖的前驱值.

    所有正常路径都把 cmd 改写为常量命令，汇合却从执行前环境开始合并，
    把早已被覆盖的原始输入值重新引入为备选，输出无 issue 的 UNSANITIZED；
    HEAD 是 SANITIZED。只有确实存在“不执行赋值”的路径时才能加入原环境
    （C2）。其他信号分支的同类合并同样只用后继状态。
    """
    document = CodeDocument(
        repository_id="r",
        path="entry.py::entry@1-7",
        text=(
            "def entry(value, flag):\n"
            "    cmd = value\n"
            "    if flag:\n"
            "        a, b = (1, 2) if flag else (3, 4)\n"
            "        cmd = 'echo safe'\n"
            "    else:\n"
            "        cmd = 'echo safe'\n"
            "    import os\n"
            "    os.system(cmd)\n"
        ),
        defines=("entry",),
    )
    analysis = analyze_command(document)
    assert not analysis.issues, (analysis.issues, analysis.sinks)
    assert command_status(analysis) == "SANITIZED"


def test_unsanitized_command_inspection_still_supports_vulnerable():
    """正例对照：UNSANITIZED 命令检查被引用时 VULNERABLE 必须放行，不可因收紧门禁变绿变红."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="hp003_command_case",
        repository_id="r",
        entry_path="entry.py",
        entry_line=2,
        source_digest="d",
        analysis_scope="subprocess.Popen command execution",
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps({
            "command_construction_status": "UNSANITIZED",
            "source_path": "entry.py",
            "helpers": [],
            "sink_facts": [{"line": 2, "path": "entry.py", "status": "UNSANITIZED"}],
            "issues": [{"kind": "unsafe-path"}],
        }),
        citation_id="tool:cmd",
        evidence_ids=("command_construction:entry.py", "tool:cmd"),
        validation_status=ValidationStatus.UNRESOLVED,
        subject=subject,
    )
    steps = [
        ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs_cmd),
    ]
    vote = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["command_construction:entry.py"],
        supporting_observation_ids=["tool:cmd"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites unsanitized Popen sink with tainted value.",
    )
    validate_conclusion(vote, steps, frozenset(["tool:cmd"]), subject=subject)


def _sanitized_command_trace():
    """同一候选、同一 SANITIZED 执行路径：os.system('echo ' + shlex.quote(value))."""
    subject = ValidationSubject(property_id="command-execution",
        candidate_id="sanitized_command_case",
        repository_id="r",
        entry_path="entry.py",
        entry_line=3,
        source_digest="d",
        analysis_scope="os.system command execution",
    )
    obs_cmd = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps({
            "command_construction_status": "SANITIZED",
            "source_path": "entry.py",
            "helpers": [],
            "sink_facts": [{"call": "os.system", "line": 3, "path": "entry.py", "status": "SANITIZED"}],
            "issues": [],
        }),
        citation_id="tool:cmd",
        evidence_ids=("command_construction:entry.py", "tool:cmd"),
        validation_status=ValidationStatus.UNRESOLVED,
        subject=subject,
    )
    obs_read = ToolObservation(
        tool="read_span",
        status="ok",
        content=json.dumps({"path": "entry.py", "text": "os.system('echo ' + shlex.quote(value))"}),
        citation_id="tool:read",
        evidence_ids=("read:entry.py", "tool:read"),
        validation_status=ValidationStatus.UNRESOLVED,
        subject=subject,
    )
    steps = [
        ReActStep(step=1, model_id="m", tool_call=ModelToolCall(call_id="c1", name="inspect_command_construction", arguments={}), observation=obs_cmd),
        ReActStep(step=2, model_id="m", tool_call=ModelToolCall(call_id="c2", name="read_span", arguments={}), observation=obs_read),
    ]
    return subject, steps


def test_sanitized_inspection_cannot_be_bypassed_by_citation_choice():
    """同一 SANITIZED 路径：引用检查被拒，则只引用 read_span 或放入 counter 也必须被拒."""
    subject, steps = _sanitized_command_trace()
    vote_cite_cmd = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.7,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["command_construction:entry.py"],
        supporting_observation_ids=["tool:cmd"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites sanitized command inspection.",
    )
    with pytest.raises(ValueError, match="command-construction counter-evidence"):
        validate_conclusion(vote_cite_cmd, steps, frozenset(["tool:cmd"]), subject=subject)

    vote_read_only = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.7,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["read:entry.py"],
        supporting_observation_ids=["tool:read"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites only source read for sanitized sink.",
    )
    with pytest.raises(ValueError, match="command-construction counter-evidence"):
        validate_conclusion(vote_read_only, steps, frozenset(["tool:read"]), subject=subject)

    vote_counter = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.7,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["read:entry.py"],
        supporting_observation_ids=["tool:read"],
        counter_observation_ids=["tool:cmd"],
        unresolved_observation_ids=[],
        rationale="Puts sanitized inspection in counter role.",
    )
    with pytest.raises(ValueError, match="command-construction counter-evidence"):
        validate_conclusion(vote_counter, steps, frozenset(["tool:read"]), subject=subject)


def test_same_scope_conflicting_command_proofs_require_abstention():
    """C4/C5: 同范围整体安全证明与危险证明冲突，不能靠引用选择获准。"""
    subject, steps = _sanitized_command_trace()
    vote_safe = AgentExpertConclusion(
        expert="scan",
        label="SAFE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["command_construction:entry.py"],
        supporting_observation_ids=["tool:cmd"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites sanitized construction as counter-evidence.",
    )
    validate_conclusion(vote_safe, steps, frozenset(["tool:cmd"]), subject=subject)

    obs_vuln = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps({
            "command_construction_status": "UNSANITIZED",
            "source_path": "entry.py",
            "helpers": [],
            "sink_facts": [{"call": "os.system", "line": 3, "path": "entry.py", "status": "UNSANITIZED"}],
            "issues": [{"kind": "unsafe-path"}],
        }),
        citation_id="tool:vuln",
        evidence_ids=("command_construction:entry.py", "tool:vuln"),
        validation_status=ValidationStatus.UNRESOLVED,
        subject=subject,
    )
    steps_vuln = [
        *steps,
        ReActStep(step=3, model_id="m", tool_call=ModelToolCall(call_id="c3", name="inspect_command_construction", arguments={}), observation=obs_vuln),
    ]
    vote_vuln = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=["tool:vuln"],
        supporting_observation_ids=["tool:vuln"],
        counter_observation_ids=[],
        unresolved_observation_ids=[],
        rationale="Cites unsanitized sink with tainted value.",
    )
    # Keep the SANITIZED observation in the full trace while citing only the
    # distinct UNSANITIZED observation as support for the vulnerability vote.
    for conclusion in (vote_vuln, vote_safe):
        with pytest.raises(ValueError, match="conflicting command"):
            validate_conclusion(conclusion, steps_vuln, frozenset(), subject=subject)


def test_real_safe_and_unsafe_paths_are_not_conflicting_whole_scope_proofs():
    from test_review_followup import inspect_and_trace, vote

    data, steps, subject = inspect_and_trace(
        "def entry(value, flag):\n"
        "    if flag:\n        command = value\n"
        "    else:\n        command = 'echo ' + shlex.quote(value)\n"
        "    os.system(command)\n",
        "def build_cmd(value):\n    return value\n",
    )
    assert {item["status"] for item in data["sink_facts"]} == {"SANITIZED", "UNSANITIZED"}
    vote(steps, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        vote(steps, subject, "SAFE")


@pytest.mark.parametrize('identity', [('neutral', 'neutral.py'), ('command-candidate', 'command.py')])
@pytest.mark.parametrize('property_id', [None, 'dynamic-evaluation', 'chmod-mode-others-write', 'command-execution'])
@pytest.mark.parametrize('quoted', [False, True])
def test_command_proof_requires_the_declared_command_property(property_id, quoted, identity):
    from test_review_followup import vote

    value = "'echo ' + shlex.quote(value)" if quoted else 'value'
    doc = CodeDocument(repository_id='r', path=identity[1], text=f'def entry(value):\n    os.system({value})\n')
    index = RepositoryIndex([doc])
    subject = ValidationSubject(input_parameters=('value',), candidate_id=identity[0], repository_id='r', entry_path=doc.path,
                                source_digest=repository_source_digest(index), entry_line=1,
                                property_id=property_id)
    scope = ToolExecutionScope(candidate_path=doc.path, admitted_paths=frozenset({doc.path}),
                               subject=subject, max_observation_tokens=10000)
    observation = command_construction(index, CommandConstructionInput(source_path=doc.path), scope)
    assert json.loads(observation.content)['command_construction_status'] == ('SANITIZED' if quoted else 'UNSANITIZED')
    observation = observation.model_copy(update={'citation_id': 'command'})
    trace = [ReActStep(step=1, model_id='offline', observation=observation,
                      tool_call=ModelToolCall(call_id='command', name=observation.tool, arguments={}))]
    label = 'SAFE' if quoted else 'VULNERABLE'
    if property_id == 'command-execution':
        assert observation.subject == subject
        vote(trace, subject, label)
    else:
        with pytest.raises(ValueError):
            vote(trace, subject, label)
        assert observation.subject is None
        # Old observations that stamped the subject without a property check
        # must also be rejected by the consumer, independent of the producer.
        legacy = observation.model_copy(update={'subject': subject})
        with pytest.raises(ValueError):
            vote([trace[0].model_copy(update={'observation': legacy})], subject, label)


@pytest.mark.parametrize('inputs,quoted,expected', [
    (('value',), False, 'UNSANITIZED'),
    (('other',), False, 'AMBIGUOUS'),
    ((), False, 'AMBIGUOUS'),
    (('value',), True, 'SANITIZED'),
    (('other',), True, 'AMBIGUOUS'),
])
@pytest.mark.parametrize('via_helper', [False, True])
def test_command_source_declaration_controls_actual_entry_values(inputs, quoted, expected, via_helper):
    from test_review_followup import vote

    expression = "'echo ' + shlex.quote(value)" if quoted else 'value'
    caller = CodeDocument(repository_id='r', path='entry.py',
                          text='def entry(value, other):\n    ' + (
                              'os.system(build_cmd(value))\n' if via_helper else f'os.system({expression})\n'),
                          defines=('entry',), calls=('build_cmd',) if via_helper else ())
    helper = CodeDocument(repository_id='r', path='helper.py', defines=('build_cmd',),
                          text=f'def build_cmd(value):\n    return {expression}\n')
    index = RepositoryIndex([caller, helper])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=caller.path, entry_line=1,
                                property_id='command-execution', input_parameters=inputs,
                                source_digest=repository_source_digest(index))
    result = command_construction(index, CommandConstructionInput(source_path=caller.path), ToolExecutionScope(
        candidate_path=caller.path, admitted_paths=frozenset({caller.path, helper.path}),
        subject=subject, max_observation_tokens=10000,
    )).model_copy(update={'citation_id': 'cmd'})
    assert json.loads(result.content)['command_construction_status'] == expected
    trace = [ReActStep(step=1, model_id='offline', observation=result,
                      tool_call=ModelToolCall(call_id='cmd', name=result.tool, arguments={}))]
    if expected == 'AMBIGUOUS':
        for label in ('SAFE', 'VULNERABLE'):
            with pytest.raises(ValueError):
                vote(trace, subject, label)
    else:
        vote(trace, subject, 'SAFE' if expected == 'SANITIZED' else 'VULNERABLE')


@pytest.mark.parametrize('statement,inputs,booleans,expected', [
    ('value = other\n    os.system(value)', ('value',), {}, 'AMBIGUOUS'),
    ("value = 'echo safe'\n    os.system(value)", ('value',), {}, 'SANITIZED'),
    ("os.system('echo safe')", (), {}, 'SANITIZED'),
    ('if enabled:\n        os.system(value)', ('value',), {}, 'AMBIGUOUS'),
    ('if enabled:\n        os.system(value)', ('value',), {'enabled': True}, 'UNSANITIZED'),
    ('if enabled:\n        os.system(value)', ('value',), {'enabled': False}, 'NOT_ESTABLISHED'),
    ('os.system(value)', ('missing',), {}, 'AMBIGUOUS'),
])
def test_declared_sources_do_not_erase_unknown_effects_or_fixed_scenarios(statement, inputs, booleans, expected):
    from test_review_followup import vote

    doc = CodeDocument(repository_id='r', path='entry.py',
                       text='def entry(value, other, enabled):\n    ' + statement + '\n')
    index = RepositoryIndex([doc])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=doc.path, entry_line=1,
                                property_id='command-execution', input_parameters=inputs,
                                entry_boolean_arguments=booleans, source_digest=repository_source_digest(index))
    observation = command_construction(index, CommandConstructionInput(source_path=doc.path), ToolExecutionScope(
        candidate_path=doc.path, admitted_paths=frozenset({doc.path}), subject=subject, max_observation_tokens=10000,
    )).model_copy(update={'citation_id': 'cmd'})
    data = json.loads(observation.content)
    assert data['command_construction_status'] == expected
    if inputs == ('missing',):
        assert 'invalid declared entry input parameters' in data['issues']
    trace = [ReActStep(step=1, model_id='offline', observation=observation,
                      tool_call=ModelToolCall(call_id='cmd', name=observation.tool, arguments={}))]
    if expected in {'UNSANITIZED', 'SANITIZED'}:
        vote(trace, subject, 'SAFE' if expected == 'SANITIZED' else 'VULNERABLE')
    else:
        with pytest.raises(ValueError):
            vote(trace, subject, 'VULNERABLE')


@pytest.mark.parametrize('body', [
    "container[0] = 'bash'",
    "alias = container\n    alias[0] = 'bash'",
    'os.system = replacement',
    'global os\n    os = replacement',
])
@pytest.mark.parametrize('dangerous_first', [False, True])
def test_helper_effect_gaps_are_enforced_at_real_admission(body, dangerous_first):
    from test_review_followup import inspect_and_trace, vote
    first = '    os.system(value)\n' if dangerous_first else ''
    data, steps, subject = inspect_and_trace(
        'def entry(value):\n' + first + "    command = ['echo', value]\n"
        "    build_cmd(command)\n    os.system('echo ' + shlex.quote(value))\n",
        'def build_cmd(container):\n    ' + body + '\n',
    )
    subject = subject.model_copy(update={'entry_line': 1})
    assert data['issues']
    with pytest.raises(ValueError):
        vote(steps, subject, 'SAFE')
    if dangerous_first:
        vote(steps, subject, 'VULNERABLE')
    else:
        with pytest.raises(ValueError):
            vote(steps, subject, 'VULNERABLE')


@pytest.mark.parametrize('assignment,expected', [
    ('a, b = (0, value)', 'VULNERABLE'),
    ('a, b = (0,)', None),
    ('try:\n        a, b = (0,)\n    except ValueError:\n        b = value', None),
    ('a, b = (0, value) if flag else (0,)', 'VULNERABLE'),
    ('a, b = (0, value) if flag else missing', 'VULNERABLE'),
    ('a, (c, b) = (0, (1, value)) if flag else (0, (1, "echo ok"))', 'VULNERABLE'),
    ('a, b = (0, "echo ok")', 'SAFE'),
])
def test_unpack_coverage_reaches_candidate_admission(assignment, expected):
    from test_review_followup import inspect_and_trace, vote
    data, steps, subject = inspect_and_trace(
        'def entry(value, flag):\n    ' + assignment + '\n    os.system(b)\n',
        'def build_cmd(value):\n    return value\n',
    )
    subject = subject.model_copy(update={'entry_line': 1})
    if expected is None:
        assert data['issues']
        assert not data['sink_facts']
    for label in ('SAFE', 'VULNERABLE'):
        if label == expected:
            vote(steps, subject, label)
        else:
            with pytest.raises(ValueError):
                vote(steps, subject, label)


@pytest.mark.parametrize('call,expected', [
    ("os.system('echo ' + shlex.quote(value))", 'SAFE'),
    ("os.system('echo ' + shlex.quote(value) + other)", 'VULNERABLE'),
    ('os.system(f\'bash -c "echo {shlex.quote(value)}"\')', None),
    # NOT_ESTABLISHED alone is not an affirmative proof (C4).
    ("subprocess.run(['echo', value])", None),
    ("subprocess.run(['python', '-c', str(int(value))])", 'SAFE'),
])
def test_shell_consumption_context_is_enforced_at_real_admission(call, expected):
    from test_review_followup import inspect_and_trace, vote
    _, steps, subject = inspect_and_trace(
        'def entry(value, other):\n    ' + call + '\n',
        'def build_cmd(value):\n    return value\n',
    )
    subject = subject.model_copy(update={'entry_line': 1})
    for label in ('SAFE', 'VULNERABLE'):
        if label == expected:
            vote(steps, subject, label)
        else:
            with pytest.raises(ValueError):
                vote(steps, subject, label)


@pytest.mark.parametrize('windows', [None, False, True])
@pytest.mark.parametrize('rebind', [False, True])
def test_platform_wrapping_requires_declared_scenario_and_tracks_rebinding(windows, rebind):
    from test_review_followup import vote
    source = ('def entry(value, windows):\n'
              "    command = 'echo ' + shlex.quote(value)\n"
              "    if not windows:\n        command = 'exec ' + command\n"
              + ('    windows = not windows\n' if rebind else '')
              + "    if not windows:\n        command = ['bash', '-c', command]\n"
              '    subprocess.Popen(command)\n')
    document = CodeDocument(repository_id='r', path='entry.py', text=source)
    index = RepositoryIndex([document])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=document.path,
        entry_line=1, source_digest=repository_source_digest(index), property_id='command-execution',
        input_parameters=('value',), entry_boolean_arguments={} if windows is None else {'windows': windows})
    result = command_construction(index, CommandConstructionInput(source_path=document.path), ToolExecutionScope(
        candidate_path=document.path, admitted_paths=frozenset({document.path}), subject=subject,
        max_observation_tokens=10000)).model_copy(update={'citation_id': 'cmd'})
    trace = [ReActStep(step=1, model_id='offline', observation=result,
                      tool_call=ModelToolCall(call_id='cmd', name=result.tool, arguments={}))]
    safe = windows is not None and (not windows if not rebind else windows)
    if safe:
        vote(trace, subject, 'SAFE')
    else:
        with pytest.raises(ValueError):
            vote(trace, subject, 'SAFE')
    with pytest.raises(ValueError):
        vote(trace, subject, 'VULNERABLE')


@pytest.mark.parametrize('call', [
    "os.system('echo ' + shlex.quote(value))",
    "subprocess.Popen(value, shell=flag)",
])
@pytest.mark.parametrize('role', ['supporting', 'counter', 'omitted'])
@pytest.mark.parametrize('keep_static', [False, True])
def test_real_command_adverse_evidence_survives_citation_and_scan_choices(call, role, keep_static):
    from test_review_followup import inspect_and_trace
    _, trace, subject = inspect_and_trace(
        'def entry(value, flag):\n    ' + call + '\n', 'def build_cmd(value):\n    return value\n',
        input_parameters=('value',))
    if not keep_static:
        trace = [step for step in trace if step.observation.tool != 'run_static_check']
    # The initial snippet is deliberately available as a citation, but cannot
    # erase a delivered candidate-bound observation by replacing its reference.
    ids = ('tool:cmd',) if role != 'omitted' else ('source-snippet',)
    proposal = AgentExpertConclusion(expert='scan', label='VULNERABLE', confidence=.9,
        validation_status='UNRESOLVED', evidence_ids=ids,
        supporting_observation_ids=('tool:cmd',) if role == 'supporting' else (),
        counter_observation_ids=('tool:cmd',) if role == 'counter' else (),
        rationale='Adverse evidence cannot be hidden by citation roles.')
    for ordered in (trace, list(reversed(trace))):
        with pytest.raises(ValueError):
            validate_conclusion(proposal, ordered, frozenset({'source-snippet'}), subject=subject)


@pytest.mark.parametrize('quoted', [False, True])
def test_command_hop_budget_reaches_nested_helper_without_crossing_scope(quoted):
    entry = CodeDocument(repository_id='r', path='entry.py', language='python',
        text='def entry(value):\n    import os\n    os.system(wrapper(value))\n',
        defines=('entry',), calls=('wrapper', 'os.system'))
    wrapper = CodeDocument(repository_id='r', path='wrapper.py', language='python',
        text='def wrapper(value):\n    return build(value)\n',
        defines=('wrapper',), calls=('build',))
    leaf = CodeDocument(repository_id='r', path='leaf.py', language='python',
        text='def build(value):\n    import shlex\n    return "echo " + '
             + ('shlex.quote(value)' if quoted else 'value') + '\n',
        defines=('build',), calls=('shlex.quote',) if quoted else ())
    index = RepositoryIndex([entry, wrapper, leaf])
    def inspect(hops, paths):
        scope = ToolExecutionScope(admitted_paths=frozenset(paths),
            max_observation_tokens=100000, candidate_path=entry.path)
        return json.loads(command_construction(index,
            CommandConstructionInput(source_path=entry.path, max_hops=hops), scope).content)
    for hops in (0, 1):
        limited = inspect(hops, index.documents)
        assert limited['sink_facts'] == []
        assert limited['command_construction_status'] in {'UNAVAILABLE', 'AMBIGUOUS'}
    complete = inspect(2, index.documents)
    assert complete['command_construction_status'] == ('SANITIZED' if quoted else 'UNSANITIZED')
    assert len(complete['sink_facts']) == 1
    restricted = inspect(4, [entry.path, wrapper.path])
    assert restricted['sink_facts'] == []
    assert restricted['command_construction_status'] == 'AMBIGUOUS'


def test_command_diagnostics_follow_interpreted_calls_not_dead_graph_neighbors():
    helpers = [CodeDocument(repository_id='r', path=f'h{i}.py', language='python',
        defines=(f'h{i}',), text=f'def h{i}(value):\n    return opaque(value)\n')
        for i in range(25)]
    entry = CodeDocument(repository_id='r', path='entry.py', language='python',
        text='def entry(value):\n    import os\n    if False:\n'
             + ''.join(f'        h{i}(value)\n' for i in range(25))
             + '    os.system(value)\n', calls=tuple(f'h{i}' for i in range(25)))
    index = RepositoryIndex([entry, *helpers])
    scope = ToolExecutionScope(admitted_paths=frozenset(index.documents),
        max_observation_tokens=8192, candidate_path=entry.path)
    observation = command_construction(index, CommandConstructionInput(source_path=entry.path), scope)
    result = json.loads(observation.content)
    assert result['command_construction_status'] == 'UNSANITIZED'
    assert len(result['sink_facts']) == 1
    assert result['helpers'] == []
    assert result['unresolved_edges'] == []
    assert len(observation.content.encode()) < 4096


def test_configured_hp003_real_pair_command_evidence_keeps_whole_function_gap():
    from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
    from cv_agent.evaluation.datasets.advisory_tasks import build_task_plan
    from cv_agent.evaluation.datasets.composition import load_advisory_config

    root = Path(__file__).resolve().parents[1]
    config = load_advisory_config(root, "configs/profiles/advisory_matrix_v4.json")
    data = config.model_dump(mode="json", by_alias=True)
    data["selected_cells"] = [
        {"case_id": "hp003_a", "system": "E3"},
        {"case_id": "hp003_b", "system": "E3"},
    ]
    data["expected_abstentions"] = []
    config = PythonHeldoutPairExperimentConfig.model_validate(data)
    for pair in config.pairs:
        for case in pair.cases:
            if case.case_id in {"hp003_a", "hp003_b"} and not (root / case.checkout).exists():
                pytest.skip("hp003 real checkouts are not available")

    tasks, subjects, _, _ = build_task_plan(root, config)
    proposed_labels = {"hp003_a": "VULNERABLE", "hp003_b": "SAFE"}
    for _, _, index, candidate, _, _ in tasks:
        label = proposed_labels[candidate.case_id]
        subject = subjects[candidate.case_id]
        observation = command_construction(
            index,
            CommandConstructionInput(source_path=candidate.path, max_hops=4),
            ToolExecutionScope(
                candidate_path=candidate.path,
                admitted_paths=frozenset(index.documents),
                subject=subject,
                max_observation_tokens=100000,
            ),
        ).model_copy(update={"citation_id": f"{candidate.case_id}:cmd"})
        content = json.loads(observation.content)
        # C3/A3: resolving the lexical os.path operations only advances the
        # actual call chain. The remaining unresolved effects still prevent
        # either original whole-function candidate from claiming V/S.
        assert content["command_construction_status"] == "AMBIGUOUS"
        assert content["issues"]
        step = ReActStep(
            step=1,
            model_id="offline",
            tool_call=ModelToolCall(
                call_id=f"{candidate.case_id}:cmd",
                name="inspect_command_construction",
                arguments={"source_path": candidate.path},
            ),
            observation=observation,
        )
        ids = frozenset({observation.citation_id})
        with pytest.raises(ValueError):
            validate_conclusion(
                AgentExpertConclusion(
                    expert="scan",
                    label=label,
                    confidence=0.8,
                    validation_status="UNRESOLVED",
                    evidence_ids=(observation.citation_id,),
                    supporting_observation_ids=(observation.citation_id,),
                    rationale="The historical proposal claims the configured hp003 label.",
                ),
                [step],
                ids,
                subject=subject,
            )


def test_nested_command_gap_preserves_actual_callee_location():
    caller = CodeDocument(repository_id='r', path='caller.py', language='python',
        text='def entry(value):\n    import os\n    os.system(wrapper(value))\n',
        calls=('wrapper',), defines=('entry',))
    helper = CodeDocument(repository_id='r', path='helper.py', language='python',
        text='def wrapper(value):\n    return transform(value)\n',
        calls=('transform',), defines=('wrapper',))
    leaf = CodeDocument(repository_id='r', path='leaf.py', language='python',
        text='def transform(value):\n    return value\n', defines=('transform',))
    index = RepositoryIndex([caller, helper, leaf])
    for paths, expected in [(tuple(index.documents), 'available_definition_not_expanded'),
                            ((caller.path, helper.path), 'definition_not_admitted')]:
        scope = ToolExecutionScope(admitted_paths=frozenset(paths),
            max_observation_tokens=8192, candidate_path=caller.path)
        result = json.loads(command_construction(index,
            CommandConstructionInput(source_path=caller.path, max_hops=1), scope).content)
        assert result['analysis_gaps'] == [{
            'kind': expected, 'call': 'transform', 'source_path': 'helper.py', 'line': 2,
        }]
        assert result['sink_facts'] == []
        assert result['command_construction_status'] == 'AMBIGUOUS'
