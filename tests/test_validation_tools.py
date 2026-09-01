import json
import os
import signal
import socket
import time

import pytest

from cv_agent.agent_tools import ToolExecutionScope, ToolRegistry
from cv_agent.agent_types import ModelToolCall
from cv_agent.agentic_workflow import AgenticPipeline
from cv_agent.harness import (
    FULL_SYSTEM_HARNESS,
    AgentRuntimeMode,
    AgentSystemVersion,
)
from cv_agent.model_runtime import OpenAICompatibleChatModel
from cv_agent.retrieval import RepositoryIndex
from cv_agent.synthetic import cross_file_fixture, guarded_delete_fixture
from cv_agent.types import CodeDocument
from cv_agent.validation_tools import (
    FixtureCase,
    FixtureOutcome,
    LoopbackCase,
    LoopbackRequest,
    LoopbackResponse,
    ValidationStatus,
    full_agent_tools,
)


SOCKET_ALIAS = socket.socket


def _scope(*paths: str) -> ToolExecutionScope:
    return ToolExecutionScope(
        admitted_paths=frozenset(paths),
        max_observation_tokens=(
            FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
        ),
    )


def _registry(index: RepositoryIndex, **kwargs) -> ToolRegistry:
    return ToolRegistry(
        full_agent_tools(index, **kwargs),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )


def _invoke(
    registry: ToolRegistry,
    name: str,
    arguments: dict[str, object],
    scope: ToolExecutionScope,
):
    return registry.invoke(
        ModelToolCall(
            call_id=f"{name}-call",
            name=name,
            arguments=arguments,
        ),
        allowed=(name,),
        scope=scope,
    )


def _confirmed_fixture() -> FixtureOutcome:
    return FixtureOutcome(
        status=ValidationStatus.CONFIRMED,
        summary="the project-owned exploit fixture reproduced the behavior",
        details={"exit_code": 0},
    )


def _network_probe_fixture() -> FixtureOutcome:
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=0.1)
    except OSError as error:
        return FixtureOutcome(
            status=ValidationStatus.REFUTED,
            summary="fixture network access was blocked",
            details={"error": str(error)},
        )
    return FixtureOutcome(
        status=ValidationStatus.CONFIRMED,
        summary="fixture unexpectedly opened a network connection",
    )


def _socket_alias_fixture() -> FixtureOutcome:
    try:
        handle = SOCKET_ALIAS(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as error:
        return FixtureOutcome(
            status=ValidationStatus.REFUTED,
            summary="pre-imported socket alias was blocked by seccomp",
            details={"error": str(error)},
        )
    handle.close()
    return FixtureOutcome(
        status=ValidationStatus.CONFIRMED,
        summary="pre-imported socket alias bypassed fixture isolation",
    )


def _slow_fixture() -> FixtureOutcome:
    time.sleep(1)
    return _confirmed_fixture()


def _large_fixture() -> FixtureOutcome:
    return FixtureOutcome(
        status=ValidationStatus.CONFIRMED,
        summary="large result crossed the result pipe",
        details={"blob": "x" * 300_000},
    )


def _sigterm_resistant_fixture() -> FixtureOutcome:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(30)
    return _confirmed_fixture()


def _exit_without_result_fixture() -> FixtureOutcome:
    os._exit(0)


def _vulnerable_application(request: LoopbackRequest) -> LoopbackResponse:
    del request
    return LoopbackResponse(status=200, body=b"deleted")


def _guarded_application(request: LoopbackRequest) -> LoopbackResponse:
    if request.headers.get("Authorization"):
        return LoopbackResponse(status=200, body=b"deleted")
    return LoopbackResponse(status=403, body=b"forbidden")


def test_full_registry_implements_every_harness_tool():
    index, _ = cross_file_fixture()
    registry = _registry(index)
    required = set(FULL_SYSTEM_HARNESS.validation.validators)
    for expert in FULL_SYSTEM_HARNESS.experts:
        required.update(expert.tools)
    required.update({"search_symbols", "read_span", "get_callers", "get_callees"})

    assert required <= set(registry.names)


def test_full_registry_satisfies_live_pipeline_construction_without_network_call():
    index, _ = cross_file_fixture()
    registry = _registry(index)
    live = OpenAICompatibleChatModel(
        base_url="http://127.0.0.1:1/v1",
        model="construction-only",
        api_key=None,
        temperature=0.0,
        timeout_seconds=1,
    )
    models = {role: live for role in ("planner", "scan", "taint", "authz")}

    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E5_GRAPH_FAST,
        models=models,
        tools=registry,
    )

    assert pipeline.runtime_mode == AgentRuntimeMode.LIVE


def test_static_source_sink_and_cross_file_taint_tools_confirm_fixture():
    index, _ = cross_file_fixture()
    registry = _registry(index)
    paths = ("controller.py", "service.py")

    sources = _invoke(
        registry,
        "find_sources",
        {"path": "controller.py"},
        _scope(*paths),
    )
    sinks = _invoke(
        registry,
        "find_sinks",
        {"path": "service.py"},
        _scope(*paths),
    )
    static = _invoke(
        registry,
        "run_static_check",
        {"path": "service.py"},
        _scope(*paths),
    )
    trace = _invoke(
        registry,
        "trace_dataflow",
        {
            "source_path": "controller.py",
            "sink_path": "service.py",
            "max_hops": 4,
        },
        _scope(*paths),
    )

    assert json.loads(sources.content)["finding_count"] == 1
    assert json.loads(sinks.content)["findings"][0]["category"] == (
        "command-execution"
    )
    assert json.loads(static.content)["finding_count"] == 1
    trace_payload = json.loads(trace.content)
    assert trace_payload["status"] == "CONFIRMED"
    assert [step["path"] for step in trace_payload["trace"]] == [
        "controller.py",
        "service.py",
    ]


def test_java_servlet_sources_and_sinks_are_detected():
    document = CodeDocument(
        repository_id="repo",
        path="BenchmarkTest00043.java::BenchmarkTest00043.doPost@1",
        text=(
            "public void doPost(HttpServletRequest request) throws Exception {\n"
            "    java.util.Map<String,String[]> map = request.getParameterMap();\n"
            '    String param = scr.getTheParameter("vector");\n'
            "    String sql = \"SELECT * FROM users WHERE name='\" + param + \"'\";\n"
            "    statement.executeUpdate(sql);\n"
            "}\n"
        ),
        language="java",
        defines=("BenchmarkTest00043.doPost",),
    )
    registry = _registry(RepositoryIndex([document]))
    scope = _scope(document.path)

    sources = _invoke(registry, "find_sources", {"path": document.path}, scope)
    sinks = _invoke(registry, "find_sinks", {"path": document.path}, scope)
    trace = _invoke(
        registry,
        "trace_dataflow",
        {"source_path": document.path, "sink_path": document.path},
        scope,
    )

    assert json.loads(sources.content)["finding_count"] == 2
    assert json.loads(sinks.content)["findings"][0]["category"] == "sql"
    assert json.loads(trace.content)["status"] == "CONFIRMED"


def test_java_taint_trace_propagates_through_typed_method_parameter():
    source = CodeDocument(
        repository_id="repo",
        path="Controller.java::Controller.doGet@1",
        text=(
            "public void doGet(HttpServletRequest request) throws Exception {\n"
            '    String value = request.getHeader("vector");\n'
            "    Service.run(value);\n"
            "}\n"
        ),
        language="java",
        defines=("Controller.doGet",),
        calls=("Service.run",),
    )
    service = CodeDocument(
        repository_id="repo",
        path="Service.java::Service.run@1",
        text=(
            "public static void run(String value) throws Exception {\n"
            "    Runtime.getRuntime().exec(value);\n"
            "}\n"
        ),
        language="java",
        defines=("Service.run",),
    )
    index = RepositoryIndex([source, service])

    trace = _invoke(
        _registry(index),
        "trace_dataflow",
        {
            "source_path": source.path,
            "sink_path": service.path,
            "max_hops": 4,
        },
        _scope(source.path, service.path),
    )
    payload = json.loads(trace.content)

    assert payload["status"] == "CONFIRMED"
    assert [step["path"] for step in payload["trace"]] == [source.path, service.path]


def test_sanitizer_prevents_false_taint_confirmation():
    document = CodeDocument(
        repository_id="repo",
        path="safe.py",
        text=(
            "def run(request):\n"
            "    command = request.args['cmd']\n"
            "    safe = shlex.quote(command)\n"
            "    return subprocess.run(safe, shell=True)\n"
        ),
        defines=("run",),
    )
    index = RepositoryIndex([document])
    registry = _registry(index)

    trace = _invoke(
        registry,
        "trace_dataflow",
        {"source_path": "safe.py", "sink_path": "safe.py"},
        _scope("safe.py"),
    )
    sanitizers = _invoke(
        registry,
        "find_sanitizers",
        {"path": "safe.py"},
        _scope("safe.py"),
    )

    assert json.loads(trace.content)["status"] == "UNRESOLVED"
    assert json.loads(sanitizers.content)["finding_count"] == 1


def test_validation_tools_cannot_read_paths_outside_retrieval_scope():
    index, _ = cross_file_fixture()
    registry = _registry(index)

    observation = _invoke(
        registry,
        "run_static_check",
        {"path": "service.py"},
        _scope("controller.py"),
    )

    assert observation.status == "blocked"


def test_trace_dataflow_blocks_unadmitted_sink_even_when_source_is_admitted():
    index, _ = cross_file_fixture()

    trace = _invoke(
        _registry(index),
        "trace_dataflow",
        {
            "source_path": "controller.py",
            "sink_path": "service.py",
            "max_hops": 4,
        },
        _scope("controller.py"),
    )

    assert trace.status == "blocked"


def test_every_repository_analysis_tool_respects_scope_and_typed_inputs():
    index, _ = cross_file_fixture()
    registry = _registry(index)
    scope = _scope("controller.py")
    path_tools = (
        "run_static_check",
        "find_sources",
        "find_sinks",
        "find_sanitizers",
        "compare_vulnerable_and_fixed",
        "get_routes",
        "get_guards",
        "inspect_principal",
        "inspect_resource_scope",
    )

    for name in path_tools:
        blocked = _invoke(
            registry,
            name,
            {"path": "service.py"},
            _scope("controller.py"),
        )
        assert blocked.status == "blocked", name

    blocked_trace = _invoke(
        registry,
        "trace_dataflow",
        {"source_path": "service.py", "max_hops": 4},
        _scope("controller.py"),
    )
    blocked_guard = _invoke(
        registry,
        "compare_route_and_service_guard",
        {"route_path": "service.py", "max_hops": 4},
        _scope("controller.py"),
    )
    references = _invoke(
        registry,
        "find_references",
        {"symbol": "subprocess"},
        scope,
    )
    invalid = _invoke(
        registry,
        "trace_dataflow",
        {"source_path": "controller.py", "max_hops": 99},
        _scope("controller.py"),
    )

    assert blocked_trace.status == "blocked"
    assert blocked_guard.status == "blocked"
    assert json.loads(references.content)["references"] == []
    assert invalid.status == "error"


def test_non_edge_documents_do_not_form_a_cross_file_taint_trace():
    source = CodeDocument(
        repository_id="repo",
        path="source.py",
        text=(
            "def entry(request):\n"
            "    command = request.args['cmd']\n"
            "    return harmless(command)\n"
        ),
        defines=("entry",),
        calls=("harmless",),
    )
    sink = CodeDocument(
        repository_id="repo",
        path="sink.py",
        text="def dangerous(command):\n    return eval(command)\n",
        defines=("dangerous",),
    )
    index = RepositoryIndex([source, sink])

    trace = _invoke(
        _registry(index),
        "trace_dataflow",
        {
            "source_path": "source.py",
            "sink_path": "sink.py",
            "max_hops": 4,
        },
        _scope("source.py", "sink.py"),
    )

    assert json.loads(trace.content)["status"] == "UNRESOLVED"


def test_authorization_tools_model_principal_resource_and_guard_coverage():
    route = CodeDocument(
        repository_id="repo",
        path="route.py",
        text=(
            "def remove_user(req):\n"
            "    actor = req.user\n"
            "    return delete_user(req.params.user_id)\n"
        ),
        defines=("remove_user",),
        calls=("delete_user",),
        routes=("DELETE:/users/:user_id",),
    )
    service = CodeDocument(
        repository_id="repo",
        path="service.py",
        text="def delete_user(user_id):\n    return database.delete(user_id)\n",
        defines=("delete_user",),
    )
    index = RepositoryIndex([route, service])
    registry = _registry(index)
    scope_paths = ("route.py", "service.py")

    principal = _invoke(
        registry,
        "inspect_principal",
        {"path": "route.py"},
        _scope(*scope_paths),
    )
    resource = _invoke(
        registry,
        "inspect_resource_scope",
        {"path": "route.py"},
        _scope(*scope_paths),
    )
    routes = _invoke(
        registry,
        "get_routes",
        {"path": "route.py"},
        _scope(*scope_paths),
    )
    comparison = _invoke(
        registry,
        "compare_route_and_service_guard",
        {"route_path": "route.py", "max_hops": 4},
        _scope(*scope_paths),
    )

    assert json.loads(principal.content)["principals"]
    assert json.loads(resource.content)["resources"]
    assert json.loads(routes.content)["routes"] == ["DELETE:/users/:user_id"]
    assert json.loads(comparison.content)["status"] == "CONFIRMED"

    guarded_index, _ = guarded_delete_fixture()
    guard_evidence = _invoke(
        _registry(guarded_index),
        "get_guards",
        {"path": "admin.py"},
        _scope("admin.py"),
    )
    guarded = _invoke(
        _registry(guarded_index),
        "compare_route_and_service_guard",
        {"route_path": "admin.py", "max_hops": 1},
        _scope("admin.py"),
    )
    assert "require_permission" in json.loads(guard_evidence.content)["guards"]
    assert json.loads(guarded.content)["status"] == "UNRESOLVED"

    late_guard = CodeDocument(
        repository_id="repo",
        path="late.py",
        text=(
            "def delete_user(actor, user_id):\n"
            "    result = database.delete(user_id)\n"
            "    require_permission(actor, 'delete_user')\n"
            "    return result\n"
        ),
        defines=("delete_user",),
    )
    late = _invoke(
        _registry(RepositoryIndex([late_guard])),
        "compare_route_and_service_guard",
        {"route_path": "late.py", "max_hops": 1},
        _scope("late.py"),
    )
    assert json.loads(late.content)["status"] == "CONFIRMED"


def test_guard_on_sibling_branch_cannot_dominate_sensitive_path():
    root = CodeDocument(
        repository_id="repo",
        path="root.py",
        text=(
            "def route(req):\n"
            "    guarded_branch(req)\n"
            "    return open_branch(req)\n"
        ),
        defines=("route",),
        calls=("guarded_branch", "open_branch"),
    )
    guarded = CodeDocument(
        repository_id="repo",
        path="guarded.py",
        text=(
            "def guarded_branch(req):\n"
            "    authorize(req.user)\n"
            "    return audit(req)\n"
        ),
        defines=("guarded_branch",),
        calls=("audit",),
    )
    open_branch = CodeDocument(
        repository_id="repo",
        path="open.py",
        text="def open_branch(req):\n    return perform(req.params.id)\n",
        defines=("open_branch",),
        calls=("perform",),
    )
    sensitive = CodeDocument(
        repository_id="repo",
        path="sensitive.py",
        text="def perform(record_id):\n    return database.remove(record_id)\n",
        defines=("perform",),
    )
    index = RepositoryIndex([root, guarded, open_branch, sensitive])

    result = _invoke(
        _registry(index),
        "compare_route_and_service_guard",
        {"route_path": "root.py", "max_hops": 4},
        _scope("root.py", "guarded.py", "open.py", "sensitive.py"),
    )

    assert json.loads(result.content)["status"] == "CONFIRMED"


def test_structured_only_guard_without_line_position_does_not_prove_authorization():
    document = CodeDocument(
        repository_id="repo",
        path="structured.py",
        text=(
            "def delete_user(req):\n"
            "    return database.delete(req.params.user_id)\n"
        ),
        defines=("delete_user",),
        guards=("require_permission",),
    )

    result = _invoke(
        _registry(RepositoryIndex([document])),
        "compare_route_and_service_guard",
        {"route_path": "structured.py", "max_hops": 1},
        _scope("structured.py"),
    )
    payload = json.loads(result.content)

    assert payload["records"][0]["guards"] == ["require_permission"]
    assert payload["records"][0]["guard_lines"] == []
    assert payload["status"] == "CONFIRMED"


def test_unlocatable_edge_call_does_not_let_upstream_guard_dominate():
    route = CodeDocument(
        repository_id="repo",
        path="route.py",
        text=(
            "def route(req):\n"
            "    authorize(req.user)\n"
            "    handler = service_entry\n"
            "    return handler\n"
        ),
        defines=("route",),
        calls=("service_entry",),
    )
    service = CodeDocument(
        repository_id="repo",
        path="service.py",
        text="def service_entry(user_id):\n    return database.delete(user_id)\n",
        defines=("service_entry",),
    )

    result = _invoke(
        _registry(RepositoryIndex([route, service])),
        "compare_route_and_service_guard",
        {"route_path": "route.py", "max_hops": 2},
        _scope("route.py", "service.py"),
    )

    assert json.loads(result.content)["status"] == "CONFIRMED"


def test_verified_fixed_pair_comparison_is_registered_not_model_selected():
    vulnerable = CodeDocument(
        repository_id="repo",
        path="vulnerable.py",
        text="def run(value):\n    return eval(value)\n",
        defines=("run",),
    )
    fixed = CodeDocument(
        repository_id="repo",
        path="fixed.py",
        text="def run(value):\n    return parse_literal(value)\n",
        defines=("run",),
    )
    vulnerable_index = RepositoryIndex([vulnerable])
    fixed_index = RepositoryIndex([fixed])
    registry = _registry(
        vulnerable_index,
        fixed_index=fixed_index,
        paired_paths={"vulnerable.py": "fixed.py"},
    )

    comparison = _invoke(
        registry,
        "compare_vulnerable_and_fixed",
        {"path": "vulnerable.py"},
        _scope("vulnerable.py"),
    )
    payload = json.loads(comparison.content)

    assert payload["status"] == "CONFIRMED"
    assert payload["vulnerable_sink_count"] == 1
    assert payload["fixed_sink_count"] == 0

    missing_pair = _invoke(
        _registry(vulnerable_index),
        "compare_vulnerable_and_fixed",
        {"path": "vulnerable.py"},
        _scope("vulnerable.py"),
    )
    assert json.loads(missing_pair.content)["status"] == "UNRESOLVED"


def test_fixed_pair_pre_sink_guard_with_retained_sink_supports_fix():
    vulnerable = CodeDocument(
        repository_id="repo",
        path="vulnerable.py",
        text="def run(value):\n    return eval(value)\n",
        defines=("run",),
    )
    fixed = CodeDocument(
        repository_id="repo",
        path="fixed.py",
        text=(
            "def run(value):\n"
            "    authorize(value)\n"
            "    return eval(value)\n"
        ),
        defines=("run",),
    )

    comparison = _invoke(
        _registry(
            RepositoryIndex([vulnerable]),
            fixed_index=RepositoryIndex([fixed]),
            paired_paths={"vulnerable.py": "fixed.py"},
        ),
        "compare_vulnerable_and_fixed",
        {"path": "vulnerable.py"},
        _scope("vulnerable.py"),
    )
    payload = json.loads(comparison.content)

    assert payload["status"] == "CONFIRMED"
    assert payload["fixed_sink_count"] == 1
    assert payload["fixed_guard_precedes_sinks"] is True


def test_fixed_pair_late_unrelated_guard_does_not_confirm_fix():
    vulnerable = CodeDocument(
        repository_id="repo",
        path="vulnerable.py",
        text="def run(value):\n    return eval(value)\n",
        defines=("run",),
    )
    fixed = CodeDocument(
        repository_id="repo",
        path="fixed.py",
        text=(
            "def run(value):\n"
            "    result = eval(value)\n"
            "    authorize(value)\n"
            "    return result\n"
        ),
        defines=("run",),
    )
    vulnerable_index = RepositoryIndex([vulnerable])
    fixed_index = RepositoryIndex([fixed])

    comparison = _invoke(
        _registry(
            vulnerable_index,
            fixed_index=fixed_index,
            paired_paths={"vulnerable.py": "fixed.py"},
        ),
        "compare_vulnerable_and_fixed",
        {"path": "vulnerable.py"},
        _scope("vulnerable.py"),
    )
    payload = json.loads(comparison.content)

    assert payload["status"] == "UNRESOLVED"
    assert payload["fixed_guard_precedes_sinks"] is False


def test_fixture_runner_is_registered_bounded_and_network_disabled():
    index, _ = cross_file_fixture()
    registry = _registry(
        index,
        fixture_cases=(
            FixtureCase(case_id="confirmed", runner=_confirmed_fixture),
            FixtureCase(case_id="network", runner=_network_probe_fixture),
            FixtureCase(case_id="alias", runner=_socket_alias_fixture),
            FixtureCase(
                case_id="timeout",
                runner=_slow_fixture,
                timeout_seconds=0.2,
            ),
            FixtureCase(case_id="large", runner=_large_fixture),
        ),
    )

    confirmed = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "confirmed"},
        _scope(),
    )
    network = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "network"},
        _scope(),
    )
    alias = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "alias"},
        _scope(),
    )
    timeout = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "timeout"},
        _scope(),
    )
    large = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "large"},
        _scope(),
    )

    assert json.loads(confirmed.content)["status"] == "CONFIRMED"
    assert json.loads(network.content)["status"] == "REFUTED"
    assert json.loads(alias.content)["status"] == "REFUTED"
    assert json.loads(timeout.content)["status"] == "UNRESOLVED"
    assert json.loads(large.content)["details"]["blob"] == "x" * 300_000

    unknown = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "not-registered"},
        _scope(),
    )
    assert unknown.status == "error"


def test_fixture_runner_kills_ignored_sigterm_and_cleans_eof():
    index, _ = cross_file_fixture()
    registry = _registry(
        index,
        fixture_cases=(
            FixtureCase(
                case_id="ignore-term",
                runner=_sigterm_resistant_fixture,
                timeout_seconds=0.2,
            ),
            FixtureCase(case_id="no-result", runner=_exit_without_result_fixture),
        ),
    )

    previous_sigterm = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        started = time.monotonic()
        timeout = _invoke(
            registry,
            "run_fixture_test",
            {"case_id": "ignore-term"},
            _scope(),
        )
        elapsed = time.monotonic() - started
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
    eof = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "no-result"},
        _scope(),
    )

    assert elapsed < 5
    assert json.loads(timeout.content)["status"] == "UNRESOLVED"
    assert "timeout" in json.loads(timeout.content)["summary"]
    assert json.loads(eof.content)["status"] == "UNRESOLVED"
    assert "without a result" in json.loads(eof.content)["summary"]


def test_fixture_runner_reports_resource_limit_setup_failure(monkeypatch):
    import resource

    index, _ = cross_file_fixture()
    original_setrlimit = resource.setrlimit

    def fail_cpu_limit(limit, values):
        if limit == resource.RLIMIT_CPU:
            raise OSError("limit setup failed")
        return original_setrlimit(limit, values)

    monkeypatch.setattr(resource, "setrlimit", fail_cpu_limit)
    registry = _registry(
        index,
        fixture_cases=(FixtureCase(case_id="confirmed", runner=_confirmed_fixture),),
    )

    result = _invoke(
        registry,
        "run_fixture_test",
        {"case_id": "confirmed"},
        _scope(),
    )
    payload = json.loads(result.content)

    assert payload["status"] == "UNRESOLVED"
    assert "resource limits" in payload["details"]["error"]


def test_budgeted_validation_output_remains_valid_json_with_explicit_error():
    document = CodeDocument(
        repository_id="repo",
        path="many.py",
        text="\n".join(f"value_{index} = eval(input_{index})" for index in range(200)),
        defines=("many",),
    )
    index = RepositoryIndex([document])
    registry = ToolRegistry(
        full_agent_tools(index),
        max_output_bytes=160,
    )

    observation = _invoke(
        registry,
        "run_static_check",
        {"path": "many.py"},
        _scope("many.py"),
    )
    payload = json.loads(observation.content)

    assert observation.status == "error"
    assert payload["observation_truncated"] is True
    assert payload["reason"] == "byte_budget"

    token_registry = ToolRegistry(
        full_agent_tools(index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    token_observation = _invoke(
        token_registry,
        "run_static_check",
        {"path": "many.py"},
        ToolExecutionScope(
            admitted_paths=frozenset({"many.py"}),
            max_observation_tokens=100,
        ),
    )
    token_payload = json.loads(token_observation.content)

    assert token_observation.status == "error"
    assert token_payload["observation_truncated"] is True
    assert token_payload["reason"] == "token_budget"

    suppressed_observation = _invoke(
        token_registry,
        "run_static_check",
        {"path": "many.py"},
        ToolExecutionScope(
            admitted_paths=frozenset({"many.py"}),
            max_observation_tokens=1,
        ),
    )
    suppressed_payload = json.loads(suppressed_observation.content)

    assert suppressed_observation.status == "error"
    assert suppressed_payload["observation_truncated"] is True
    assert suppressed_payload["reason"] == "token_budget"
    assert suppressed_observation.metadata["model_payload_suppressed"] is True
    assert token_registry.prompt_payload(suppressed_observation) == ""


def test_json_tool_registry_rejects_impossible_marker_budget():
    index, _ = cross_file_fixture()

    with pytest.raises(ValueError, match="json tool output budget"):
        ToolRegistry(full_agent_tools(index), max_output_bytes=10)


def test_loopback_http_validator_confirms_bypass_and_refutes_guarded_case():
    index, _ = cross_file_fixture()
    registry = _registry(
        index,
        loopback_cases=(
            LoopbackCase(case_id="vulnerable", application=_vulnerable_application),
            LoopbackCase(case_id="guarded", application=_guarded_application),
        ),
    )

    vulnerable = _invoke(
        registry,
        "run_loopback_http_case",
        {"case_id": "vulnerable"},
        _scope(),
    )
    guarded = _invoke(
        registry,
        "run_loopback_http_case",
        {"case_id": "guarded"},
        _scope(),
    )
    vulnerable_payload = json.loads(vulnerable.content)
    guarded_payload = json.loads(guarded.content)

    assert vulnerable_payload["status"] == "CONFIRMED"
    assert vulnerable_payload["details"]["bind_host"] == "127.0.0.1"
    assert guarded_payload["status"] == "REFUTED"
    assert guarded_payload["details"]["unauthorized_status"] == 403

    unknown = _invoke(
        registry,
        "run_loopback_http_case",
        {"case_id": "not-registered"},
        _scope(),
    )
    assert unknown.status == "error"
