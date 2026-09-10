import json

import pytest

from cv_agent.agent_tools import ToolExecutionScope, ToolRegistry
from cv_agent.agent_types import ModelToolCall
from cv_agent.python_ast import parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.validation_tools import full_agent_tools, _parameters
from cv_agent.types import CodeDocument


def trace(files):
    documents = [span.document for path, text in files.items()
                 for span in parse_python_source("test-repo", path, text)]
    entry = next(doc for doc in documents if doc.path.startswith("entry.py::entry@"))
    registry = ToolRegistry(full_agent_tools(RepositoryIndex(documents)), max_output_bytes=1_000_000)
    observation = registry.invoke(
        ModelToolCall(call_id="trace", name="trace_dataflow", arguments={"source_path": entry.path}),
        allowed=("trace_dataflow",),
        scope=ToolExecutionScope(frozenset(doc.path for doc in documents), 8192),
    )
    return json.loads(observation.content)


@pytest.mark.parametrize("signature,call,expected", [
    ("command, audit_tag", 'run_command("1 + 1", user_value)', "UNRESOLVED"),
    ("command, audit_tag", 'run_command(user_value, "fixed")', "CONFIRMED"),
    ("command: str, audit_tag: str", 'run_command(user_value, "fixed")', "CONFIRMED"),
    ("command: str, audit_tag: str", 'run_command(command="1 + 1", audit_tag=user_value)', "UNRESOLVED"),
    ("command: str, audit_tag: str", 'run_command(audit_tag="fixed", command=user_value)', "CONFIRMED"),
])
def test_taint_binds_actual_arguments_to_named_parameters(signature, call, expected):
    result = trace({
        "entry.py": f"from service import run_command\n\ndef entry(request):\n    user_value = request.args['value']\n    return {call}\n",
        "service.py": f"def run_command({signature}):\n    return eval(command)\n",
    })
    assert result["status"] == expected


@pytest.mark.parametrize("transform,sink,expected", [
    ("os.path.realpath(value)", "open(clean)", "CONFIRMED"),
    ("validate(value)", "eval(clean)", "CONFIRMED"),
    ("shlex.quote(value)", "subprocess.run(clean, shell=True)", "UNRESOLVED"),
    ("shlex.quote(value)", "database.execute(clean)", "CONFIRMED"),
    ("int(value)", "database.execute(clean)", "UNRESOLVED"),
])
def test_sanitizers_are_specific_to_the_sink_category(transform, sink, expected):
    result = trace({
        "entry.py": f"def entry(request):\n    value = request.args['value']\n    clean = {transform}\n    return {sink}\n",
    })
    assert result["status"] == expected


def test_multiline_sink_and_branch_merge_keep_possible_taint():
    result = trace({
        "entry.py": "def entry(request):\n    value = request.args['value']\n    if request.args['flag']:\n        value = 'fixed'\n    return eval(\n        value\n    )\n",
    })
    assert result["status"] == "CONFIRMED"


def test_comment_and_string_mentions_are_not_executable_sources_or_sinks():
    result = trace({
        "entry.py": "def entry(request):\n    # eval(request.args['value'])\n    value = 'request.args'\n    return eval(repr(value))\n",
    })
    assert result["status"] == "UNRESOLVED"


@pytest.mark.parametrize("language,source", [
    ("go", "func (s *Server) handle(value string, audit int) {}"),
    ("java", '@Path("route") public void handle(String value, int audit) {}'),
    ("typescript", "function handle(value: string, audit: number) {}"),
    ("javascript", "handle(value, audit) {}"),
])
def test_formal_parameters_are_names_not_annotations_or_receivers(language, source):
    document = CodeDocument(repository_id="r", path="function", text=source, language=language)
    assert _parameters(document) == ("value", "audit")
