from cv_agent.agents.scanner import StaticScanner
from cv_agent.domain.types import CodeDocument
import pytest


def test_static_scanner_emits_stable_candidates():
    document = CodeDocument(
        repository_id="repo",
        path="runner.py",
        text="def run(cmd):\n    return subprocess.run(cmd, shell=True)\n",
    )
    candidates = StaticScanner().scan("repo", [document])
    assert [candidate.line for candidate in candidates] == [2]
    assert {candidate.metadata["rule"] for candidate in candidates} == {"command-execution"}


@pytest.mark.parametrize('path',['runner.py::run@100-104','Runner.java::run@100',
                                 'bundle.js::runner@100-104#5000-5200'])
def test_scanner_reports_source_lines_not_function_relative_lines(path):
    document=CodeDocument(repository_id='repo',path=path,
        text='def run(cmd):\n    return subprocess.run(cmd, shell=True)\n')
    candidate=StaticScanner().scan('repo',[document])[0]
    assert candidate.line==101
    assert candidate.metadata['span_relative_line']==2
    assert ':101:command-execution' in candidate.candidate_id


def test_javascript_byte_disambiguator_keeps_retrieval_line_bounds():
    from cv_agent.retrieval import _line_bounds_from_path
    assert _line_bounds_from_path('bundle.js::runner@100-104#5000-5200')==(100,104)


@pytest.mark.parametrize('expression', [
    'renderer.render(template)', 'value.format_map(params)',
    'format_handlers[kind](template, **params)',
    'factory.from_template(template)',
])
def test_template_candidates_follow_python_call_syntax_without_reference_paths(expression):
    from cv_agent.code_adapters.python import parse_python_source
    docs = [span.document for span in parse_python_source('repo', 'renamed/engine.py',
             'def build(template, params, kind):\n    return ' + expression + '\n')]
    candidates = StaticScanner().scan('repo', docs)
    assert any(c.line == 2 and c.metadata['rule'] == 'template-operation' for c in candidates)
    assert all(c.metadata.get('evidence_kind') == 'static_candidate' for c in candidates)


def test_template_discovery_ignores_comments_and_strings_but_keeps_benign_calls():
    from cv_agent.code_adapters.python import parse_python_source
    source = '''def build():
    # renderer.render(untrusted)
    example = "format_handlers[kind](untrusted)"
    return "hello {}".format("world")
'''
    docs = [span.document for span in parse_python_source('repo', 'sample.py', source)]
    candidates = StaticScanner().scan('repo', docs)
    assert [(c.line, c.metadata['rule']) for c in candidates] == [(4, 'template-operation')]
    # Candidate generation must include fixed/benign code without declaring a vulnerability.
    assert 'label' not in candidates[0].metadata


def test_python_discovery_uses_calls_instead_of_comment_and_string_patterns():
    from cv_agent.code_adapters.python import parse_python_source
    source = '''def entry(value):
    # eval(value); subprocess.run(value)
    example = "eval(value); subprocess.run(value)"
    return eval(value)
'''
    docs = [s.document for s in parse_python_source('repo', 'entry.py', source)]
    assert [(c.line, c.metadata['rule']) for c in StaticScanner().scan('repo', docs)] == [
        (4, 'dynamic-evaluation')]


def test_python_import_aliases_and_multiline_database_calls_are_discovered():
    from cv_agent.code_adapters.python import parse_python_source
    source = '''from subprocess import run as launch
import os as operating
def entry(value, cursor):
    launch(value)
    operating.system(value)
    cursor.execute(
        value
    )
'''
    docs = [s.document for s in parse_python_source('repo', 'entry.py', source)]
    found = StaticScanner().scan('repo', docs)
    assert [(c.line, c.metadata['rule']) for c in found] == [
        (4, 'command-execution'), (5, 'command-execution'), (6, 'database-operation')]
    assert all(c.analysis_scope for c in found)


def test_nested_spans_do_not_duplicate_the_same_source_operation():
    from cv_agent.code_adapters.python import parse_python_source
    source = 'def outer():\n    def inner(value):\n        return eval(value)\n    return inner\n'
    docs = [s.document for s in parse_python_source('repo', 'entry.py', source)]
    found = StaticScanner().scan('repo', docs)
    assert len(found) == 1
    assert found[0].line == 3
    assert 'inner@' in found[0].path


def test_indented_method_with_unindented_multiline_string_is_parsed_without_rewriting_it():
    from cv_agent.code_adapters.python import parse_python_source
    source = 'class Engine:\n    def entry(self, value):\n        text = """example\nnot indented\n"""\n        return eval(value)\n'
    docs = [s.document for s in parse_python_source('repo', 'engine.py', source)]
    found = StaticScanner().scan('repo', docs)
    assert [(c.line, c.metadata['rule']) for c in found] == [(6, 'dynamic-evaluation')]


@pytest.mark.parametrize('decorator', ['router.get("/records/{id}")', 'app.route("/records")'])
def test_authorization_boundary_is_discovered_even_without_injection_sink(decorator):
    from cv_agent.code_adapters.python import parse_python_source
    source = f'@{decorator}\ndef read_record(id):\n    return records[id]\n'
    docs = [s.document for s in parse_python_source('repo', 'routes.py', source)]
    found = StaticScanner().scan('repo', docs)
    assert [(c.line, c.metadata['rule']) for c in found] == [(1, 'authorization-boundary')]
    assert 'principal' in found[0].analysis_scope
    assert 'label' not in found[0].metadata


@pytest.mark.parametrize('binding,expression,rule', [
    ('', 'getattr(record, field)', 'dynamic-attribute-access'),
    ('from builtins import getattr as access\n', 'access(record, field)', 'dynamic-attribute-access'),
    ('import os as operating\n', 'operating._exit(0)', 'process-control'),
    ('from os import _exit as stop\n', 'stop(0)', 'process-control'),
])
def test_source_only_discovery_covers_reflection_and_process_control(binding, expression, rule):
    from cv_agent.code_adapters.python import parse_python_source
    source = binding + 'def operation(record, field):\n    return ' + expression + '\n'
    docs = [s.document for s in parse_python_source('repo', 'renamed/operations.py', source)]
    found = StaticScanner().scan('repo', docs)
    assert [c.metadata['rule'] for c in found] == [rule]
    assert found[0].line == len(source.splitlines())
    assert found[0].metadata['evidence_kind'] == 'static_candidate'
    assert 'label' not in found[0].metadata


def test_fixed_attribute_names_and_reflection_decoys_do_not_imply_dynamic_access():
    from cv_agent.code_adapters.python import parse_python_source
    source = '''def operation(record):
    # getattr(record, field); os._exit(0)
    example = "getattr(record, field); os._exit(0)"
    return getattr(record, "display_name")
'''
    docs = [s.document for s in parse_python_source('repo', 'renamed/operations.py', source)]
    assert StaticScanner().scan('repo', docs) == []
