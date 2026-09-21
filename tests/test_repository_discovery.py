from cv_agent.repository_discovery import discover_python_repository, select_pilot_candidates


def test_module_and_function_operations_are_discovered_without_reference_locations(tmp_path):
    (tmp_path / 'entry.py').write_text(
        'from subprocess import run as launch\n'
        'launch("echo hello")\n'
        'def entry(value):\n'
        '    return eval(value)\n')
    discovered = discover_python_repository(tmp_path, 'subject-01')
    assert [(c.line, c.metadata['rule']) for c in discovered.candidates] == [
        (2, 'command-execution'), (4, 'dynamic-evaluation')]
    assert all(c.case_id.startswith('candidate-') for c in discovered.candidates)
    assert len({c.case_id for c in discovered.candidates}) == 2
    assert discovered.report['source_files'] == 1
    assert discovered.report['parse_errors'] == []
    assert set(discovered.report['source_sha256']) == {'entry.py'}
    again = discover_python_repository(tmp_path, 'subject-01')
    assert again.candidates == discovered.candidates
    assert select_pilot_candidates(discovered.candidates, 1) == discovered.candidates[:1]


def test_discovery_reports_unparsed_files_and_excludes_environment_code(tmp_path):
    (tmp_path / 'bad.py').write_text('def broken(:\n')
    (tmp_path / 'good.py').write_text('def render(template):\n    return template.format(value=1)\n')
    env = tmp_path / '.venv'
    env.mkdir()
    (env / 'ignored.py').write_text('eval(value)\n')
    (tmp_path / 'linked.py').symlink_to(tmp_path / 'good.py')
    discovered = discover_python_repository(tmp_path, 'subject-01')
    assert discovered.report['source_files'] == 3
    assert {r['path'] for r in discovered.report['parse_errors']} == {'bad.py', 'linked.py'}
    assert len(discovered.candidates) == 1
    assert discovered.candidates[0].metadata['rule'] == 'template-operation'


def test_neutral_root_location_does_not_change_detector_inputs(tmp_path):
    outputs = []
    for private_name in ('vulnerable-checkout', 'fixed-checkout'):
        root = tmp_path / private_name
        root.mkdir()
        (root / 'handler.py').write_text('def entry(value):\n    return eval(value)\n')
        outputs.append(discover_python_repository(root, 'subject-01'))
    assert outputs[0].candidates == outputs[1].candidates
    assert list(outputs[0].index.documents.values()) == list(outputs[1].index.documents.values())
    assert '::entry@' in outputs[0].candidates[0].path


def test_discovered_function_retains_cross_file_graph_context(tmp_path):
    (tmp_path / 'entry.py').write_text('from service import calculate\ndef entry(value):\n    return calculate(value).format()\n')
    (tmp_path / 'service.py').write_text('def calculate(value):\n    return value\n')
    found = discover_python_repository(tmp_path, 'subject-01')
    candidate = found.candidates[0]
    assert '::entry@' in candidate.path
    neighbors = found.index.graph_neighbors(candidate.path, direction='forward')
    assert any(path.startswith('service.py::calculate@') for path in neighbors)


def test_candidate_limit_is_explicit_and_does_not_reorder_findings():
    import pytest
    with pytest.raises(ValueError, match='positive'):
        select_pilot_candidates((), 0)
