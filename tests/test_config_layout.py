"""Relocation changes paths, never experiment parameters or source identities."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRIES = json.loads((ROOT / 'tests/fixtures/config_relocation.json').read_text())


def test_configuration_layout_and_original_content():
    assert len(ENTRIES) == 36
    assert not list((ROOT / 'configs').glob('*.json'))
    for entry in ENTRIES:
        path = ROOT / entry['new']
        content = path.read_text()
        # C1/C4 migration adds three proof obligations and hp003's explicit
        # scenario assumptions. Removing only those reviewed deltas must
        # reproduce the original frozen bytes.
        if entry['new'] == 'configs/datasets/advisory_pairs_v4.json':
            payload = json.loads(content)
            assert [pair.pop('property_id') for pair in payload['pairs']] == [
                'temporary-directory-race', 'authorization-boundary', 'command-execution',
            ]
            assert payload['pairs'][2].pop('entry_condition_assumptions') == {
                "sys.platform.startswith('linux')": True,
                'is_windows()': False,
                'self._env_manager != em.LOCAL': False,
                'os.path.exists(artifact_uri)': True,
            }
            assert payload['pairs'][2].pop('entry_value_assumptions') == {
                'port': 5000,
                'host': '127.0.0.1',
                'timeout': None,
                'self._nworkers': None,
                'model_config': None,
                'synchronous': False,
                'MLServerDefaultModelName': 'mlflow-model',
                'MLServerMLflowRuntime': 'mlserver_mlflow.MLflowRuntime',
            }
            content = json.dumps(payload, ensure_ascii=False, indent=2) + '\n'
        if entry['new'] in {'configs/experiments/python_pair_gate.json', 'configs/experiments/python_pair_matrix.json'}:
            payload = json.loads(content)
            expected = ['template-traversal']
            if entry['new'].endswith('matrix.json'):
                expected.append('sandbox-attr-format-escape')
            assert [pair['property_id'] for pair in payload['pairs']] == expected
            for property_id in expected:
                content = content.replace(f'      "property_id": "{property_id}",\n', '')
        # Reverse the declared path relocation, then compare original bytes.
        for old in ENTRIES:
            content = content.replace(old['new'], old['old'])
        assert hashlib.sha256(content.encode()).hexdigest() == entry['sha256'], path
        if entry['new'] != entry['old']:
            assert not (ROOT / entry['old']).exists()


def test_config_references_resolve():
    def values(value):
        if isinstance(value, dict):
            for child in value.values():
                yield from values(child)
        elif isinstance(value, list):
            for child in value:
                yield from values(child)
        elif isinstance(value, str):
            yield value
    for entry in ENTRIES:
        for value in values(json.loads((ROOT / entry['new']).read_text())):
            if value.startswith('configs/') and value.endswith('.json'):
                assert (ROOT / value).is_file(), (entry['new'], value)
