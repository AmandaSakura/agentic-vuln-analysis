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
        # Reverse only the declared path relocation, then compare original bytes.
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
