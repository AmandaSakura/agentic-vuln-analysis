"""Offline public CLI regression for exact-operation delivery, not function text."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


pipeline = module('static_delivery_pipeline', ROOT / 'audit/static_pipeline_20261002/pipeline.py')
pilot = module('static_delivery_inputs', ROOT / 'audit/live_static_pilot_20261001/run.py')


@pytest.mark.parametrize('mode,state', [('0o772', 'SUPPORTED'), ('0o750', 'REFUTED'), ('mode', 'UNKNOWN')])
def test_public_pipeline_checks_exact_call_instead_of_whole_function(tmp_path, mode, state):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'entry.py').write_text(f'import os\ndef inspect(path, mode):\n    os.chmod(path, {mode})\n')
    bundle = pipeline.build_bundle(source, tmp_path / 'static')
    rows = pilot.inputs_from_bundle(bundle, 'owned_offline_control')
    assert len(rows) == 1 and rows[0]['canonical_state'] == state
    assert 'def inspect' in rows[0]['payload']['source_slice']
    rows[0]['delivery'] = pipeline.check_delivery(source, bundle, rows[0])
    assert all(rows[0]['delivery']['checks'].values())
    assert all(pipeline.post_reply_delivery(rows[0]).values())


def test_pipeline_boundary_controls_reject_corruption_and_drift_and_keep_positive_controls(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    text = 'import os\ndef inspect(path):\n    os.chmod(path, 0o750)\n'
    (source / 'entry.py').write_text(text)
    bundle = pipeline.build_bundle(source, tmp_path / 'static')
    row = pilot.inputs_from_bundle(bundle, 'owned_offline_control')[0]
    row['delivery'] = pipeline.check_delivery(source, bundle, row)
    boundaries = pipeline.check_boundaries(source, bundle, row)
    assert all(boundaries.values())
    assert (source / 'entry.py').read_text() == text
    assert all(pipeline.post_reply_delivery(row).values())
