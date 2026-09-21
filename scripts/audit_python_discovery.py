"""Recheck source discovery after development repairs; no model or reference input is read."""
import json
from uuid import uuid4

from run_python_repository_pilot import prepare, project_root, save_json
from cv_agent.live_gate import source_fingerprint
from cv_agent.repository_pilot import RepositoryPilotConfig


def audit(config_path):
    config = RepositoryPilotConfig.model_validate_json(config_path.read_text())
    inventory, _ = prepare(config, project_root)
    output = project_root / 'artifacts/python_discovery_audit' / uuid4().hex
    output.mkdir(parents=True)
    save_json(output / 'inventory.json', inventory)
    save_json(output / 'results.json', [])
    save_json(output / 'metadata.json', {'source_fingerprint': source_fingerprint(project_root),
        'config': config.model_dump(mode='json'), 'model_requests': 0, 'claim_eligible': False})
    print(json.dumps({'directory': str(output), 'subjects': [
        {'repository_id': subject['repository_id'], 'source_files': subject['discovery']['source_files'],
         'candidates': subject['discovery']['candidate_count'], 'parse_errors': subject['discovery']['parse_errors']}
        for subject in inventory['subjects']], 'model_requests': 0}), flush=True)


if __name__ == '__main__':
    audit(project_root / 'configs/python_repository_pilot.json')
    audit(project_root / 'configs/python_nltk_development_pilot.json')
