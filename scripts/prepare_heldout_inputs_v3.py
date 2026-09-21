"""Freeze the independent split after promoting the inspected NLTK pilot to development."""
import json
from pathlib import Path

from cv_agent.heldout_manifest import prepare_heldout
from cv_agent.provenance import git_identity


def main():
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / 'configs/heldout_preparation_v3.json').read_text())
    dataset = root / 'data/raw/VulnGym'
    rows = [json.loads(line) for line in (dataset / 'data/entries.jsonl').read_text().splitlines() if line.strip()]
    prepared = prepare_heldout(rows, config['development_repositories'])
    detector, evaluator = root / config['detector_output'], root / config['evaluator_output']
    if detector.exists() or evaluator.exists():
        raise FileExistsError('Preserve the already-frozen v3 split')
    evaluator.mkdir(parents=True)
    detector.write_text(json.dumps({
        'dataset_identity': git_identity(dataset).model_dump(mode='json'),
        'role': 'heldout_candidate_inputs', 'claim_eligible': False, 'split_version': 3,
        'supersedes': config['supersedes'], 'subjects': prepared['detector_inputs'],
    }, indent=2) + '\n')
    (evaluator / 'preparation_config.json').write_text(json.dumps(config, indent=2) + '\n')
    for name, key in [('labels.json', 'evaluator_labels'), ('excluded.json', 'excluded'), ('summary.json', 'summary')]:
        (evaluator / name).write_text(json.dumps(prepared[key], indent=2) + '\n')
    print(json.dumps(prepared['summary'], indent=2))


if __name__ == '__main__':
    main()
