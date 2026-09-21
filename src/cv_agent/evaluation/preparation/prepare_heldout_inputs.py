"""Freeze label-free repository/commit inputs; no downloads, model calls, or exploit execution."""

from cv_agent.runtime.paths import PROJECT_ROOT
import json
from pathlib import Path

ROOT=PROJECT_ROOT
from cv_agent.evaluation.datasets.heldout_manifest import prepare_heldout
from cv_agent.runtime.provenance import git_identity


def main():
    config=json.loads((ROOT/'configs/preparation/heldout_preparation_v2.json').read_text())
    dataset=ROOT/'data/raw/VulnGym'
    rows=[json.loads(line) for line in (dataset/'data/entries.jsonl').read_text().splitlines() if line.strip()]
    prepared=prepare_heldout(rows,config['development_repositories'])
    detector=ROOT/config['detector_output']
    evaluator=ROOT/config['evaluator_output']
    if detector.exists() or evaluator.exists():
        raise FileExistsError('Held-out preparation already exists; do not overwrite the frozen split')
    evaluator.mkdir(parents=True)
    detector.write_text(json.dumps(dict(dataset_identity=git_identity(dataset).model_dump(mode='json'),
        role='heldout_candidate_inputs',claim_eligible=False,split_version=2,
        supersedes=config['supersedes'],subjects=prepared['detector_inputs']),indent=2)+'\n')
    (evaluator/'preparation_config.json').write_text(json.dumps(config,indent=2)+'\n')
    for name,key in [('labels.json','evaluator_labels'),('excluded.json','excluded'),('summary.json','summary')]:
        (evaluator/name).write_text(json.dumps(prepared[key],indent=2)+'\n')
    print(json.dumps(prepared['summary'],indent=2))
    print(f'Detector inputs: {detector}; evaluator-only labels: {evaluator}')


if __name__=='__main__':
    main()
