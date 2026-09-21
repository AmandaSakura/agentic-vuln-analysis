"""Write synthetic advisory contracts as the current two explicit input files."""
import json

DATASET_FIELDS = {'dataset_role', 'claim_eligible', 'source_manifest', 'pairs'}


def write_advisory_config(root, data, profile):
    dataset_path = root / 'configs/datasets/advisory_pairs_v4.json'
    profile_path = root / f'configs/profiles/advisory_{profile}_v4.json'
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    dataset_path.write_text(json.dumps({key: value for key, value in data.items() if key in DATASET_FIELDS}))
    profile_path.write_text(json.dumps({key: value for key, value in data.items() if key not in DATASET_FIELDS}))
