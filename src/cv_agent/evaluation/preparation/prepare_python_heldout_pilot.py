"""Fetch the explicit independent Python checkout without reading vulnerability labels."""

from cv_agent.runtime.paths import PROJECT_ROOT
import json
from pathlib import Path
import subprocess

from cv_agent.runtime.provenance import git_identity
from cv_agent.evaluation.repository import RepositoryPilotConfig, validate_heldout_membership


def main():
    root = PROJECT_ROOT
    config = RepositoryPilotConfig.model_validate_json((root / 'configs/experiments/python_heldout_pilot.json').read_text())
    validate_heldout_membership(config, json.loads((root / 'configs/datasets/vulngym_heldout_inputs_v3.json').read_text()))
    for subject in config.subjects:
        checkout = root / subject.checkout
        if not checkout.exists():
            checkout.mkdir(parents=True)
            commands = [
                ['git', 'init', '--quiet', str(checkout)],
                ['git', '-C', str(checkout), 'remote', 'add', 'origin', subject.repository_url],
                ['git', '-C', str(checkout), 'fetch', '--quiet', '--depth=1', 'origin', subject.commit],
                ['git', '-C', str(checkout), 'checkout', '--quiet', '--detach', subject.commit],
            ]
            for command in commands:
                subprocess.run(command, check=True, timeout=300)
        identity = git_identity(checkout)
        if identity.revision != subject.commit or identity.dirty:
            raise ValueError('Independent checkout differs from the pinned clean source')
        print(f'{subject.repository_id}: prepared {subject.commit}', flush=True)


if __name__ == '__main__':
    main()
