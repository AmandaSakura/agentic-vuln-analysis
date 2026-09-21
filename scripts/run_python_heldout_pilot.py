"""Two-cell independent Python input pilot; configuration is frozen before scoring."""
from run_python_repository_pilot import project_root, run


if __name__ == '__main__':
    run(project_root / 'configs/python_heldout_pilot.json')
