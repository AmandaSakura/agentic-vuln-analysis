"""Two-cell independent Python input pilot; configuration is frozen before scoring."""
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.evaluation.runners.run_python_repository_pilot import run


if __name__ == '__main__':
    run(project_root / 'configs/experiments/python_heldout_pilot.json')
