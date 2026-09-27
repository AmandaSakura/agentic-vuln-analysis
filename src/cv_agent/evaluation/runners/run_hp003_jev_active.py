"""Run hp003_a/b with active Jev planning and an ordinary E4 control."""
from cv_agent.evaluation.runners.run_jev_routing_pilot import run


if __name__ == '__main__':
    run(config_path='configs/experiments/hp003_jev_active.json')
