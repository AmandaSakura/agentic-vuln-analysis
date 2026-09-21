"""Run one candidate with explicit model settings and durable outcomes."""
import os
import time

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.runtime.budget import BudgetExceeded, BudgetStopped
from cv_agent.runtime.journal import RecordedTools, Trial


def run_candidate(index, candidate, system, journal, budget, report_system=None, *, model_config, registered_tools=None, api_key=None, graph_direction="forward", graph_ranking="lexical"):
    system_name = report_system or system.value
    trial = Trial(candidate.case_id, system_name, journal)
    start = time.perf_counter()
    result = dict(case_id=candidate.case_id, system=system_name,
                  status='failed', predicted_label=None, verdict=None)
    trial.record({'event': 'trial_start'})
    interruption = None
    try:
        budget.check()
        spec = FULL_SYSTEM_HARNESS.system_spec(system)
        roles = set(spec.expert_order) | ({'planner'} if spec.planner_enabled else set())
        models = {role: OpenAICompatibleChatModel(
            **model_config, api_key=api_key if api_key is not None else os.environ['ANTIGRAVITY_API_KEY'],
            observer=budget.observer(trial, role)) for role in sorted(roles)}
        verdict = AgenticPipeline(index=index, system=system, models=models,
                                  graph_direction=graph_direction,
                                  graph_ranking=graph_ranking,
                                  tools=RecordedTools(index, trial, registered_tools)).run(candidate)
        result.update(predicted_label=verdict.label,
                      status='abstained' if verdict.label == 'ABSTAIN' else 'completed',
                      verdict=verdict.model_dump(mode='json'))
    except (Exception, KeyboardInterrupt) as error:
        interruption = error if isinstance(error, KeyboardInterrupt) else None
        result.update(error_type=type(error).__name__, error=str(error),
                      status='interrupted' if interruption is not None else
                      'not_run' if isinstance(error, BudgetExceeded) and trial.model_calls == 0
                      else 'interrupted' if isinstance(error, BudgetStopped)
                      else 'failed')
    result.update(model_calls=trial.model_calls, tool_calls=trial.tool_calls,
                  latency_sec=round(time.perf_counter()-start, 3))
    trial.record({'event': 'trial_result', 'result': result})
    if interruption is not None:
        raise interruption
    return result
