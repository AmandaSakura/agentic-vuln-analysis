"""Predeclared first-turn samples; no tool execution, retries or fallback."""
import json
import os
from uuid import uuid4

from run_micro_benchmark import Journal, Trial, project_root, utc_now
from run_development_benchmark import Budget, snapshot_sources
from cv_agent.agent_types import ChatMessage
from cv_agent.benchmark_evaluation import provider_usage
from cv_agent.live_gate import require_passing_tests
from cv_agent.model_runtime import OpenAICompatibleChatModel


def main():
    config = json.loads((project_root / 'configs/langchain_transport_probe.json').read_text())
    model_config = json.loads((project_root / config['model_config']).read_text())
    recorded = [json.loads(line) for line in (project_root / config['source']).read_text().splitlines()]
    output = project_root / 'artifacts/langchain_transport_probe' / uuid4().hex
    output.mkdir(parents=True)
    (output / 'metadata.json').write_text(json.dumps(dict(
        config=config, model_config=model_config, started_at=utc_now(),
        tool_execution=False, claim_eligible=False, source_sha256=snapshot_sources(output)), indent=2))
    print(f'Run directory: {output}', flush=True)
    require_passing_tests()
    budget = Budget(config['max_requests'], config['max_seconds'])
    journal = Journal(output / 'events.jsonl')
    results = []
    for sample, case in enumerate(config['cases'], 1):
        request = next(event for event in recorded
                       if event['event'] == 'model_start' and event['case_id'] == case)
        trial = Trial(case, f'transport_sample_{sample}', journal)
        model = OpenAICompatibleChatModel(**model_config, api_key=os.environ['ANTIGRAVITY_API_KEY'],
                                         observer=budget.observer(trial, 'transport_probe'))
        result = dict(sample=sample, case_id=case)
        try:
            reply = model.complete([ChatMessage.model_validate(message) for message in request['messages']],
                                   request['tools'])
            result.update(valid_reply=True, tool_calls_requested=len(reply.tool_calls))
        except (ValueError, RuntimeError) as error:
            result.update(valid_reply=False, error_type=type(error).__name__, error=str(error))
        results.append(result)
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        (output / 'results.json').write_text(json.dumps(dict(results=results, usage=provider_usage(events)), indent=2))
        print(result, flush=True)


if __name__ == '__main__':
    main()
