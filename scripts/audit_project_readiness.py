"""Read-only readiness audit of the declared pilot and preserved native evidence."""
import json
from pathlib import Path
from uuid import uuid4

from cv_agent.agentic_live import load_owasp_agentic_inputs, select_owasp_entry
from cv_agent.benchmark_evaluation import provider_usage
from cv_agent.experiment_acceptance import require_verification_capability
from cv_agent.live_gate import source_fingerprint
from cv_agent.validation_tools import full_agent_tools


def main():
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / 'configs/project_readiness_review.json').read_text())
    pilot = json.loads((root / config['pilot_config']).read_text())
    inputs = load_owasp_agentic_inputs(root / 'data/raw', case_ids=pilot['case_ids'])
    candidates = select_owasp_entry(inputs, pilot['entry_method'])
    tools = full_agent_tools(inputs.index)
    readiness_error = None
    try:
        require_verification_capability(tools)
    except ValueError as error:
        readiness_error = str(error)
    directory = root / config['historical_run']
    events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
    native = [event['diagnostic'] for event in events if event['event'] == 'model_proxy_diagnostic']
    report = dict(model_requests_made_by_audit=0, source_fingerprint=source_fingerprint(root),
        candidates=[dict(case_id=c.case_id, entry_path=c.path, line=c.line) for c in candidates],
        available_validators=[tool.name for tool in tools if tool.available and tool.validation_statuses],
        verification_readiness_error=readiness_error,
        historical_run=config['historical_run'], historical_usage=provider_usage(events),
        historical_native=dict(records=len(native),
            blocked=sum(item['diagnosis'] == 'upstream_blocked' for item in native),
            output_limit_present=sum(item.get('upstream_max_output_tokens') is not None for item in native)),
        full_expansion_allowed=False,
        note='Offline audit only; historical responses do not validate changed code or prompts.')
    output = root / 'artifacts/project_readiness_review' / uuid4().hex
    output.mkdir(parents=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(output=str(output), **report), indent=2))


if __name__ == '__main__':
    main()
