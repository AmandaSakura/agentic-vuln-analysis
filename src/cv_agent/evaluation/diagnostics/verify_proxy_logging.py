"""One benign, gated request to verify automatic native-response diagnostics."""
import json
import os
from uuid import uuid4

from cv_agent.runtime.journal import Journal, Trial, utc_now
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.runtime.budget import Budget
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.domain.chat import ChatMessage
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import require_passing_tests
from cv_agent.runtime.model import OpenAICompatibleChatModel


def main():
    config = json.loads((project_root / 'configs/diagnostics/proxy_logging_check.json').read_text())
    model_config = json.loads((project_root / config['model_config']).read_text())
    output = project_root / 'artifacts/transport_raw_diagnostic' / uuid4().hex
    output.mkdir(parents=True)
    (output / 'metadata.json').write_text(json.dumps(dict(config=config, model_config=model_config,
        started_at=utc_now(), claim_eligible=False, source_sha256=snapshot_sources(project_root, output)), indent=2))
    print(f'Run directory: {output}', flush=True)
    require_passing_tests()
    journal = Journal(output / 'events.jsonl')
    trial = Trial('benign-logging-check', 'transport-only', journal)
    model = OpenAICompatibleChatModel(**model_config, api_key=os.environ['ANTIGRAVITY_API_KEY'],
        observer=Budget(config['max_requests'], config['max_seconds']).observer(trial, 'logging_check'))
    try:
        model.complete([ChatMessage(role='user', content=config['prompt'])], [])
    finally:
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        diagnostics = [event['diagnostic'] for event in events if event['event'] == 'model_proxy_diagnostic']
        result = dict(diagnostics=diagnostics, usage=provider_usage(events))
        (output / 'results.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
    if not diagnostics or diagnostics[0]['diagnosis'] != 'upstream_response':
        raise RuntimeError('Native proxy log correlation was not verified')


if __name__ == '__main__':
    main()
