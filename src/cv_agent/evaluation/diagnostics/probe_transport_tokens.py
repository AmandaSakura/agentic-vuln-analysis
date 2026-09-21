"""Fixed first-request comparison; no tools executed and no retries."""
import json
import os
from uuid import uuid4

from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.runtime.journal import Journal, Trial, utc_now
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.domain.chat import ChatMessage
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.evaluation.metrics import provider_usage


def main():
    config = json.loads((project_root/'configs/diagnostics/transport_token_probe.json').read_text())
    model_config = json.loads((project_root/config['model_config']).read_text())
    recorded = [json.loads(line) for line in (project_root/config['source']).read_text().splitlines()]
    output = project_root/'artifacts/transport_token_probe'/uuid4().hex
    output.mkdir(parents=True)
    (output/'metadata.json').write_text(json.dumps(dict(started_at=utc_now(),config=config,
        model_config=model_config,tool_execution=False,claim_eligible=False,
        source_sha256=snapshot_sources(project_root, output)),indent=2)+'\n')
    journal = Journal(output/'events.jsonl')
    results = []
    print(f'Run directory: {output}',flush=True)
    for repository,limit in config['probes']:
        request = next(event for event in recorded if event['event']=='model_start'
            and event['system']=='E3' and f'github.com/{repository}/' in event['case_id'])
        trial = Trial(repository,f'max_tokens_{limit}',journal)
        model = OpenAICompatibleChatModel(**{**model_config,'max_tokens':limit},
            api_key=os.environ['ANTIGRAVITY_API_KEY'],observer=trial.observe('transport_probe'))
        result = dict(repository=repository,max_tokens=limit)
        try:
            reply = model.complete([ChatMessage.model_validate(item) for item in request['messages']],request['tools'])
            result.update(valid_reply=True,tool_calls_requested=len(reply.tool_calls))
        except Exception as error:
            result.update(valid_reply=False,error_type=type(error).__name__,error=str(error))
        results.append(result)
        events = [json.loads(line) for line in (output/'events.jsonl').read_text().splitlines()]
        (output/'results.json').write_text(json.dumps(dict(results=results,usage=provider_usage(events)),indent=2)+'\n')
        print(result,flush=True)


if __name__=='__main__':
    main()
