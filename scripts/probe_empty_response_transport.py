"""Four explicit transport probes; no tool execution, automatic retry, or fallback."""
import json
import os
from uuid import uuid4

from run_micro_benchmark import project_root,CONFIG,Journal,Trial,utc_now
from run_development_benchmark import snapshot_sources
from cv_agent.agent_types import ChatMessage
from cv_agent.model_runtime import OpenAICompatibleChatModel
from cv_agent.benchmark_evaluation import provider_usage


def main():
    key=os.environ['ANTIGRAVITY_API_KEY']
    source=project_root/'artifacts/real_source_smoke/d1891dbaa76244d7a4dc76888c9e4dbc/events.jsonl'
    recorded=[json.loads(line) for line in source.read_text().splitlines()]
    output=project_root/'artifacts/transport_probe'/uuid4().hex
    output.mkdir(parents=True)
    (output/'metadata.json').write_text(json.dumps(dict(started_at=utc_now(),source=str(source),
        config=CONFIG,max_requests=4,tool_execution=False,claim_eligible=False,
        source_sha256=snapshot_sources(output)),indent=2)+'\n')
    journal=Journal(output/'events.jsonl')
    results=[]
    print(f'Run directory: {output}',flush=True)
    for repository,settings in [('PrefectHQ',('disabled',None)),('jlowin',(None,'disabled'))]:
        request=next(event for event in recorded if event['event']=='model_start'
                     and event['system']=='E3' and f'github.com/{repository}/' in event['case_id'])
        for setting in settings:
            name='thinking_omitted' if setting is None else 'thinking_disabled'
            trial=Trial(repository,name,journal)
            model=OpenAICompatibleChatModel(**{**CONFIG,'thinking_mode':setting},api_key=key,
                                            observer=trial.observe('transport_probe'))
            result=dict(repository=repository,variant=name)
            try:
                reply=model.complete([ChatMessage.model_validate(message) for message in request['messages']],request['tools'])
                result.update(valid_reply=True,returned_model=reply.model_id,tool_calls_requested=len(reply.tool_calls))
            except Exception as error:
                result.update(valid_reply=False,error_type=type(error).__name__,error=str(error))
            results.append(result)
            events=[json.loads(line) for line in (output/'events.jsonl').read_text().splitlines()]
            (output/'results.json').write_text(json.dumps(dict(results=results,usage=provider_usage(events),
                interpretation='Exploratory transport-only comparison; four outcomes cannot establish a general cause.'),indent=2)+'\n')
            print(result,flush=True)


if __name__=='__main__':
    main()
