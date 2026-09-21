"""Offline, exact-request replay of the recorded positive pilot; not a new live run."""

from cv_agent.runtime.paths import PROJECT_ROOT
import json
from pathlib import Path

ROOT = PROJECT_ROOT
from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply
from cv_agent.tools.registry import ToolRegistry
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.validation import full_agent_tools


def main():
    source = ROOT/'artifacts/development_benchmark/21a5871ad4a54128b58dc39bcc5d41d0'
    events = [json.loads(line) for line in (source/'events.jsonl').read_text().splitlines()]
    starts = [event for event in events if event['event']=='model_start']
    replies = [event for event in events if event['event']=='model_reply']
    responders = []
    for start, reply in zip(starts, replies, strict=True):
        def respond(messages, tools, start=start, reply=reply):
            if [message.model_dump(mode='json') for message in messages] != start['messages']:
                raise ValueError('Replay prompt differs from the original live request')
            if list(tools) != start['tools']:
                raise ValueError('Replay tool definitions differ from the original live request')
            return ModelReply.model_validate(reply['reply'])
        responders.append(respond)
    inputs = load_owasp_agentic_inputs(ROOT/'data/raw', case_ids=['BenchmarkTest02244'])
    model = ScriptedChatModel(responders)
    verdict = AgenticPipeline(index=inputs.index, system=AgentSystemVersion.E1_LOCAL_SINGLE,
        models={'scan':model}, tools=ToolRegistry(full_agent_tools(inputs.index),max_output_bytes=8192)
    ).run(inputs.candidates[0])
    output = source/'offline_replay_after_parser_fix.json'
    output.write_text(json.dumps(dict(
        runtime_mode='scripted', claim_eligible=False, new_api_requests=0,
        exact_request_matches=len(model.requests), recorded_requests=len(starts),
        purpose='Parser-fix regression replay; does not replace the original failed live trial',
        verdict=verdict.model_dump(mode='json')), indent=2)+'\n')
    print(f'{verdict.label}; {len(model.requests)} exact request matches; {output}')


if __name__=='__main__':
    main()
