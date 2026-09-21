"""Inspect retained call targets under real Harness budgets; no model calls or labels."""

from cv_agent.runtime.paths import PROJECT_ROOT
import json
from collections import Counter
from pathlib import Path

ROOT = PROJECT_ROOT
from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.tools.registry import ToolRegistry
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.validation import full_agent_tools
from cv_agent.retrieval.bm25 import MetadataBM25Index


def main():
    manifest = json.loads((ROOT/'configs/datasets/development_manifest.json').read_text())
    inputs = load_owasp_agentic_inputs(ROOT/'data/raw',case_ids=manifest['case_ids'])
    rows=[]
    bm25 = MetadataBM25Index(inputs.index.documents.values())
    variants=[('E1',AgentSystemVersion.E1_LOCAL_SINGLE,inputs.index),
              ('E2',AgentSystemVersion.E2_TEXT_SINGLE,inputs.index),
              ('E3',AgentSystemVersion.E3_GRAPH_SINGLE,inputs.index),
              ('E2_metadata_bm25',AgentSystemVersion.E2_TEXT_SINGLE,bm25)]
    for name, system, index in variants:
        tools=ToolRegistry(full_agent_tools(index),max_output_bytes=8192)
        pipeline=AgenticPipeline(index=index,system=system,
                                 models={'scan':ScriptedChatModel([])},tools=tools)
        for candidate in inputs.candidates:
            state=pipeline._retrieve({'candidate':candidate})
            paths={item.path for item in state['evidence']}
            targets=set(inputs.index.graph_neighbors(candidate.path,direction='forward'))
            rows.append(dict(case_id=candidate.case_id,system=name,
                             entry=candidate.path,retained_paths=sorted(paths),
                             direct_targets=sorted(targets),retained_targets=sorted(targets & paths),
                             all_direct_targets_retained=bool(targets) and targets <= paths,
                             context_tokens=state['context_token_count']))
    summary={system:dict(cases=len(sub),with_direct_targets=sum(bool(row['direct_targets']) for row in sub),
                        all_direct_targets_retained=sum(row['all_direct_targets_retained'] for row in sub),
                        mean_context_tokens=sum(row['context_tokens'] for row in sub)/len(sub))
             for system in ('E1','E2','E3','E2_metadata_bm25') for sub in [[row for row in rows if row['system']==system]]}
    output=ROOT/'artifacts/development_context_audit_with_bm25.json'
    output.write_text(json.dumps(dict(model_requests=0,claim_eligible=False,
        purpose='Direct call-target context retention, not vulnerability recall or proof',
        summary=summary,cases=rows),indent=2)+'\n')
    print(json.dumps(summary,indent=2))
    print(output)


if __name__=='__main__':
    main()
