"""Offline retrieval/command audit of the local v4 subjects; never calls a model."""

from cv_agent.runtime.paths import PROJECT_ROOT
from pathlib import Path
import json

from cv_agent.tools.analysis.commands import analyze_command, command_status
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.dataflow import trace_dataflow
from cv_agent.tools.validation.models import TraceDataflowInput
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.datasets.advisory_source import build_pair_input
from cv_agent.retrieval import context_token_count


def main():
    root = PROJECT_ROOT
    config = load_advisory_config(root, "configs/profiles/advisory_gate_v4.json")
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E5_GRAPH_FAST)
    budget = spec.budget.model_copy(update={"graph_direction": config.graph_direction, "graph_ranking": config.graph_ranking})
    rows = []
    for pair in config.pairs:
        if not pair.pair_id.startswith(("hp002_", "hp003_")):
            continue
        for case in pair.cases:
            index, candidate, _ = build_pair_input(root, pair, case)
            evidence = index.retrieve_context(candidate, mode=spec.retrieval, budget=budget)
            admitted = {item.path for item in evidence}
            callers = index.graph_neighbors(candidate.path, direction="reverse")
            row = {
                "case_id": case.case_id,
                "candidate": candidate.path,
                "callers": callers,
                "admitted_paths": sorted(admitted),
                "context_tokens": context_token_count(evidence),
                "context_budget": budget.total_context_tokens,
            }
            if pair.pair_id.startswith("hp002_"):
                assert any("::delete_api_key_route@" in path for path in admitted & set(callers))
            else:
                helpers = tuple(
                    index.documents[path]
                    for path in index.graph_neighbors(candidate.path, direction="forward")
                    if path in admitted and any(
                        definition.rsplit(".", 1)[-1] == "get_cmd"
                        for definition in index.documents[path].defines
                    )
                )
                result = analyze_command(index.documents[candidate.path], helpers, entry_boolean_arguments=candidate.entry_boolean_arguments)
                scope = ToolExecutionScope(admitted_paths=frozenset(admitted), candidate_path=candidate.path, subject=candidate_subject(index, candidate), max_observation_tokens=20000)
                flow = trace_dataflow(index, TraceDataflowInput(source_path=candidate.path), scope)
                row["dataflow"] = json.loads(flow.content)
                row.update(command_status=command_status(result), issues=result.issues,
                           unresolved_calls=result.unresolved_calls, sinks=result.sinks)
            assert row["context_tokens"] <= row["context_budget"]
            rows.append(row)
    output = root / "artifacts/heldout_evidence_v4_audit.json"
    output.write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
