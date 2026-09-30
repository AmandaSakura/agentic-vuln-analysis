"""Offline E4 witness sharing and fixed-ballot E5 replay, with actual producers."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from cv_agent.agents.validator_accounting import account_validator_observations
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.review import ValidationPlan, ValidationSubtask
from cv_agent.evaluation.datasets.advisory_source import build_pair_input, require_clean_checkout
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.runtime.witness.isolation_policy import IsolationReadGrant
from cv_agent.evaluation.metrics import replay_fast_prefix
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


TOOL = "run_bounded_execution_witness"


def _embedded(message: str, marker: str):
    return json.JSONDecoder().raw_decode(message.split("\n" + marker, 1)[1].lstrip())[0]


def _observations(messages):
    observations = []
    for message in messages:
        if message.role == "tool":
            observations.append(json.loads(message.content))
        elif message.role == "user" and "Completed dependencies and prior own tasks:" in message.content:
            dependencies = _embedded(message.content, "Completed dependencies and prior own tasks:")
            observations.extend(json.loads(observation) for dependency in dependencies
                                for observation in dependency["observations"] if observation)
    return observations


class _ExpertScript:
    def __init__(self, role, path, scenario, *, literal_safe=False):
        self.role, self.path, self.scenario = role, path, scenario
        self.literal_safe = literal_safe
        self.proposed_literal_safe = False

    def __call__(self, messages, tools):
        own_tools = [message for message in messages if message.role == "tool"]
        if not own_tools:
            assigned = _embedded(messages[1].content, "Assigned validation subtasks:")
            name = assigned[0]["allowed_validator"] if assigned else "read_span"
            arguments = ({"constructor_parameters": {}, "precondition_files": {}, "scenario_hypothesis": self.scenario}
                         if name == TOOL else {"source_path" if name == "inspect_command_construction" else "path": self.path})
            return ModelReply(model_id="offline-multiexpert", tool_calls=(ModelToolCall(
                call_id=self.role + "-assigned", name=name, arguments=arguments),))
        observations = _observations(messages)
        witness = [item for item in observations if item.get("tool") == TOOL and item.get("status") == "ok"]
        confirmed = next((item for item in reversed(witness) if item.get("validation_status") == "CONFIRMED"), None)
        rejected = any(message.role == "user" and "Validation error:" in message.content for message in messages)
        literal = next((item for item in reversed(witness)
                        if json.loads(item["content"]).get("raw_status") == "LITERAL_OBSERVED"), None)
        bad_safe = (self.role == "taint" and self.literal_safe and literal is not None and not rejected)
        self.proposed_literal_safe |= bad_safe
        proof = confirmed if self.role != "authz" else None
        label = "SAFE" if bad_safe else "VULNERABLE" if proof is not None else "ABSTAIN"
        selected = literal if bad_safe else proof if proof is not None else witness[-1] if witness else None
        citation = selected.get("citation_id") if selected is not None else None
        return ModelReply(model_id="offline-multiexpert", content=json.dumps({
            "expert": self.role, "label": label, "confidence": .95 if proof is not None else 0.,
            "validation_status": "CONFIRMED" if proof is not None else "UNRESOLVED",
            "evidence_ids": [citation] if citation else [],
            "supporting_observation_ids": [citation] if citation and label != "ABSTAIN" else [],
            "unresolved_observation_ids": [citation] if citation and label == "ABSTAIN" else [],
            "rationale": "Interpret only the delivered candidate-bound witness; incomplete or literal results require abstention.",
        }))


def run_scripted_multiexpert_candidate(index, candidate, context, *, scenario_hypothesis: dict[str, Any],
                                      nonce: str, attempt_literal_safe: bool = False) -> dict[str, Any]:
    """Use the ordinary E4 tasks, budgets and admission, never expected labels."""
    if context.response_mode != "compact" or context.dataset_scenario is not None:
        raise ValueError("multi-expert controls require trusted compact model-proposed scenes")
    if candidate.input_parameters or candidate.entry_boolean_arguments or candidate.entry_condition_assumptions or candidate.entry_value_assumptions:
        raise ValueError("scripted scene remains separate from the original empty candidate")
    plan = ValidationPlan(candidate_id=candidate.candidate_id, vulnerability_hypotheses=("command property",),
        rationale="A witness producer and independent expert interpretations of its observation.", subtasks=(
            ValidationSubtask(task_id="witness",expert="scan",allowed_validator=TOOL,
                objective="Execute the classified bounded witness.",success_condition="Record the concrete result."),
            ValidationSubtask(task_id="construction-scan",expert="scan",allowed_validator="inspect_command_construction",
                dependencies=("witness",),objective="Inspect the candidate command construction.",success_condition="Record construction facts."),
            ValidationSubtask(task_id="construction-taint",expert="taint",allowed_validator="inspect_command_construction",
                dependencies=("witness",),objective="Interpret candidate dataflow and the witness.",success_condition="Record construction facts.")))
    scripts = {role: _ExpertScript(role,candidate.path,scenario_hypothesis,literal_safe=attempt_literal_safe)
               for role in ("scan","taint","authz")}
    models = {role: ScriptedChatModel([script] * (FULL_SYSTEM_HARNESS.react_loop.max_steps * 2))
              for role,script in scripts.items()}
    models["planner"] = ScriptedChatModel([
        ModelReply(model_id="offline-multiexpert",tool_calls=(ModelToolCall(call_id="planner-read",name="read_span",
            arguments={"path":candidate.path}),)),
        ModelReply(model_id="offline-multiexpert",content=plan.model_dump_json()),
    ])
    registry = ToolRegistry(full_agent_tools(index,witness_contexts={candidate.repository_id:context},
        witness_nonce_factory=lambda:nonce),max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    scopes = []
    class MeasuredPipeline(AgenticPipeline):
        def _engine(self,role,state):
            engine=super()._engine(role,state)
            scopes.append({"role":role,"max_observation_tokens":engine.scope.max_observation_tokens,
                           "initial_observed_tokens":engine.scope.observed_tokens})
            return engine
    verdict=MeasuredPipeline(index=index,system=AgentSystemVersion.E4_GRAPH_MULTI,models=models,tools=registry).run(candidate)
    accounting=account_validator_observations(verdict.votes,verdict.task_executions,
        candidate_subject(index,candidate),verdict.planner.plan)
    attempts=[]
    for execution_ordinal,execution in enumerate(verdict.task_executions,1):
        for step_ordinal,step in enumerate(execution.vote.trace,1):
            observation=step.observation
            if observation.tool != TOOL:
                continue
            payload=json.loads(observation.content)
            full=observation.metadata.get("witness_full_response",payload)
            attempts.append({"producer_execution_ordinal":execution_ordinal,"producer_step_ordinal":step_ordinal,
                "witness_attempted":observation.metadata.get("witness_attempted",False),
                "tool_status":observation.status,"validation_status":observation.validation_status,
                "observation_token_count":observation.metadata["observation_token_count"],
                "observation_truncated":observation.metadata["observation_truncated"],
                "delivered_payload":payload,"complete_server_response":full,
                "raw_scenario_hypothesis":step.tool_call.arguments.get("scenario_hypothesis")})
    serialized=verdict.model_dump(mode="json")
    return {"system":"E4","dataset_role":"development","claim_eligible":False,
        "scenario_origin":"developer_scripted","autonomous_scenario_discovery_measured":False,
        "verdict":serialized,"validator_observation_origins":accounting.origins,"scopes":scopes,
        "material_votes_sharing_validator_observation":accounting.material_votes_sharing_validator_observation,
        "independent_validator_observations":accounting.independent_validator_observations,
        "accounting_note":"Distinct producer observations are counted, not statistical independence. Quorum can use two experts interpreting one witness.",
        "live_model_requests":0,"scripted_model_calls":sum(len(model.requests) for model in models.values()),
        "executed_witness_attempts":sum(item["witness_attempted"] for item in attempts),"witness_attempts":attempts,
        "e5_fixed_ballot_replay":replay_fast_prefix(serialized),"e5_additional_witness_executions":0,
        "literal_safe_proposed":scripts["taint"].proposed_literal_safe,
        "requests":{role:[{"messages":[message.model_dump(mode="json") for message in messages],"tools":definitions}
                          for messages,definitions in model.requests] for role,model in models.items()}}


def run_pair(root:Path,configuration:Path,output:Path)->Path:
    controls=json.loads(configuration.read_text())
    settings=json.loads((root/controls["source_configuration"]).read_text())
    if controls["response_mode"] != "compact" or settings["scenario_mode"] != "model_proposed":
        raise ValueError("K4 requires explicit compact oracle controls, not a live experiment")
    advisory=load_advisory_config(root,settings["selection_profile"],dataset_path=settings["dataset"])
    if advisory.claim_eligible:
        raise ValueError("K4 developer controls cannot support held-out claims")
    grants_path=root/settings["read_grants"]
    grants=tuple(IsolationReadGrant.model_validate(item) for item in json.loads(grants_path.read_text()))
    resources=WitnessResourceProfile.model_validate_json((root/settings["resource_profile"]).read_text())
    output.mkdir(parents=True,exist_ok=False)
    nonce=uuid4().hex
    rows=[]
    for selected in settings["cases"]:
        matches=[(pair,case) for pair in advisory.pairs for case in pair.cases if case.case_id==selected["case_id"]]
        if len(matches)!=1:
            raise ValueError("K4 selection must identify one declared development snapshot")
        pair,case=matches[0]
        require_clean_checkout(root/case.checkout,case.commit)
        neutral=case.model_copy(update={"case_id":"neutral-entry"})
        index,candidate,_=build_pair_input(root,pair,neutral,include_scenario_assumptions=False,
            include_scoped_operation=False,advisory_text=settings["advisory_text"])
        context=WitnessExecutionContext(checkout_root=(root/case.checkout).resolve(),
            python_executable=root/selected["python_executable"],import_root=pair.python_import_root or ".",
            resource_profile=resources,read_grants=grants,runtime_root=(output/"shared-runtime").resolve(),response_mode="compact")
        row={"evaluation_case_id":selected["case_id"],**run_scripted_multiexpert_candidate(index,candidate,context,
            scenario_hypothesis=settings["scenario_hypothesis"],nonce=nonce)}
        rows.append(row)
        (output/(selected["case_id"]+".json")).write_text(json.dumps(row,indent=2)+"\n")
    summary={"live_model_requests":0,"dataset_role":"development","claim_eligible":False,
        "scenario_origin":"developer_scripted","rows":rows,
        "read_policy_sha256":hashlib.sha256(grants_path.read_bytes()).hexdigest(),
        "note":"E5 is a fixed-ballot counterfactual, not measured independent latency or evidence."}
    (output/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration",type=Path)
    parser.add_argument("output",type=Path)
    args=parser.parse_args()
    print(run_pair(PROJECT_ROOT,args.configuration,args.output))


if __name__=="__main__":
    main()
