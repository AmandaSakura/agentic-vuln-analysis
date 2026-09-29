"""Offline agent acceptance: scripts fill missing data, the tool owns the witness."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelToolCall, ModelUsage
from cv_agent.evaluation.datasets.advisory_source import build_pair_input, require_clean_checkout
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.diagnostics.isolation_read_policy import IsolationReadGrant
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


TOOL = 'run_bounded_execution_witness'


def _observed(messages) -> dict[str, Any]:
    message = next(message for message in reversed(messages) if message.role == 'tool')
    return json.loads(message.content)


def run_scripted_candidate(index, candidate, context: WitnessExecutionContext, *,
                           constructor_parameters: dict[str, Any],
                           precondition_files: dict[str, str], nonce: str,
                           scenario_hypothesis: dict[str, Any] | None = None,
                           hypothesis_sequence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Never inspect a truth label; final script reads delivered typed evidence."""
    normalized_sequence = None
    if hypothesis_sequence is not None:
        if scenario_hypothesis is not None:
            raise ValueError('scripted hypothesis sequence and singular scenario are mutually exclusive')
        if constructor_parameters or precondition_files:
            raise ValueError('scripted hypothesis sequence cannot mix unclassified outer data')
        # ReAct reserves its final two steps for conclusions. No extra model
        # steps, defaults or guessed scene values are introduced by this script.
        if not 1 <= len(hypothesis_sequence) <= FULL_SYSTEM_HARNESS.react_loop.max_steps - 2:
            raise ValueError('scripted hypothesis sequence must fit the original tool-step budget')
        normalized_sequence = [WitnessScenarioHypothesis.model_validate(scene) for scene in hypothesis_sequence]
        semantics = []
        for scene in normalized_sequence:
            data = scene.model_dump(mode='json')
            values = {'input_parameter': data['input_parameter']['value'],
                      **{field: {name: premise['value'] for name, premise in premises.items()}
                         for field, premises in data.items() if field != 'input_parameter'}}
            semantics.append(json.dumps(values, sort_keys=True, separators=(',', ':'), allow_nan=False))
        if len(set(semantics)) != len(semantics):
            raise ValueError('scripted scenes must change semantic values, not only classifications or rationales')
    empty = ModelReply(model_id='offline-witness-script', tool_calls=(ModelToolCall(
        call_id='discover-missing-data', name=TOOL,
        arguments={'constructor_parameters': {}, 'precondition_files': {}},
    ),), usage=ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0))

    def fill_missing(messages, tools):
        observed = _observed(messages)
        if observed.get('status') != 'ok':
            raise ValueError('scripted witness preparation was not delivered: ' + str(observed.get('content')))
        payload = json.loads(observed['content'])
        missing = payload.get('missing_constructor_parameters', [])
        if not missing and payload.get('artifact_path'):
            # A fully generated manifest has already executed the validator.
            # Repeating that identical call would be refused by the tool loop.
            return conclude(messages, tools)
        arguments = (
            {'constructor_parameters': {}, 'precondition_files': {},
             'scenario_hypothesis': scenario_hypothesis}
            if scenario_hypothesis is not None else
            {'constructor_parameters': {name: constructor_parameters[name]
                                        for name in missing if name in constructor_parameters},
             'precondition_files': precondition_files}
        )
        return ModelReply(model_id='offline-witness-script', tool_calls=(ModelToolCall(
            call_id='supply-constructor-layout', name=TOOL,
            arguments=arguments,
        ),), usage=ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0))

    def conclude(messages, tools):
        observed = _observed(messages)
        confirmed = (observed.get('validation_status') == 'CONFIRMED'
                     and observed.get('status') == 'ok')
        citation = observed.get('citation_id') if observed.get('status') == 'ok' else None
        result = {'expert':'scan', 'label':'VULNERABLE' if confirmed else 'ABSTAIN',
                  'confidence':.9 if confirmed else 0.,
                  'validation_status':'CONFIRMED' if confirmed else 'UNRESOLVED',
                  'evidence_ids':[citation] if citation else [],
                  'supporting_observation_ids':[citation] if confirmed and citation else [],
                  'rationale':'Use only the delivered candidate-bound witness; literal or missing proof requires abstention.'}
        return ModelReply(model_id='offline-witness-script', content=json.dumps(result),
                          usage=ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0))

    if normalized_sequence is None:
        replies = (empty, fill_missing, *([conclude] * (FULL_SYSTEM_HARNESS.react_loop.max_steps - 2)))
    else:
        position = 0
        def scene_reply(scene, number):
            return ModelReply(model_id='offline-witness-script', tool_calls=(ModelToolCall(
                call_id=f'explicit-scene-{number}', name=TOOL, arguments={
                    'constructor_parameters': {}, 'precondition_files': {},
                    'scenario_hypothesis': scene.model_dump(mode='json'),
                }),), usage=ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0))
        def advance(messages, tools):
            nonlocal position
            observed = _observed(messages)
            if observed.get('status') != 'ok':
                raise ValueError('scripted scene response was not delivered: ' + str(observed.get('content')))
            if observed.get('validation_status') == 'CONFIRMED' or position + 1 == len(normalized_sequence):
                return conclude(messages, tools)
            position += 1
            return scene_reply(normalized_sequence[position], position)
        replies = (scene_reply(normalized_sequence[0], 0), *([advance] * len(normalized_sequence)),
                   *([conclude] * (FULL_SYSTEM_HARNESS.react_loop.max_steps - len(normalized_sequence) - 1)))
    model = ScriptedChatModel(replies)
    registry = ToolRegistry(full_agent_tools(
        index, witness_contexts={candidate.repository_id: context},
        witness_nonce_factory=lambda: nonce,
    ), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    verdict = AgenticPipeline(index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE,
                             models={'scan':model}, tools=registry).run(candidate)
    witness_attempts = []
    for vote in verdict.votes:
        for step in vote.trace:
            if step.observation.tool != TOOL:
                continue
            payload = (json.loads(step.observation.content)
                       if step.observation.status == 'ok' else
                       {'detail': step.observation.content})
            full_payload = step.observation.metadata.get('witness_full_response', payload)
            reference = payload.get('classified_scenario_ref')
            reference_matches_call = None
            if reference is not None:
                proposal = step.tool_call.arguments.get('scenario_hypothesis')
                reference_matches_call = (
                    proposal is not None and reference.get('arguments') == '/scenario_hypothesis'
                    and WitnessScenarioHypothesis.model_validate(proposal).digest() == reference.get('sha256')
                    and full_payload.get('scenario_sha256') == reference.get('sha256')
                )
            witness_attempts.append({
                'validation_status': step.observation.validation_status,
                'tool_status': step.observation.status,
                'witness_attempted': step.observation.metadata.get('witness_attempted', False),
                'delivered_payload': payload,
                'observation_token_count': step.observation.metadata.get('observation_token_count', 0),
                'observation_truncated': step.observation.metadata.get('observation_truncated', False),
                'classified_scenario_ref_matches_call': reference_matches_call,
                **{key: full_payload[key] for key in (
                    'raw_status', 'gaps', 'scenario_origin', 'scenario_sha256', 'premises', 'scope_note',
                    'original_subject', 'execution_subject', 'scenario_verification', 'artifact_path', 'detail',
                    'classification_status', 'entry_adapter',
                ) if key in full_payload},
            })
    return {
        'verdict':verdict.model_dump(mode='json'), 'live_model_requests':0,
        'scripted_model_calls':len(model.requests), 'claim_eligible':False,
        'witness_attempts': witness_attempts,
        'semantic_hypothesis_count': len(normalized_sequence) if normalized_sequence is not None else None,
        'requests':[{'messages':[message.model_dump(mode='json') for message in messages],
                     'tools':list(tools)} for messages, tools in model.requests],
    }


def run_pair(root: Path, configuration: Path, output: Path) -> Path:
    settings = json.loads(configuration.read_text())
    config = load_advisory_config(root, settings['selection_profile'],
                                  dataset_path=settings['dataset'])
    if config.claim_eligible:
        raise ValueError('offline witness acceptance requires declared development data')
    output.mkdir(parents=True, exist_ok=False)
    grants_path = root/settings['read_grants']
    grant_bytes = grants_path.read_bytes()
    grants = tuple(IsolationReadGrant.model_validate(item) for item in json.loads(grant_bytes))
    resources = WitnessResourceProfile.model_validate_json((root/settings['resource_profile']).read_text())
    nonce = uuid4().hex
    rows = []
    scenario_hypothesis = settings.get('scenario_hypothesis')
    hypothesis_sequence = settings.get('hypothesis_sequence')
    scenario_mode = settings.get('scenario_mode', 'dataset_provided')
    if scenario_mode not in {'dataset_provided', 'model_proposed'}:
        raise ValueError('offline scenario mode must name its actual provenance')
    if scenario_hypothesis is not None and hypothesis_sequence is not None:
        raise ValueError('offline profile cannot specify both singular and sequence hypotheses')
    if (scenario_mode == 'model_proposed') != (scenario_hypothesis is not None or hypothesis_sequence is not None):
        raise ValueError('model-proposed offline controls require an explicit scripted hypothesis')
    for selected in settings['cases']:
        matches = [(pair,case) for pair in config.pairs for case in pair.cases
                   if case.case_id == selected['case_id']]
        if len(matches) != 1:
            raise ValueError('offline selection must identify one development snapshot')
        pair, case = matches[0]
        if pair.property_id != 'command-execution':
            raise ValueError('offline witness accepts only declared command candidates')
        require_clean_checkout(root/case.checkout, case.commit)
        # Both detector identities are neutral. Labels remain evaluation-private.
        neutral = case.model_copy(update={'case_id':'neutral-entry'})
        # Remove both subject premises and editorial retrieval hints. The
        # supplied script remains an oracle control of the execution contract.
        index, candidate, _ = build_pair_input(
            root, pair, neutral, include_scenario_assumptions=scenario_mode == 'dataset_provided',
            include_scoped_operation=scenario_mode == 'dataset_provided',
            advisory_text=settings.get('advisory_text'),
        )
        context = WitnessExecutionContext(
            checkout_root=(root/case.checkout).resolve(),
            python_executable=root/selected['python_executable'],
            import_root=pair.python_import_root or '.', resource_profile=resources,
            read_grants=grants, runtime_root=(output/'shared-runtime').resolve(),
            response_mode=settings.get('response_mode', 'full'),
            dataset_scenario=(WitnessScenarioHypothesis.model_validate(settings['dataset_scenario'])
                              if scenario_mode == 'dataset_provided' and 'dataset_scenario' in settings
                              else None),
        )
        try:
            result = run_scripted_candidate(index,candidate,context,
                constructor_parameters=settings['constructor_parameters'],
                precondition_files=settings['precondition_files'], nonce=nonce,
                scenario_hypothesis=scenario_hypothesis, hypothesis_sequence=hypothesis_sequence)
        except Exception as error:
            (output/(selected['case_id']+'-error.json')).write_text(json.dumps({
                'evaluation_case_id': selected['case_id'], 'live_model_requests': 0, 'claim_eligible': False,
                'error_type': type(error).__name__, 'error': str(error),
            }, indent=2)+'\n')
            raise
        row = {'evaluation_case_id':selected['case_id'], 'scenario_origin':scenario_mode,
               'scenario_proposer':'offline_script' if scenario_hypothesis is not None or hypothesis_sequence is not None else 'dataset',
               **result}
        rows.append(row)
        (output/(selected['case_id']+'.json')).write_text(json.dumps(row,indent=2)+'\n')
    summary = {'live_model_requests':0,'claim_eligible':False,'rows':rows,
               'read_policy_sha256':hashlib.sha256(grant_bytes).hexdigest(),
               'resource_profile':resources.model_dump(mode='json'),
               'scenario_origin':scenario_mode,
               'scenario_proposer':'offline_script' if scenario_hypothesis is not None or hypothesis_sequence is not None else 'dataset',
               'autonomous_scenario_discovery_measured':False,
               'manifest_origin':'system_ast',
               'model_supplement_fields':['constructor_parameters','precondition_files','scenario_hypothesis']}
    (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configuration',type=Path)
    parser.add_argument('output',type=Path)
    args = parser.parse_args()
    print(run_pair(PROJECT_ROOT,args.configuration,args.output))


if __name__ == '__main__':
    main()
