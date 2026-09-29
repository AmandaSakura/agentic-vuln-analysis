"""Declarative validation-tool assembly and public registry factories."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from functools import partial

from cv_agent.tools.registry import AgentTool, ToolExecutionScope
from cv_agent.tools.repository import repository_tools
from cv_agent.domain.evidence import ToolObservation, ValidationStatus, ValidationSubject
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext, WitnessSupplement
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import FrozenModel
from cv_agent.tools.validation.authorization import compare_guard, guards, routes, semantic_matches
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.comparison import compare_versions
from cv_agent.tools.validation.dataflow import trace_dataflow
from cv_agent.tools.validation.fixtures import fixture, loopback
from cv_agent.tools.validation.models import (
    CaseInput,
    CommandConstructionInput,
    CompareGuardInput,
    FindReferencesInput,
    FixtureCapability,
    FixtureCase,
    LoopbackCase,
    PathInput,
    SourceFlowInput,
    TraceDataflowInput,
)
from cv_agent.tools.validation.patterns import PRINCIPAL_PATTERN, RESOURCE_PATTERN, SANITIZER_RULES, SINK_RULES, SOURCE_RULES, pattern_tool, references, static_check
from cv_agent.tools.validation.permissions import permission_mode
from cv_agent.tools.validation.probes import concrete_eval_probe
from cv_agent.tools.validation.bounded_witness import BoundedWitnessService, TOOL_NAME as WITNESS_TOOL


def _json_tool(
    name: str,
    description: str,
    input_model: type[FrozenModel],
    handler: Callable[[FrozenModel, ToolExecutionScope], ToolObservation],
    *, available: bool = True,
    validation_statuses: tuple[ValidationStatus, ...] = (),
    fixture_capabilities: tuple[FixtureCapability, ...] = (),
    candidate_witness_supports: Callable[[ValidationSubject], bool] | None = None,
) -> AgentTool:
    return AgentTool(
        name=name,
        description=description,
        input_model=input_model,
        handler=handler,
        content_type="json",
        available=available,
        validation_statuses=validation_statuses,
        fixture_capabilities=fixture_capabilities,
        candidate_witness_supports=candidate_witness_supports,
    )


def validation_tools(
    index: RepositoryIndex,
    *,
    fixed_index: RepositoryIndex | None = None,
    paired_paths: Mapping[str, str] | None = None,
    fixture_cases: Iterable[FixtureCase] = (),
    loopback_cases: Iterable[LoopbackCase] = (),
    witness_contexts: Mapping[str, WitnessExecutionContext] | None = None,
    witness_nonce_factory: Callable[[], str] | None = None,
) -> tuple[AgentTool, ...]:
    paired = dict(paired_paths or {})
    fixture_list = tuple(fixture_cases)
    loopback_list = tuple(loopback_cases)
    fixtures = {case.case_id: case for case in fixture_list}
    loopbacks = {case.case_id: case for case in loopback_list}
    if len(fixtures) != len(fixture_list):
        raise ValueError("fixture cases must have unique ids")
    if len(loopbacks) != len(loopback_list):
        raise ValueError("loopback cases must have unique ids")

    capabilities = tuple(
        FixtureCapability(
            case_id=case.case_id,
            property_id=case.proof_scope.property_id
            if case.proof_scope
            else (case.subject.property_id if case.subject else None),
            coverage=case.proof_scope.coverage if case.proof_scope else None,
            method=case.proof_scope.method if case.proof_scope else None,
            supported_statuses=case.proof_scope.supported_statuses
            if case.proof_scope
            else (),
            subject=case.subject,
            proof_scope=case.proof_scope,
        )
        for case in fixture_list
    )
    witness_service = BoundedWitnessService(index, witness_contexts or {},
                                           nonce_factory=witness_nonce_factory)

    return (
        _json_tool(
            WITNESS_TOOL,
            ('Build a source-bound command witness from this candidate and the system runtime. '
             'Supply constructor_parameters={} and precondition_files={} first; fill only '
             'reported missing constructor parameters using JSON data. The system owns all '
             'source, probe, control, command recorder and isolation settings. Actual expansion '
             'with all runtime obligations and benign control can return CONFIRMED; literal or '
             'incomplete observations stay UNRESOLVED and never prove SAFE. Input class: the '
             'caller can create and supply an existing local directory with shell metacharacters '
             'in its name. When no candidate scenario is declared, propose scenario_hypothesis: '
             'input_parameter and optional entry_boolean_arguments, entry_condition_assumptions, '
             'entry_value_assumptions, constructor_parameters and precondition_files; every premise '
             'uses {value, classification, rationale}, with classification attacker_controlled_input, '
             'deployment_configuration or environment_condition. The input parameter must be '
             'attacker_controlled_input. Keep both outer maps empty with a proposed scenario. '
             'These are hypotheses measured at runtime; report their source and classifications '
             'with any CONFIRMED result. Remote reachability remains unestablished.'),
            WitnessSupplement,
            witness_service.handle,
            available=bool(witness_contexts),
            validation_statuses=(ValidationStatus.CONFIRMED,),
            candidate_witness_supports=witness_service.supports,
        ),
        _json_tool(
            'find_references',
            'Find admitted definitions and call references for one symbol.',
            FindReferencesInput,
            partial(references, index),
        ),
        _json_tool(
            'run_static_check',
            'Run deterministic sink rules on one admitted code span.',
            PathInput,
            partial(static_check, index),
        ),
        _json_tool(
            'run_fixture_test',
            f'Run one project-registered bounded fixture by id. Registered case IDs: {json.dumps(sorted(fixtures))}',
            CaseInput,
            partial(fixture, fixtures),
            available=bool(fixtures),
            validation_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
            fixture_capabilities=capabilities,
        ),
        _json_tool(
            'find_sources',
            'Find untrusted-input sources in one admitted code span.',
            PathInput,
            pattern_tool(index, 'find_sources', SOURCE_RULES),
        ),
        _json_tool(
            'find_sinks',
            'Find security-sensitive sinks in one admitted code span.',
            PathInput,
            pattern_tool(index, 'find_sinks', SINK_RULES),
        ),
        _json_tool(
            'trace_dataflow',
            (
                'Trace possible tainted values from the candidate entry through admitted call-graph '
                'paths. Set sink_category to select the relevant flow when multiple sink types '
                'share the candidate line. MAY_REACH is static evidence, always UNRESOLVED validation, not exploit '
                'confirmation.'
            ),
            TraceDataflowInput,
            partial(trace_dataflow, index),
        ),
        _json_tool(
            'probe_python_eval',
            (
                'Independently probe request input reaching eval using two concrete inputs in a '
                'bounded Python function-slice interpreter. Use the candidate entry as source_path. '
                'Candidate confirmation requires request/req in the declared input_parameters; '
                'the probe cannot infer external control from a parameter name. '
                'Does not execute repository code or prove application exploitability. Unsupported '
                'syntax and no witness mean UNRESOLVED, not SAFE.'
            ),
            SourceFlowInput,
            partial(concrete_eval_probe, index),
            available=any((doc.language == 'python' and doc.adapter_tier == 'ast' for doc in index.documents.values())),
            validation_statuses=(ValidationStatus.CONFIRMED,),
        ),
        _json_tool(
            'validate_permission_mode',
            (
                'Validate literal os.chmod mode behavior in the candidate span. CONFIRMED means the '
                'bounded sequence ends others-writable; REFUTED means it ends non-others-writable. '
                'Ambiguous branches, shadowing, multiple targets and temporal exposure remain '
                'UNRESOLVED.'
            ),
            PathInput,
            partial(permission_mode, index),
            available=any(('os.chmod' in doc.text for doc in index.documents.values())),
            validation_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
        ),
        _json_tool(
            'inspect_command_construction',
            (
                'Inspect admitted command-construction callees for parameter interpolation with or '
                'without shell quoting. The result remains UNRESOLVED validation and supplies '
                'supporting or counter-evidence for command-injection judgments.'
            ),
            CommandConstructionInput,
            partial(command_construction, index),
            available=any((
                'get_cmd' in doc.text
                or any(keyword in doc.text for keyword in ('subprocess', 'os.system', 'os.popen'))
                for doc in index.documents.values()
            )),
        ),
        _json_tool(
            'find_sanitizers',
            'Find sanitizer or validation operations in one admitted span.',
            PathInput,
            pattern_tool(index, 'find_sanitizers', SANITIZER_RULES),
        ),
        _json_tool(
            'compare_vulnerable_and_fixed',
            (
                'Compare one admitted span with its registered fixed pair. Source differences '
                'support hypotheses but remain UNRESOLVED validation.'
            ),
            PathInput,
            partial(compare_versions, index, fixed_index, paired),
            available=bool(fixed_index and paired),
        ),
        _json_tool(
            'get_routes',
            'Read structured and inferred route declarations for one admitted span.',
            PathInput,
            partial(routes, index),
        ),
        _json_tool(
            'get_guards',
            'Read structured and inferred authorization guards for one admitted span.',
            PathInput,
            partial(guards, index),
        ),
        _json_tool(
            'inspect_principal',
            'Inspect principal identity evidence in one admitted span.',
            PathInput,
            semantic_matches(index, 'inspect_principal', PRINCIPAL_PATTERN, 'principals'),
        ),
        _json_tool(
            'inspect_resource_scope',
            'Inspect resource and tenant scope evidence in one admitted span.',
            PathInput,
            semantic_matches(index, 'inspect_resource_scope', RESOURCE_PATTERN, 'resources'),
        ),
        _json_tool(
            'compare_route_and_service_guard',
            'Compare reachable route and service authorization enforcement.',
            CompareGuardInput,
            partial(compare_guard, index),
        ),
        _json_tool(
            'run_loopback_http_case',
            f'Run one project-registered HTTP case on an ephemeral loopback server. Registered case IDs: {json.dumps(sorted(loopbacks))}',
            CaseInput,
            partial(loopback, loopbacks),
            available=bool(loopbacks),
            validation_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
        ),
    )


def full_agent_tools(
    index: RepositoryIndex,
    *,
    fixed_index: RepositoryIndex | None = None,
    paired_paths: Mapping[str, str] | None = None,
    fixture_cases: Iterable[FixtureCase] = (),
    loopback_cases: Iterable[LoopbackCase] = (),
    witness_contexts: Mapping[str, WitnessExecutionContext] | None = None,
    witness_nonce_factory: Callable[[], str] | None = None,
) -> tuple[AgentTool, ...]:
    return (
        *repository_tools(index),
        *validation_tools(
            index,
            fixed_index=fixed_index,
            paired_paths=paired_paths,
            fixture_cases=fixture_cases,
            loopback_cases=loopback_cases,
            witness_contexts=witness_contexts,
            witness_nonce_factory=witness_nonce_factory,
        ),
    )
