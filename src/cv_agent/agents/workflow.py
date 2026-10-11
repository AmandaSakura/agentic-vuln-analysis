from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import Field

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.identity import candidate_subject
from cv_agent.agents import planning
from cv_agent.domain.review import ApplicableAgenticVerdict, AgentExpertVote, AgenticVerdict, BlockedValidationTask, PlannerResult, RetrievalAdmissionAudit, RoutedAgenticVerdict, RoutedApplicableAgenticVerdict, RoutingResult, SourceAdmissionRecord, ValidationPlan, ValidationSubtask, ValidationTaskExecution
from cv_agent.domain.chat import ModelUsage
from cv_agent.agents.voting import QuorumPolicy, SingleExpertPolicy
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentRuntimeMode, AgentSystemHarness, AgentSystemVersion, ExpertAgentHarness
from cv_agent.runtime.model import ChatModel, OpenAICompatibleChatModel, trusted_runtime_mode
from cv_agent.agents.react import ReActEngine, run_expert, run_planner
from cv_agent.agents.evidence_policy import revalidate_global_ballots, validator_observation_completed
from cv_agent.agents.validator_accounting import account_validator_observations
from cv_agent.retrieval import RepositoryIndex, prompt_token_upper_bound as context_text_token_count, fit_text_to_serialized_context
from cv_agent.domain.types import Candidate, Evidence, ExpertVote, FrozenModel


# At most eight task nodes, three unassigned expert nodes, retrieve/plan,
# one fast check and adjudication, plus completion accounting in LangGraph.
GRAPH_TRANSITION_LIMIT = FULL_SYSTEM_HARNESS.planner_max_subtasks + len(FULL_SYSTEM_HARNESS.experts) + 5


class PlannerPatch(FrozenModel):
    """Only the missing tasks; dependencies may name retained routing tasks."""

    candidate_id: str
    subtasks: tuple[ValidationSubtask, ...] = Field(min_length=1)
    rationale: str


class AgentWorkflowState(TypedDict):
    candidate: Candidate
    evidence: list[Evidence]
    context_prompt: str
    context_token_count: int
    admission_records: tuple[SourceAdmissionRecord, ...]
    admission_subject_digest: str | None
    planner: PlannerResult | None
    routing: RoutingResult | None
    votes: list[AgentExpertVote]
    verdict: AgenticVerdict | None
    task_executions: list[ValidationTaskExecution]
    fast_checked: bool


def _sum_optional(values: list[int | None]) -> int | None:
    if any(value is None for value in values):
        return None
    return sum(value for value in values if value is not None)


def _render_context_prompt(
    candidate: Candidate,
    evidence: list[Evidence],
) -> str:
    return json.dumps(
        {
            "candidate": {
                "candidate_id": candidate.candidate_id,
                "line": candidate.line,
                "path": candidate.path,
                "repository_id": candidate.repository_id,
                **({"analysis_scope": candidate.analysis_scope} if candidate.analysis_scope is not None else {}),
                **({"property_id": candidate.property_id} if candidate.property_id is not None else {}),
            },
            "retrieved_code": [
                {
                    "evidence_id": item.evidence_id,
                    "graph_distance": item.graph_distance,
                    "path": item.path,
                    "retrieval": item.retrieval,
                    "text": item.text,
                }
                for item in evidence
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _bounded_context_prompt(
    candidate: Candidate,
    evidence: list[Evidence],
    *,
    token_budget: int,
) -> tuple[list[Evidence], str, int]:
    selected: list[Evidence] = []
    payload = _render_context_prompt(candidate, selected)
    token_count = context_text_token_count(payload)
    if token_count > token_budget:
        raise ValueError("candidate descriptor exceeds the model context budget")

    for item in evidence:
        fitted = fit_text_to_serialized_context(
            item.text,
            token_budget=token_budget,
            count_tokens=context_text_token_count,
            render=lambda text, item=item: _render_context_prompt(
                candidate,
                [*selected, item.model_copy(update={"text": text})],
            ),
        )
        if fitted is None:
            continue
        text, payload, token_count = fitted
        if not text and item.text:
            continue
        selected.append(item.model_copy(update={"text": text}))
    return selected, payload, token_count


class AgenticPipeline:
    def __init__(
        self,
        *,
        index: RepositoryIndex,
        system: AgentSystemVersion,
        models: Mapping[str, ChatModel],
        tools: ToolRegistry,
        graph_direction: Literal["forward", "reverse", "both"] = "forward",
        graph_ranking: Literal["lexical", "distance"] = "lexical",
        routing_model: ChatModel | None = None,
        routing_min_probability: float = 0.85,
        routing_mode: Literal['off', 'shadow', 'active'] = 'active',
        routing_max_source_observation_tokens: int = 4096,
        routing_observer: Callable[[dict], None] | None = None,
        retrieval_observer: Callable[[dict], None] | None = None,
        routing_spec_version: int = 2,
        system_name: str | None = None,
        expert_policy: Literal['fixed', 'applicable_v1'] = 'fixed',
    ) -> None:
        self.index = index
        self.system_name = system_name or system.value
        self.system_spec: AgentSystemHarness = FULL_SYSTEM_HARNESS.system_spec(system)
        budget = self.system_spec.budget.model_validate({
            **self.system_spec.budget.model_dump(), "graph_direction": graph_direction,
            "graph_ranking": graph_ranking,
        })
        self.system_spec = self.system_spec.model_copy(update={"budget": budget})
        self.models = dict(models)
        self.tools = tools
        self.expert_policy = expert_policy
        if expert_policy not in {'fixed', 'applicable_v1'}:
            raise ValueError('expert policy must be fixed or applicable_v1')
        required_roles = set(self.system_spec.expert_order)
        if self.system_spec.planner_enabled:
            required_roles.add("planner")
        missing = sorted(required_roles - set(self.models))
        if missing:
            raise ValueError(f"agentic pipeline lacks model roles: {missing}")
        runtime_modes = {trusted_runtime_mode(self.models[role]) for role in required_roles}
        if len(runtime_modes) != 1:
            raise ValueError("agentic pipeline cannot mix scripted and live model roles")
        self.runtime_mode = next(iter(runtime_modes))
        self.routing_model = routing_model
        self.routing_min_probability = routing_min_probability
        self.routing_mode = routing_mode
        self.routing_max_source_observation_tokens = routing_max_source_observation_tokens
        self.routing_observer = routing_observer
        self.retrieval_observer = retrieval_observer
        self.routing_spec_version = routing_spec_version
        if not 0 <= routing_min_probability <= 1:
            raise ValueError('routing probability threshold must be in [0, 1]')
        if routing_mode not in {'off', 'shadow', 'active'}:
            raise ValueError('invalid routing mode')
        if routing_model is not None:
            if system != AgentSystemVersion.E4_GRAPH_MULTI:
                raise ValueError('Jev routing currently requires the E4 full-review policy')
            if trusted_runtime_mode(routing_model) != self.runtime_mode:
                raise ValueError('routing and expert models must share runtime provenance')
            if isinstance(routing_model, OpenAICompatibleChatModel) and routing_model.protocol != 'jev-systemone':
                raise ValueError('live routing requires the Jev protocol')
        if self.runtime_mode == AgentRuntimeMode.LIVE:
            required_tools = set(FULL_SYSTEM_HARNESS.validation.validators)
            for name in self.system_spec.expert_order:
                required_tools.update(self._expert_spec(name).tools)
            if self.system_spec.planner_enabled:
                required_tools.update(
                    {"search_symbols", "read_span", "get_callers", "get_callees"}
                )
            missing_tools = sorted(required_tools - set(self.tools.names))
            if missing_tools:
                raise ValueError(
                    "live agentic pipeline lacks required Harness tools: "
                    f"{missing_tools}"
                )
        self.graph = self._build_graph()

    def _build_graph(self):
        builder = StateGraph(AgentWorkflowState)
        builder.add_node("retrieve", self._retrieve)
        builder.add_node("plan", self._plan)
        builder.add_node("scan", self._run_scan)
        builder.add_node("taint", self._run_taint)
        builder.add_node("try_fast", self._try_fast)
        builder.add_node("authz", self._run_authz)
        builder.add_node("adjudicate", self._adjudicate)
        builder.add_edge(START, "retrieve")
        builder.add_edge("retrieve", "plan")
        routes = {name: name for name in ("scan", "taint", "authz", "try_fast", "adjudicate")}
        routes["done"] = END
        for node in ("plan", "scan", "taint", "authz", "try_fast"):
            builder.add_conditional_edges(node, self._route_next, routes)
        builder.add_edge("adjudicate", END)
        return builder.compile()

    def _retrieve(self, state: AgentWorkflowState) -> dict[str, object]:
        retrieved, records = self.index.retrieve_context_with_admission(
            state["candidate"],
            mode=self.system_spec.retrieval,
            budget=self.system_spec.budget,
        )
        evidence, context_prompt, token_count = _bounded_context_prompt(
            state["candidate"],
            [
                *_bounded_context_prompt(
                    state["candidate"],
                    [item for item in retrieved if item.retrieval == "local"],
                    token_budget=self.system_spec.budget.base_context_tokens,
                )[0],
                *[item for item in retrieved if item.retrieval != "local"],
            ],
            token_budget=self.system_spec.budget.total_context_tokens,
        )
        candidate = state["candidate"]
        marginal_costs: dict[str, int] = {}
        prior_count = context_text_token_count(_render_context_prompt(candidate, []))
        for position, item in enumerate(evidence, start=1):
            next_count = context_text_token_count(
                _render_context_prompt(candidate, evidence[:position])
            )
            marginal_costs[item.path] = next_count - prior_count
            prior_count = next_count
        admission_records = tuple(
            SourceAdmissionRecord.model_validate({
                **record,
                "serialized_token_cost": marginal_costs.get(str(record["path"]), 0)
                if record["status"] == "admitted" else 0,
                "status": "skipped"
                if record["status"] == "admitted" and record["path"] not in marginal_costs
                else record["status"],
                "reason": "serialized_context_budget"
                if record["status"] == "admitted" and record["path"] not in marginal_costs
                else record["reason"],
            })
            for record in records
        )
        subject_digest = candidate_subject(self.index, candidate).source_digest
        if self.retrieval_observer is not None:
            self.retrieval_observer({
                "event": "retrieval_admission",
                "subject_digest": subject_digest,
                "admitted_paths": [item.path for item in evidence],
                "context_token_count": token_count,
                "admission_records": [item.model_dump(mode="json") for item in admission_records],
            })
        return {
            "evidence": evidence,
            "context_prompt": context_prompt,
            "context_token_count": token_count,
            "admission_records": admission_records,
            "admission_subject_digest": subject_digest,
        }

    def _engine(self, role: str, state: AgentWorkflowState) -> ReActEngine:
        previous = [item.vote for item in state["task_executions"] if item.vote.expert == role]
        selected = self._next_task(state)
        task = selected[1] if selected is not None and role != "planner" else None
        visible = self._visible_executions(state, role, task)
        observation_ceiling = FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
        plan = self._active_plan(state)
        if task is not None and plan is not None:
            task_count = sum(item.expert == role for item in plan.subtasks)
            # Reserve each later subtask's share of this expert's fixed budget.
            # Unspent earlier shares remain available to subsequent subtasks.
            observation_ceiling = observation_ceiling * (len(previous) + 1) // task_count
        return ReActEngine(
            model=self.models[role],
            tools=self.tools,
            scope=ToolExecutionScope(
                admitted_paths=frozenset(item.path for item in state["evidence"]),
                initial_evidence_ids=frozenset(item.evidence_id for item in state["evidence"]),
                candidate_path=state["candidate"].path,
                subject=candidate_subject(self.index, state["candidate"]),
                fixture_case_id=task.fixture_case_id if task is not None else None,
                observed_tokens=(state['routing'].tool_observation_token_count
                                 if role == 'planner' and state.get('routing') is not None
                                 and state['routing'].mode == 'active'
                                 else sum(vote.tool_observation_token_count for vote in previous)),
                max_observation_tokens=observation_ceiling,
            ),
            harness=FULL_SYSTEM_HARNESS.react_loop,
            prior_trace=tuple(step for item in visible for step in item.vote.trace),
            citation_prefix=f"{role}/tool",
            citation_offset=sum(vote.tool_calls for vote in previous),
        )

    def _repository_tool_names(self) -> tuple[str, ...]:
        preferred = (
            "search_symbols",
            "read_span",
            "get_callers",
            "get_callees",
        )
        return tuple(name for name in preferred if name in self.tools.names)

    def _plan(self, state: AgentWorkflowState) -> dict[str, object]:
        if not self.system_spec.planner_enabled:
            return {"planner": None}
        if self.system_name == "E4_RULE_V1":
            from cv_agent.agents.plan_policy import compose_plan, required_tasks, validate_plan_policy
            subject = candidate_subject(self.index, state["candidate"])
            locked = required_tasks(state["candidate"], state["evidence"], self.tools, self.system_spec, subject=subject)
            proposed = None
            origins = ()
            gap = "No deterministic policy obligation applies to this candidate."
            if locked:
                proposed, origins = compose_plan(
                    state["candidate"].candidate_id, locked, {},
                    expert_order=self.system_spec.expert_order,
                )
                try:
                    validate_plan_policy(
                        proposed,
                        harness=FULL_SYSTEM_HARNESS,
                        system_spec=self.system_spec,
                        tools=self.tools,
                        candidate=state["candidate"],
                        evidence=state["evidence"],
                        subject=subject,
                    )
                except ValueError as error:
                    gap = f"Deterministic policy plan is incomplete: {error}"
                else:
                    gap = "rule_v1_deterministic"
            routing = RoutingResult(
                runtime_mode=self.runtime_mode,
                spec_version=3,
                mode="off",
                plan=proposed if gap == "rule_v1_deterministic" else None,
                proposed_plan=proposed,
                locked_tasks=locked,
                task_origins=origins,
                model_calls=0,
                tool_calls=0,
                tool_observation_token_count=0,
                usage=ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0),
                escalation_reason=gap,
                fallback_scope=None if gap == "rule_v1_deterministic" else "full_plan",
            )
            if self.routing_observer is not None:
                self.routing_observer({'event': 'routing_decision', 'routing': routing.model_dump(mode='json')})
            if routing.plan is not None:
                return {'planner': None, 'routing': routing}
            state = {**state, 'routing': routing}
        routing = None
        if self.routing_model is not None:
            from cv_agent.agents.routing import route_plan
            routing = route_plan(
                model=self.routing_model, index=self.index, candidate=state['candidate'],
                evidence=state['evidence'], tools=self.tools, system_spec=self.system_spec,
                min_probability=self.routing_min_probability, mode=self.routing_mode,
                max_source_observation_tokens=self.routing_max_source_observation_tokens,
                spec_version=self.routing_spec_version,
            )
            if self.routing_observer is not None:
                self.routing_observer({'event': 'routing_decision', 'routing': routing.model_dump(mode='json')})
            if routing.plan is not None:
                return {'planner': None, 'routing': routing}
            state = {**state, 'routing': routing}
        else:
            routing = state.get('routing')
        if routing is not None and routing.mode == 'active' and routing.spec_version == 3:
            accepted_choices, retained, allowed_roles = self._routing_patch_scope(
                routing, state['candidate'].candidate_id
            )
            if retained:
                return self._plan_patch(state, routing, accepted_choices, retained, allowed_roles)
        allowed_tools = tuple(
            name for name in ("read_span",) if name in self.tools.available_names
        )
        if not allowed_tools:
            raise ValueError("planner has no registered repository tools")
        result = run_planner(
            self._engine("planner", state),
            system_prompt=(
                "You are a vulnerability-validation planner. Decompose the candidate into "
                "ordered, evidence-seeking subtasks. Use only declared experts and validators."
            ),
            task_prompt=self._planner_prompt(state),
            allowed_tools=allowed_tools,
            max_subtasks=FULL_SYSTEM_HARNESS.planner_max_subtasks,
            output_validator=lambda plan: self._validate_plan(
                plan, state["candidate"], state["evidence"], state=state
            ),
        )
        if routing is not None and routing.fallback_scope == "patch_subtasks":
            routing = routing.model_copy(update={"fallback_scope": "full_plan"})
        return {"planner": result, 'routing': routing}

    def _routing_patch_scope(
        self, routing: RoutingResult, candidate_id: str
    ) -> tuple[dict[str, str], tuple[ValidationSubtask, ...], tuple[str, ...]]:
        """Keep policy and accepted Jev work; only rejected or unknown choices remain open."""
        from cv_agent.agents.plan_policy import compose_plan

        origins = {origin.task_id: origin for origin in routing.task_origins}
        accepted: dict[str, str] = {}
        if routing.proposed_plan is not None:
            if routing.proposed_plan.candidate_id != candidate_id:
                raise ValueError("routing proposal carries the wrong candidate identity")
            for task in routing.proposed_plan.subtasks:
                origin = origins.get(task.task_id)
                if origin is None or origin.origin != 'jev' or origin.decision_id is None:
                    continue
                decision = routing.decisions.get(task.expert)
                if (
                    decision is not None
                    and decision.decision_id == origin.decision_id
                    and decision.accepted
                    and decision.choice == task.allowed_validator
                    and task.expert not in routing.rejection_reasons
                ):
                    accepted[task.expert] = task.allowed_validator
        retained: tuple[ValidationSubtask, ...] = ()
        if routing.locked_tasks or accepted:
            plan, _ = compose_plan(
                candidate_id,
                routing.locked_tasks, accepted,
                expert_order=self.system_spec.expert_order,
            )
            retained = plan.subtasks
        allowed_roles = tuple(
            role for role in self.system_spec.expert_order
            if role not in accepted and role in routing.decisions
        )
        return accepted, retained, allowed_roles

    def _compose_patch(
        self,
        *,
        patch: PlannerPatch,
        candidate: Candidate,
        evidence: list[Evidence],
        routing: RoutingResult,
        accepted_choices: dict[str, str],
        retained: tuple[ValidationSubtask, ...],
        allowed_roles: tuple[str, ...],
    ):
        from cv_agent.agents.plan_policy import compose_plan, validate_plan_policy

        if patch.candidate_id != candidate.candidate_id:
            raise ValueError("patch candidate identity differs from the routed candidate")
        retained_ids = {task.task_id for task in retained}
        retained_pairs = {(task.expert, task.allowed_validator) for task in retained}
        for task in patch.subtasks:
            if task.task_id in retained_ids or (task.expert, task.allowed_validator) in retained_pairs:
                raise ValueError(f"patch attempted to replace locked task {task.task_id}")
            if task.expert not in allowed_roles:
                raise ValueError(f"patch assigned {task.expert} outside the unresolved routing roles")
        merged, origins = compose_plan(
            candidate.candidate_id, routing.locked_tasks, accepted_choices,
            patch_tasks=patch.subtasks, expert_order=self.system_spec.expert_order,
        )
        validate_plan_policy(
            merged, harness=FULL_SYSTEM_HARNESS, system_spec=self.system_spec,
            tools=self.tools, candidate=candidate, evidence=evidence,
            subject=candidate_subject(self.index, candidate),
        )
        return merged, origins

    def _plan_patch(
        self,
        state: AgentWorkflowState,
        routing: RoutingResult,
        accepted_choices: dict[str, str],
        retained: tuple[ValidationSubtask, ...],
        allowed_roles: tuple[str, ...],
    ) -> dict[str, object]:
        if not allowed_roles or len(retained) >= FULL_SYSTEM_HARNESS.planner_max_subtasks:
            raise ValueError("routing patch has no remaining legal subtask capacity or unresolved role")
        validators = set(FULL_SYSTEM_HARNESS.validation.validators) & set(self.tools.available_names)
        retained_pairs = {(task.expert, task.allowed_validator) for task in retained}
        allowed = {
            role: sorted(
                tool for tool in set(self._expert_spec(role).tools) & validators
                if (role, tool) not in retained_pairs
            )
            for role in allowed_roles
        }
        if not any(allowed.values()):
            raise ValueError("routing patch has no available validator for unresolved roles")
        candidate = state['candidate']
        patch_context = {
            'candidate': {
                'candidate_id': candidate.candidate_id,
                'path': candidate.path,
                'line': candidate.line,
                'property_id': candidate.property_id,
                'analysis_scope': candidate.analysis_scope,
            },
            'unresolved_gap': routing.escalation_reason,
            'locked_tasks': [task.model_dump(mode='json') for task in retained],
            'allowed_patch_validators_by_expert': allowed,
            'maximum_additional_subtasks': FULL_SYSTEM_HARNESS.planner_max_subtasks - len(retained),
            'source_observation': (
                self.tools.prompt_payload(routing.observation)
                if routing.observation is not None else ''
            ),
        }

        def validate_patch(patch: PlannerPatch) -> None:
            self._compose_patch(
                patch=patch, candidate=candidate, evidence=state['evidence'],
                routing=routing, accepted_choices=accepted_choices,
                retained=retained, allowed_roles=allowed_roles,
            )

        run = self._engine('planner', state).run(
            system_prompt=(
                "You repair only unresolved validation subtask choices. All locked tasks "
                "are immutable, including accepted Jev decisions. Return only new tasks; "
                "never repeat, replace, or omit a locked task. You are not casting a vote."
            ),
            task_prompt=(
                "Propose a scoped planner patch using this routing context: "
                + json.dumps(patch_context, sort_keys=True, separators=(',', ':'))
                + "\nDependencies may name locked task IDs. The source observation was already "
                "read by routing; do not reread it. The runtime merges your patch with "
                "locked tasks and validates the complete dependency graph."
            ),
            allowed_tools=(), output_model=PlannerPatch,
            output_validator=validate_patch, require_tool_attempt=False,
        )
        merged, origins = self._compose_patch(
            patch=run.output, candidate=candidate, evidence=state['evidence'],
            routing=routing, accepted_choices=accepted_choices,
            retained=retained, allowed_roles=allowed_roles,
        )
        planner = PlannerResult(
            runtime_mode=self.runtime_mode, plan=merged, trace=run.trace,
            model_ids=run.model_ids, model_calls=run.model_calls,
            tool_calls=run.tool_calls,
            tool_observation_token_count=run.tool_observation_token_count,
            usage=run.usage,
        )
        decisions = {
            role: decision.model_copy(update={
                'applied': True,
                'applied_reason': 'retained_after_patch',
                'action': 'validator',
            }) if role in accepted_choices else decision
            for role, decision in routing.decisions.items()
        }
        routed = routing.model_copy(update={
            'plan': merged, 'task_origins': origins,
            'decisions': decisions, 'fallback_scope': 'patch_subtasks',
        })
        if self.routing_observer is not None:
            self.routing_observer({'event': 'routing_patch_applied', 'routing': routed.model_dump(mode='json')})
        return {'planner': planner, 'routing': routed}

    @staticmethod
    def _active_plan(state: AgentWorkflowState) -> ValidationPlan | None:
        if state['planner'] is not None:
            return state['planner'].plan
        routing = state.get('routing')
        return routing.plan if routing is not None else None

    def _planner_prompt(self, state: AgentWorkflowState) -> str:
        return planning.render_planner_prompt(
            harness=FULL_SYSTEM_HARNESS,
            system_spec=self.system_spec,
            tools=self.tools,
            candidate=state["candidate"],
            evidence=state["evidence"],
            subject=candidate_subject(self.index, state["candidate"]),
        )

    def _validate_plan(
        self,
        plan: ValidationPlan,
        candidate: Candidate,
        evidence: list[Evidence] | None = None,
        state: AgentWorkflowState | None = None,
    ) -> None:
        subject = candidate_subject(self.index, candidate)
        planning.validate_plan(
            plan,
            harness=FULL_SYSTEM_HARNESS,
            system_spec=self.system_spec,
            tools=self.tools,
            candidate=candidate,
            evidence=evidence,
            subject=subject,
        )

    @staticmethod
    def _expert_spec(name: str) -> ExpertAgentHarness:
        return planning.expert_spec(FULL_SYSTEM_HARNESS, name)

    def _allowed_expert_tools(self, name: str) -> tuple[str, ...]:
        spec = self._expert_spec(name)
        allowed = tuple(tool for tool in spec.tools if tool in self.tools.available_names)
        if not allowed:
            raise ValueError(f"expert {name} has no registered tools")
        return allowed

    def _allowed_task_tools(
        self,
        name: str,
        task: ValidationSubtask | None,
    ) -> tuple[str, ...]:
        allowed = self._allowed_expert_tools(name)
        if task is None:
            return allowed
        if task.allowed_validator not in allowed:
            raise ValueError(
                f"task {task.task_id} selected unavailable validator {task.allowed_validator}"
            )
        if task.allowed_validator == "inspect_command_construction":
            focused_tools = {"read_span", "get_callers", "get_callees", task.allowed_validator}
            return tuple(tool for tool in allowed if tool in focused_tools)
        validators = set(FULL_SYSTEM_HARNESS.validation.validators)
        return tuple(tool for tool in allowed
                     if tool == task.allowed_validator or tool not in validators)

    def _visible_executions(
        self, state: AgentWorkflowState, name: str, task: ValidationSubtask | None,
    ) -> list[ValidationTaskExecution]:
        plan = self._active_plan(state)
        if plan is None:
            return []
        tasks = {item.task_id: item for item in plan.subtasks}
        needed = set(task.dependencies if task else ())
        needed.update(
            item.task_id for item in state["task_executions"]
            if item.vote.expert == name and item.task_id is not None
        )
        pending = list(needed)
        while pending:
            for dependency in tasks[pending.pop()].dependencies:
                if dependency not in needed:
                    needed.add(dependency)
                    pending.append(dependency)
        return [item for item in state["task_executions"] if item.task_id in needed]

    def _expert_prompt(
        self, state: AgentWorkflowState, name: str, task: ValidationSubtask | None,
    ) -> str:
        tasks = [task.model_dump(mode="json")] if task is not None else []
        task_payload = json.dumps(
            tasks,
            sort_keys=True,
            separators=(",", ":"),
        )
        dependencies = [
            {
                "task_id": item.task_id,
                "expert": item.vote.expert,
                "validator_completed": item.validator_completed,
                **({"label": item.vote.label,
                    "validation_status": item.vote.validation_status.value,
                    "rationale": item.vote.rationale}
                   if item.vote.expert == name else {}),
                "evidence_ids": item.vote.evidence_ids,
                "observations": [self.tools.prompt_payload(step.observation) for step in item.vote.trace],
            }
            for item in self._visible_executions(state, name, task)
        ]
        return (
            f"{state['context_prompt']}\n"
            f"Assigned validation subtasks: {task_payload}\n"
            f"Completed dependencies and prior own tasks: {json.dumps(dependencies, separators=(',', ':'))}\n"
            "Execute this task's validator, then give your current overall candidate judgment "
            "for your specialty, taking the prior own task results into account. "
            "Peer dependencies supply observations only; derive your own conclusion from "
            "the evidence and the candidate's analysis_scope. "
            "A completed task may remain UNRESOLVED; do not treat completion as validation success."
        )

    def _run_named_expert(self, state: AgentWorkflowState, name: str) -> dict[str, object]:
        selected = self._next_task(state)
        if selected is None or selected[0] != name:
            raise RuntimeError("expert was dispatched without a ready task")
        task = selected[1]
        spec = self._expert_spec(name)
        allowed_tools = self._allowed_task_tools(name, task)
        required_validators = (task.allowed_validator,) if task is not None else ()
        if (
            task is None
            and name == "scan"
            and "run_fixture_test" in allowed_tools
            and self._registered_fixture_matches_candidate(state)
        ):
            # In no-planner systems the scan expert otherwise tends to spend
            # the whole observation budget on static/source reads before trying
            # the stronger candidate-bound fixture. A registered fixture is the
            # concrete validator for this candidate, so make it the implicit
            # first check rather than another optional tool.
            allowed_tools = ("run_fixture_test",)
            required_validators = ("run_fixture_test",)
        elif (task is None and name == "scan"
              and "run_bounded_execution_witness" in allowed_tools
              and self.tools.candidate_witness_available(candidate_subject(self.index, state["candidate"]))):
            # The system builds the manifest. The expert may fill structured
            # missing constructor data in a later call, then cite its proof.
            required_validators = ("run_bounded_execution_witness",)
        vote = run_expert(
            self._engine(name, state),
            expert=spec.expert,
            system_prompt=spec.mandate,
            task_prompt=self._expert_prompt(state, name, task),
            allowed_tools=allowed_tools,
            required_validators=required_validators,
        )
        executions = [*state["task_executions"], ValidationTaskExecution(
            task_id=task.task_id if task else None, vote=vote,
            validator_completed=all(any(
                step.observation.tool == validator
                and validator_observation_completed(step.observation)
                for step in vote.trace
            ) for validator in required_validators),
        )]
        completed = {item.task_id for item in executions if item.task_id is not None}
        plan = self._active_plan(state)
        remaining_own = [
            item for item in plan.subtasks
            if item.expert == name and item.task_id not in completed
        ] if plan else []
        votes = list(state["votes"])
        if not remaining_own:
            own = [item.vote for item in executions if item.vote.expert == name]
            # Only the last, cumulative judgment is a ballot. Repeated tasks do
            # not give one specialist multiple votes in the quorum.
            aggregate = vote.model_copy(update={
                "trace": tuple(step for item in own for step in item.trace),
                "model_ids": tuple(dict.fromkeys(model_id for item in own for model_id in item.model_ids)),
                "model_calls": sum(item.model_calls for item in own),
                "tool_calls": sum(item.tool_calls for item in own),
                "tool_observation_token_count": sum(item.tool_observation_token_count for item in own),
                "usage": ModelUsage(**{
                    key: _sum_optional([getattr(item.usage, key) for item in own])
                    for key in ("input_tokens", "output_tokens", "total_tokens")
                }),
            })
            votes.append(aggregate)
            votes.sort(key=lambda item: self.system_spec.expert_order.index(item.expert))
        return {"votes": votes, "task_executions": executions}

    def _run_scan(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "scan")

    def _registered_fixture_matches_candidate(self, state: AgentWorkflowState) -> bool:
        subject = candidate_subject(self.index, state["candidate"])
        caps = self.tools.candidate_fixture_capabilities(subject)
        return any(cap.case_id == state["candidate"].case_id for cap in caps)

    def _run_taint(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "taint")

    def _run_authz(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "authz")

    def _blocked_tasks(self, state: AgentWorkflowState) -> tuple[BlockedValidationTask, ...]:
        plan = self._active_plan(state)
        executions = {item.task_id: item for item in state["task_executions"] if item.task_id is not None}
        failed = {key for key, item in executions.items() if item.validator_completed is not True}
        blocked = []
        # ValidationPlan guarantees dependency order, so one pass propagates
        # blocking without repeatedly scheduling tasks that cannot run.
        for task in plan.subtasks if plan else ():
            dependencies = tuple(key for key in task.dependencies if key in failed)
            if task.task_id not in executions and dependencies:
                blocked.append(BlockedValidationTask(
                    task_id=task.task_id, expert=task.expert, dependencies=dependencies,
                ))
                failed.add(task.task_id)
        return tuple(blocked)

    def _next_task(self, state: AgentWorkflowState) -> tuple[str, ValidationSubtask | None] | None:
        plan = self._active_plan(state)
        tasks = plan.subtasks if plan is not None else ()
        completed = {item.task_id for item in state["task_executions"] if item.task_id is not None}
        validated = {item.task_id for item in state["task_executions"] if item.validator_completed is True}
        completed_experts = {vote.expert for vote in state["votes"]}
        ready: list[tuple[str, ValidationSubtask | None]] = [
            (task.expert, task) for task in tasks
            if task.task_id not in completed and set(task.dependencies) <= validated
        ]
        assigned = {task.expert for task in tasks}
        for name in self.system_spec.expert_order:
            if name not in assigned and name not in completed_experts:
                if self.expert_policy == "applicable_v1":
                    from cv_agent.agents.applicability import evaluate_expert_applicability_v1
                    verdict = evaluate_expert_applicability_v1(state["candidate"], name, plan=plan)
                    if verdict.status == "not_applicable":
                        continue
                ready.append((name, None))
        if ready:
            return min(ready, key=lambda item: self.system_spec.expert_order.index(item[0]))
        if len(completed) + len(self._blocked_tasks(state)) != len(tasks):
            raise RuntimeError("planner dependencies have no executable task")
        return None

    def _route_next(self, state: AgentWorkflowState) -> str:
        if state["verdict"] is not None:
            return "done"
        prefix = self.system_spec.expert_order[:self.system_spec.early_quorum_after]
        if (
            self.system_spec.early_quorum_after is not None
            and not state["fast_checked"]
            and tuple(vote.expert for vote in state["votes"]) == prefix
        ):
            return "try_fast"
        selected = self._next_task(state)
        return selected[0] if selected is not None else "adjudicate"

    @staticmethod
    def _consensus_votes(votes: list[AgentExpertVote]) -> list[ExpertVote]:
        return [
            ExpertVote(
                expert=vote.expert,
                label=vote.label,
                confidence=vote.confidence,
                validation_status=vote.validation_status.value,
                evidence_ids=vote.evidence_ids,
                rationale=vote.rationale,
            )
            for vote in votes
        ]

    def _result(
        self,
        state: AgentWorkflowState,
        *,
        label: str,
        confidence: float,
        path: str,
        rationale: str,
    ) -> AgenticVerdict:
        planner = state["planner"]
        executed_votes = [item.vote for item in state["task_executions"]]
        usage_items = [vote.usage for vote in executed_votes]
        model_calls = sum(vote.model_calls for vote in executed_votes)
        tool_calls = sum(vote.tool_calls for vote in executed_votes)
        tool_observation_token_count = sum(
            vote.tool_observation_token_count for vote in executed_votes
        )
        if planner is not None:
            usage_items.append(planner.usage)
            model_calls += planner.model_calls
            tool_calls += planner.tool_calls
            tool_observation_token_count += planner.tool_observation_token_count
        routing = state.get('routing')
        if routing is not None:
            usage_items.append(routing.usage)
            model_calls += routing.model_calls
            tool_calls += routing.tool_calls
            tool_observation_token_count += routing.tool_observation_token_count
        usage = ModelUsage(
            input_tokens=_sum_optional([item.input_tokens for item in usage_items]),
            output_tokens=_sum_optional([item.output_tokens for item in usage_items]),
            total_tokens=_sum_optional([item.total_tokens for item in usage_items]),
        )
        extra = {}
        if self.expert_policy == 'applicable_v1':
            extra['skipped_experts'] = self._skipped_experts(state)
            verdict_type = RoutedApplicableAgenticVerdict if routing is not None else ApplicableAgenticVerdict
        else:
            verdict_type = RoutedAgenticVerdict if routing is not None else AgenticVerdict
        proof_accounting = account_validator_observations(
            state["votes"], state["task_executions"],
            candidate_subject(self.index, state["candidate"]), self._active_plan(state),
        )
        return verdict_type(
            runtime_mode=self.runtime_mode,
            label=label,
            confidence=confidence,
            path=path,
            rationale=rationale,
            planner=planner,
            **({'routing': routing} if routing is not None else {}),
            **extra,
            votes=tuple(state["votes"]),
            task_executions=tuple(state["task_executions"]),
            blocked_tasks=self._blocked_tasks(state),
            material_votes_sharing_validator_observation=proof_accounting.material_votes_sharing_validator_observation,
            independent_validator_observations=proof_accounting.independent_validator_observations,
            model_calls=model_calls,
            tool_calls=tool_calls,
            usage=usage,
            retrieval_context_token_count=state["context_token_count"],
            tool_observation_token_count=tool_observation_token_count,
            context_token_count=(
                state["context_token_count"] + tool_observation_token_count
            ),
            retrieval_admission=RetrievalAdmissionAudit(
                subject_digest=state["admission_subject_digest"] or "",
                records=state["admission_records"],
            ),
        )

    def _skipped_experts(self, state: AgentWorkflowState) -> dict[str, str]:
        from cv_agent.agents.applicability import evaluate_expert_applicability_v1

        plan = self._active_plan(state)
        return {
            name: result.reason
            for name in self.system_spec.expert_order
            if (result := evaluate_expert_applicability_v1(
                state['candidate'], name, plan=plan
            )).status == 'not_applicable'
        }

    def _try_fast(self, state: AgentWorkflowState) -> dict[str, object]:
        checked, _ = revalidate_global_ballots(
            state["votes"], state["task_executions"],
            frozenset(item.evidence_id for item in state["evidence"]),
            candidate_subject(self.index, state["candidate"]),
        )
        state = {**state, "votes": checked}
        if self._blocked_tasks(state):
            return {"verdict": None, "fast_checked": True, "votes": checked}
        verdict = QuorumPolicy(
            fast_enabled=True,
            quorum=self.system_spec.quorum,
            fast_confidence=self.system_spec.fast_confidence,
        ).try_fast(self._consensus_votes(state["votes"]))
        if verdict is None:
            return {"verdict": None, "fast_checked": True, "votes": checked}
        return {
            "fast_checked": True,
            "votes": checked,
            "verdict": self._result(
                state,
                label=verdict.label,
                confidence=verdict.confidence,
                path="fast",
                rationale=verdict.rationale,
            )
        }

    def _adjudicate(self, state: AgentWorkflowState) -> dict[str, object]:
        checked, rejected = revalidate_global_ballots(
            state["votes"], state["task_executions"],
            frozenset(item.evidence_id for item in state["evidence"]),
            candidate_subject(self.index, state["candidate"]),
        )
        state = {**state, "votes": checked}
        if self._blocked_tasks(state):
            return {"verdict": self._result(
                state, label="ABSTAIN", confidence=0.0, path="slow",
                rationale="Required validation dependencies did not complete; dependent tasks were blocked.",
            )}
        if self.expert_policy == "applicable_v1" and self.system_spec.full_review_policy == "majority":
            from cv_agent.agents.applicability import evaluate_expert_applicability_v1
            plan = self._active_plan(state)
            applicable = [
                name for name in self.system_spec.expert_order
                if evaluate_expert_applicability_v1(state["candidate"], name, plan=plan).status != "not_applicable"
            ]
            if len(applicable) < self.system_spec.quorum:
                return {"verdict": self._result(
                    state,
                    label="ABSTAIN",
                    confidence=0.0,
                    path="slow",
                    rationale=f"insufficient_applicable_roles: only {len(applicable)} applicable expert(s), quorum requires {self.system_spec.quorum}",
                )}
        votes = self._consensus_votes(state["votes"])
        if self.system_spec.full_review_policy == "single":
            verdict = SingleExpertPolicy().decide(votes)
        else:
            verdict = QuorumPolicy(
                fast_enabled=False,
                quorum=self.system_spec.quorum,
                fast_confidence=self.system_spec.fast_confidence,
            ).decide(votes)
        return {
            "verdict": self._result(
                state,
                label=verdict.label,
                confidence=verdict.confidence,
                path=verdict.path,
                rationale=("global-evidence-v2: " + "; ".join(rejected) + ". " + verdict.rationale
                           if rejected else verdict.rationale),
            )
        }

    def run(self, candidate: Candidate) -> AgenticVerdict:
        if not candidate.property_id or not candidate.property_id.strip():
            raise ValueError("Candidate requires an explicit property_id before workflow execution")
        result = self.graph.invoke(
            {
                "candidate": candidate,
                "evidence": [],
                "context_prompt": "",
                "context_token_count": 0,
                "admission_records": (),
                "admission_subject_digest": None,
                "planner": None,
                "routing": None,
                "votes": [],
                "verdict": None,
                "task_executions": [],
                "fast_checked": False,
            },
            config={"recursion_limit": GRAPH_TRANSITION_LIMIT},
        )
        verdict = result["verdict"]
        if verdict is None:
            raise RuntimeError("agentic workflow completed without a verdict")
        return verdict
