from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.identity import candidate_subject
from cv_agent.agents import planning
from cv_agent.domain.review import AgentExpertVote, AgenticVerdict, PlannerResult, ValidationPlan, ValidationSubtask, ValidationTaskExecution
from cv_agent.domain.chat import ModelUsage
from cv_agent.agents.voting import QuorumPolicy, SingleExpertPolicy
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentRuntimeMode, AgentSystemHarness, AgentSystemVersion, ExpertAgentHarness
from cv_agent.runtime.model import ChatModel, trusted_runtime_mode
from cv_agent.agents.react import ReActEngine, run_expert, run_planner
from cv_agent.retrieval import RepositoryIndex, prompt_token_upper_bound as context_text_token_count, fit_text_to_serialized_context
from cv_agent.domain.types import Candidate, Evidence, ExpertVote


class AgentWorkflowState(TypedDict):
    candidate: Candidate
    evidence: list[Evidence]
    context_prompt: str
    context_token_count: int
    planner: PlannerResult | None
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
    ) -> None:
        self.index = index
        self.system_spec: AgentSystemHarness = FULL_SYSTEM_HARNESS.system_spec(system)
        budget = self.system_spec.budget.model_validate({
            **self.system_spec.budget.model_dump(), "graph_direction": graph_direction,
            "graph_ranking": graph_ranking,
        })
        self.system_spec = self.system_spec.model_copy(update={"budget": budget})
        self.models = dict(models)
        self.tools = tools
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
        retrieved = self.index.retrieve_context(
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
        return {
            "evidence": evidence,
            "context_prompt": context_prompt,
            "context_token_count": token_count,
        }

    def _engine(self, role: str, state: AgentWorkflowState) -> ReActEngine:
        previous = [item.vote for item in state["task_executions"] if item.vote.expert == role]
        selected = self._next_task(state)
        task = selected[1] if selected is not None and role != "planner" else None
        visible = self._visible_executions(state, role, task)
        observation_ceiling = FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
        if task is not None and state["planner"] is not None:
            task_count = sum(item.expert == role for item in state["planner"].plan.subtasks)
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
                observed_tokens=sum(vote.tool_observation_token_count for vote in previous),
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
                plan, state["candidate"], state["evidence"]
            ),
        )
        return {"planner": result}

    def _planner_prompt(self, state: AgentWorkflowState) -> str:
        return planning.render_planner_prompt(
            harness=FULL_SYSTEM_HARNESS,
            system_spec=self.system_spec,
            tools=self.tools,
            candidate=state["candidate"],
            evidence=state["evidence"],
        )

    def _validate_plan(
        self,
        plan: ValidationPlan,
        candidate: Candidate,
        evidence: list[Evidence] | None = None,
    ) -> None:
        planning.validate_plan(
            plan,
            harness=FULL_SYSTEM_HARNESS,
            system_spec=self.system_spec,
            tools=self.tools,
            candidate=candidate,
            evidence=evidence,
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
        planner = state["planner"]
        if planner is None:
            return []
        tasks = {item.task_id: item for item in planner.plan.subtasks}
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
        vote = run_expert(
            self._engine(name, state),
            expert=spec.expert,
            system_prompt=spec.mandate,
            task_prompt=self._expert_prompt(state, name, task),
            allowed_tools=self._allowed_task_tools(name, task),
            required_validators=(task.allowed_validator,) if task is not None else (),
        )
        executions = [*state["task_executions"], ValidationTaskExecution(
            task_id=task.task_id if task else None, vote=vote,
        )]
        completed = {item.task_id for item in executions if item.task_id is not None}
        plan = state["planner"]
        remaining_own = [
            item for item in plan.plan.subtasks
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

    def _run_taint(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "taint")

    def _run_authz(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "authz")

    def _next_task(self, state: AgentWorkflowState) -> tuple[str, ValidationSubtask | None] | None:
        plan = state["planner"]
        tasks = plan.plan.subtasks if plan is not None else ()
        completed = {item.task_id for item in state["task_executions"] if item.task_id is not None}
        completed_experts = {vote.expert for vote in state["votes"]}
        ready: list[tuple[str, ValidationSubtask | None]] = [
            (task.expert, task) for task in tasks
            if task.task_id not in completed and set(task.dependencies) <= completed
        ]
        assigned = {task.expert for task in tasks}
        ready.extend(
            (name, None) for name in self.system_spec.expert_order
            if name not in assigned and name not in completed_experts
        )
        if ready:
            return min(ready, key=lambda item: self.system_spec.expert_order.index(item[0]))
        if len(completed) != len(tasks):
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
        usage = ModelUsage(
            input_tokens=_sum_optional([item.input_tokens for item in usage_items]),
            output_tokens=_sum_optional([item.output_tokens for item in usage_items]),
            total_tokens=_sum_optional([item.total_tokens for item in usage_items]),
        )
        return AgenticVerdict(
            runtime_mode=self.runtime_mode,
            label=label,
            confidence=confidence,
            path=path,
            rationale=rationale,
            planner=planner,
            votes=tuple(state["votes"]),
            task_executions=tuple(state["task_executions"]),
            model_calls=model_calls,
            tool_calls=tool_calls,
            usage=usage,
            retrieval_context_token_count=state["context_token_count"],
            tool_observation_token_count=tool_observation_token_count,
            context_token_count=(
                state["context_token_count"] + tool_observation_token_count
            ),
        )

    def _try_fast(self, state: AgentWorkflowState) -> dict[str, object]:
        verdict = QuorumPolicy(
            fast_enabled=True,
            quorum=self.system_spec.quorum,
            fast_confidence=self.system_spec.fast_confidence,
        ).try_fast(self._consensus_votes(state["votes"]))
        if verdict is None:
            return {"verdict": None, "fast_checked": True}
        return {
            "fast_checked": True,
            "verdict": self._result(
                state,
                label=verdict.label,
                confidence=verdict.confidence,
                path="fast",
                rationale=verdict.rationale,
            )
        }

    def _adjudicate(self, state: AgentWorkflowState) -> dict[str, object]:
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
                rationale=verdict.rationale,
            )
        }

    def run(self, candidate: Candidate) -> AgenticVerdict:
        result = self.graph.invoke(
            {
                "candidate": candidate,
                "evidence": [],
                "context_prompt": "",
                "context_token_count": 0,
                "planner": None,
                "votes": [],
                "verdict": None,
                "task_executions": [],
                "fast_checked": False,
            }
        )
        verdict = result["verdict"]
        if verdict is None:
            raise RuntimeError("agentic workflow completed without a verdict")
        return verdict
