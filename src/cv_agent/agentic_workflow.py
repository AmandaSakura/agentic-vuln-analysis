from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .agent_tools import ToolExecutionScope, ToolRegistry
from .agent_types import (
    AgentExpertVote,
    AgenticVerdict,
    ModelUsage,
    PlannerResult,
)
from .consensus import QuorumPolicy, SingleExpertPolicy
from .harness import (
    FULL_SYSTEM_HARNESS,
    AgentRuntimeMode,
    AgentSystemHarness,
    AgentSystemVersion,
    ExpertAgentHarness,
)
from .model_runtime import ChatModel, trusted_runtime_mode
from .react_engine import ReActEngine, run_expert, run_planner
from .retrieval import (
    RepositoryIndex,
    context_text_token_count,
    fit_text_to_serialized_context,
)
from .types import Candidate, Evidence, ExpertVote


class AgentWorkflowState(TypedDict):
    candidate: Candidate
    evidence: list[Evidence]
    context_prompt: str
    context_token_count: int
    planner: PlannerResult | None
    votes: list[AgentExpertVote]
    verdict: AgenticVerdict | None


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
            render=lambda text, item=item: _render_context_prompt(
                candidate,
                [*selected, item.model_copy(update={"text": text})],
            ),
        )
        if fitted is None:
            continue
        text, payload, token_count = fitted
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
    ) -> None:
        self.index = index
        self.system_spec: AgentSystemHarness = FULL_SYSTEM_HARNESS.system_spec(system)
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
        builder.add_edge("plan", "scan")
        builder.add_conditional_edges(
            "scan",
            self._route_after_scan,
            {"single": "adjudicate", "multi": "taint"},
        )
        builder.add_conditional_edges(
            "taint",
            self._route_after_taint,
            {"fast_candidate": "try_fast", "full": "authz"},
        )
        builder.add_conditional_edges(
            "try_fast",
            self._route_after_fast,
            {"done": END, "continue": "authz"},
        )
        builder.add_edge("authz", "adjudicate")
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
            retrieved,
            token_budget=self.system_spec.budget.total_context_tokens,
        )
        return {
            "evidence": evidence,
            "context_prompt": context_prompt,
            "context_token_count": token_count,
        }

    def _engine(self, role: str, state: AgentWorkflowState) -> ReActEngine:
        return ReActEngine(
            model=self.models[role],
            tools=self.tools,
            scope=ToolExecutionScope(
                admitted_paths=frozenset(item.path for item in state["evidence"]),
                max_observation_tokens=(
                    FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
                ),
            ),
            harness=FULL_SYSTEM_HARNESS.react_loop,
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
        allowed_tools = self._repository_tool_names()
        if not allowed_tools:
            raise ValueError("planner has no registered repository tools")
        result = run_planner(
            self._engine("planner", state),
            system_prompt=(
                "You are a vulnerability-validation planner. Decompose the candidate into "
                "ordered, evidence-seeking subtasks. Use only declared experts and validators."
            ),
            task_prompt=state["context_prompt"],
            allowed_tools=allowed_tools,
            max_subtasks=FULL_SYSTEM_HARNESS.planner_max_subtasks,
        )
        if result.plan.candidate_id != state["candidate"].candidate_id:
            raise ValueError("planner output carries the wrong candidate identity")
        scheduled = set(self.system_spec.expert_order)
        validators = set(FULL_SYSTEM_HARNESS.validation.validators)
        for task in result.plan.subtasks:
            if task.expert not in scheduled:
                raise ValueError(
                    f"planner assigned task {task.task_id} to unscheduled expert {task.expert}"
                )
            if task.allowed_validator not in validators:
                raise ValueError(
                    f"planner selected unregistered validator {task.allowed_validator}"
                )
            expert_tools = set(self._expert_spec(task.expert).tools)
            if task.allowed_validator not in expert_tools:
                raise ValueError(
                    f"planner assigned validator {task.allowed_validator} to expert "
                    f"{task.expert}, which cannot execute it"
                )
        return {"planner": result}

    @staticmethod
    def _expert_spec(name: str) -> ExpertAgentHarness:
        matches = [expert for expert in FULL_SYSTEM_HARNESS.experts if expert.expert == name]
        if len(matches) != 1:
            raise ValueError(f"full-system Harness lacks expert {name}")
        return matches[0]

    def _allowed_expert_tools(self, name: str) -> tuple[str, ...]:
        spec = self._expert_spec(name)
        allowed = tuple(tool for tool in spec.tools if tool in self.tools.names)
        if not allowed:
            raise ValueError(f"expert {name} has no registered tools")
        return allowed

    def _expert_prompt(self, state: AgentWorkflowState, name: str) -> str:
        planner = state["planner"]
        tasks = (
            [
                task.model_dump(mode="json")
                for task in planner.plan.subtasks
                if task.expert == name
            ]
            if planner is not None
            else []
        )
        task_payload = json.dumps(
            tasks,
            sort_keys=True,
            separators=(",", ":"),
        )
        return (
            f"{state['context_prompt']}\n"
            f"Assigned validation subtasks: {task_payload}"
        )

    def _run_named_expert(self, state: AgentWorkflowState, name: str) -> dict[str, object]:
        spec = self._expert_spec(name)
        vote = run_expert(
            self._engine(name, state),
            expert=spec.expert,
            system_prompt=spec.mandate,
            task_prompt=self._expert_prompt(state, name),
            allowed_tools=self._allowed_expert_tools(name),
        )
        return {"votes": [*state["votes"], vote]}

    def _run_scan(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "scan")

    def _run_taint(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "taint")

    def _run_authz(self, state: AgentWorkflowState) -> dict[str, object]:
        return self._run_named_expert(state, "authz")

    def _route_after_scan(self, state: AgentWorkflowState) -> str:
        return "single" if self.system_spec.full_review_policy == "single" else "multi"

    def _route_after_taint(self, state: AgentWorkflowState) -> str:
        if self.system_spec.early_quorum_after == len(state["votes"]):
            return "fast_candidate"
        return "full"

    @staticmethod
    def _consensus_votes(votes: list[AgentExpertVote]) -> list[ExpertVote]:
        return [
            ExpertVote(
                expert=vote.expert,
                label=vote.label,
                confidence=vote.confidence,
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
        usage_items = [vote.usage for vote in state["votes"]]
        model_calls = sum(vote.model_calls for vote in state["votes"])
        tool_calls = sum(vote.tool_calls for vote in state["votes"])
        tool_observation_token_count = sum(
            vote.tool_observation_token_count for vote in state["votes"]
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
            return {"verdict": None}
        return {
            "verdict": self._result(
                state,
                label=verdict.label,
                confidence=verdict.confidence,
                path="fast",
                rationale=verdict.rationale,
            )
        }

    @staticmethod
    def _route_after_fast(state: AgentWorkflowState) -> str:
        return "done" if state["verdict"] is not None else "continue"

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
            }
        )
        verdict = result["verdict"]
        if verdict is None:
            raise RuntimeError("agentic workflow completed without a verdict")
        return verdict
