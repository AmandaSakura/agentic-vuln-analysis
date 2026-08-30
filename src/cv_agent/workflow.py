from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field

from .consensus import QuorumPolicy, SingleExpertPolicy
from .experts import EXPERTS
from .retrieval import RepositoryIndex, context_token_count, limit_evidence_context
from .types import Candidate, Evidence, ExpertVote, SystemVersion, Verdict


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    system: SystemVersion
    top_k: int = Field(default=6, ge=1, le=50)
    graph_hops: int = Field(default=2, ge=0, le=6)
    context_token_budget: int = Field(default=2000, ge=32, le=100_000)


class WorkflowState(TypedDict):
    candidate: Candidate
    plan: list[str]
    evidence: list[Evidence]
    context_token_count: int
    votes: list[ExpertVote]
    verdict: Verdict | None


class AgentPipeline:
    def __init__(self, index: RepositoryIndex, config: PipelineConfig) -> None:
        self.index = index
        self.config = config
        self.graph = self._build_graph()

    def _build_graph(self):
        builder = StateGraph(WorkflowState)
        builder.add_node("make_plan", self._plan)
        builder.add_node("retrieve", self._retrieve)
        builder.add_node("run_scan", self._run_scan)
        builder.add_node("run_taint", self._run_taint)
        builder.add_node("try_fast", self._try_fast)
        builder.add_node("run_authz", self._run_authz)
        builder.add_node("adjudicate", self._adjudicate)
        builder.add_edge(START, "make_plan")
        builder.add_edge("make_plan", "retrieve")
        builder.add_edge("retrieve", "run_scan")
        builder.add_conditional_edges(
            "run_scan",
            self._route_after_scan,
            {"single": "adjudicate", "multi": "run_taint"},
        )
        builder.add_conditional_edges(
            "run_taint",
            self._route_after_taint,
            {"slow": "run_authz", "fast_candidate": "try_fast"},
        )
        builder.add_conditional_edges(
            "try_fast",
            self._route_after_fast,
            {"done": END, "continue": "run_authz"},
        )
        builder.add_edge("run_authz", "adjudicate")
        builder.add_edge("adjudicate", END)
        return builder.compile()

    def _plan(self, state: WorkflowState) -> dict:
        if self.config.system in {SystemVersion.V1_LOCAL_SINGLE, SystemVersion.V2_TEXT_SINGLE, SystemVersion.V3_GRAPH_SINGLE}:
            experts = ["scan"]
        else:
            experts = ["scan", "taint", "authz"]
        return {"plan": experts}

    def _retrieve(self, state: WorkflowState) -> dict:
        candidate = state["candidate"]
        if self.config.system == SystemVersion.V1_LOCAL_SINGLE:
            evidence = self.index.local(candidate)
        elif self.config.system == SystemVersion.V2_TEXT_SINGLE:
            evidence = self.index.text_search(candidate.query, top_k=self.config.top_k)
        else:
            evidence = self.index.graph_search(candidate, top_k=self.config.top_k, max_hops=self.config.graph_hops)
        evidence = limit_evidence_context(
            evidence,
            token_budget=self.config.context_token_budget,
        )
        return {
            "evidence": evidence,
            "context_token_count": context_token_count(evidence),
        }

    @staticmethod
    def _run_expert(state: WorkflowState, name: str) -> dict:
        vote = EXPERTS[name].evaluate(state["candidate"], state["evidence"])
        return {"votes": [*state["votes"], vote]}

    def _run_scan(self, state: WorkflowState) -> dict:
        return self._run_expert(state, "scan")

    def _run_taint(self, state: WorkflowState) -> dict:
        return self._run_expert(state, "taint")

    def _run_authz(self, state: WorkflowState) -> dict:
        return self._run_expert(state, "authz")

    def _route_after_scan(self, state: WorkflowState) -> str:
        if self.config.system in {
            SystemVersion.V1_LOCAL_SINGLE,
            SystemVersion.V2_TEXT_SINGLE,
            SystemVersion.V3_GRAPH_SINGLE,
        }:
            return "single"
        return "multi"

    def _route_after_taint(self, state: WorkflowState) -> str:
        if self.config.system == SystemVersion.V5_GRAPH_FAST_SLOW:
            return "fast_candidate"
        return "slow"

    @staticmethod
    def _try_fast(state: WorkflowState) -> dict:
        verdict = QuorumPolicy(fast_enabled=True).try_fast(state["votes"])
        if verdict is not None:
            verdict = verdict.model_copy(
                update={"context_token_count": state["context_token_count"]}
            )
        return {"verdict": verdict}

    @staticmethod
    def _route_after_fast(state: WorkflowState) -> str:
        return "done" if state["verdict"] is not None else "continue"

    def _adjudicate(self, state: WorkflowState) -> dict:
        if self.config.system in {SystemVersion.V1_LOCAL_SINGLE, SystemVersion.V2_TEXT_SINGLE, SystemVersion.V3_GRAPH_SINGLE}:
            verdict = SingleExpertPolicy().decide(state["votes"])
        else:
            # V5 reaches this node only when the two-vote early quorum failed;
            # after the third expert it uses the same full-review policy as V4.
            verdict = QuorumPolicy(fast_enabled=False).decide(state["votes"])
        return {
            "verdict": verdict.model_copy(
                update={"context_token_count": state["context_token_count"]}
            )
        }

    def run(self, candidate: Candidate) -> Verdict:
        result = self.graph.invoke(
            {
                "candidate": candidate,
                "plan": [],
                "evidence": [],
                "context_token_count": 0,
                "votes": [],
                "verdict": None,
            }
        )
        verdict = result["verdict"]
        if verdict is None:
            raise RuntimeError("workflow completed without a verdict")
        return verdict
