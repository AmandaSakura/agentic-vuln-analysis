from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict

from .consensus import QuorumPolicy, SingleExpertPolicy
from .experts import EXPERTS
from .harness import OWASP_HARNESS, SystemHarness
from .retrieval import RepositoryIndex, context_token_count
from .types import Candidate, Evidence, ExpertVote, SystemVersion, Verdict


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    system: SystemVersion


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
        self.system_spec: SystemHarness = OWASP_HARNESS.system_spec(config.system)
        self.graph = self._build_graph()

    def _build_graph(self):
        builder = StateGraph(WorkflowState)
        builder.add_node("make_plan", self._plan)
        builder.add_node("retrieve", self._retrieve)
        builder.add_node("run_scan", self._run_scan)
        builder.add_node("run_taint", self._run_taint)
        builder.add_node("try_fast", self._try_fast)
        builder.add_node("run_verify", self._run_verify)
        builder.add_node("adjudicate", self._adjudicate)
        builder.add_edge(START, "retrieve")
        builder.add_edge("retrieve", "make_plan")
        builder.add_edge("make_plan", "run_scan")
        builder.add_conditional_edges(
            "run_scan",
            self._route_after_scan,
            {"single": "adjudicate", "multi": "run_taint"},
        )
        builder.add_conditional_edges(
            "run_taint",
            self._route_after_taint,
            {"slow": "run_verify", "fast_candidate": "try_fast"},
        )
        builder.add_conditional_edges(
            "try_fast",
            self._route_after_fast,
            {"done": END, "continue": "run_verify"},
        )
        builder.add_edge("run_verify", "adjudicate")
        builder.add_edge("adjudicate", END)
        return builder.compile()

    def _plan(self, state: WorkflowState) -> dict:
        plan = list(self.system_spec.expert_order)
        if "verify" in plan:
            authz = EXPERTS["authz"]
            verifier = "authz" if authz.applies(state["evidence"]) else "flow"
            plan[plan.index("verify")] = verifier
        return {"plan": plan}

    def _retrieve(self, state: WorkflowState) -> dict:
        candidate = state["candidate"]
        evidence = self.index.retrieve_context(
            candidate,
            mode=self.system_spec.retrieval,
            budget=self.system_spec.budget,
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

    def _run_verify(self, state: WorkflowState) -> dict:
        if len(state["plan"]) < 3:
            raise RuntimeError("multi-expert workflow has no planned verifier")
        return self._run_expert(state, state["plan"][2])

    def _route_after_scan(self, state: WorkflowState) -> str:
        return "single" if self.system_spec.full_review_policy == "single" else "multi"

    def _route_after_taint(self, state: WorkflowState) -> str:
        if self.system_spec.early_quorum_after == len(state["votes"]):
            return "fast_candidate"
        return "slow"

    def _try_fast(self, state: WorkflowState) -> dict:
        verdict = QuorumPolicy(
            fast_enabled=True,
            quorum=self.system_spec.quorum,
            fast_confidence=self.system_spec.fast_score,
        ).try_fast(state["votes"])
        if verdict is not None:
            verdict = verdict.model_copy(
                update={"context_token_count": state["context_token_count"]}
            )
        return {"verdict": verdict}

    @staticmethod
    def _route_after_fast(state: WorkflowState) -> str:
        return "done" if state["verdict"] is not None else "continue"

    def _adjudicate(self, state: WorkflowState) -> dict:
        if self.system_spec.full_review_policy == "single":
            verdict = SingleExpertPolicy().decide(state["votes"])
        else:
            # V5 reaches this node only when the two-vote early quorum failed;
            # after the third expert it uses the same full-review policy as V4.
            verdict = QuorumPolicy(
                fast_enabled=False,
                quorum=self.system_spec.quorum,
                fast_confidence=self.system_spec.fast_score,
            ).decide(state["votes"])
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
