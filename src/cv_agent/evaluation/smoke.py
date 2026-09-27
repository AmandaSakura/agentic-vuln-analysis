"""Non-claim smoke check with a real bounded eval witness and an insufficient quorum."""
from cv_agent.evaluation.quorum_probe import run_probe_case
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion


def run_agentic_smoke() -> dict[str, object]:
    # The old static-sink + MAY_REACH command votes cannot justify a quorum.
    # Their rejection remains covered by evaluation.scripted. This
    # wiring check uses the existing candidate-bound concrete probe fixture.
    verdict, models = run_probe_case("C01", AgentSystemVersion.E5_GRAPH_FAST)
    if verdict.path != "slow" or len(verdict.votes) != 3:
        raise RuntimeError("agentic smoke fixture incorrectly formed a quorum from a weak flow vote")
    if not models["authz"].requests:
        raise RuntimeError("agentic smoke fixture skipped review without a sufficient quorum")
    return {
        "harness_id": FULL_SYSTEM_HARNESS.harness_id,
        "runtime_mode": "scripted",
        "claim_eligible": False,
        "purpose": "wiring-only ReAct and LangGraph diagnostic with a bounded eval witness",
        "verdict": verdict.model_dump(mode="json"),
    }
