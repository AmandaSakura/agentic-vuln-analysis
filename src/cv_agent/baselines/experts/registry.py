"""Default deterministic expert instances."""
from __future__ import annotations

from cv_agent.baselines.experts.authorization import AuthorizationExpert
from cv_agent.baselines.experts.common import Expert
from cv_agent.baselines.experts.flow import FlowRefutationExpert
from cv_agent.baselines.experts.scan import ScanExpert
from cv_agent.baselines.experts.taint import TaintExpert


EXPERTS: dict[str, Expert] = {
    "scan": ScanExpert(),
    "taint": TaintExpert(),
    "authz": AuthorizationExpert(),
    "flow": FlowRefutationExpert(),
}
