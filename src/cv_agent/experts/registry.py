"""Default deterministic expert instances."""
from __future__ import annotations

from .authorization import AuthorizationExpert
from .common import Expert
from .flow import FlowRefutationExpert
from .scan import ScanExpert
from .taint import TaintExpert


EXPERTS: dict[str, Expert] = {
    "scan": ScanExpert(),
    "taint": TaintExpert(),
    "authz": AuthorizationExpert(),
    "flow": FlowRefutationExpert(),
}
