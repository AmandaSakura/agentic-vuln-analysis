"""Public experiment harness API.

Models, declared defaults, configuration checks, and result checks live in
separate modules; these explicit exports preserve the existing import path.
"""

from ..types import SystemVersion
from .models import (
    AgentRuntimeMode,
    AgentSystemHarness,
    AgentSystemVersion,
    CommandPolicy,
    DatasetRole,
    EndToEndHarness,
    ExperimentHarness,
    ExpertAgentHarness,
    ExpertName,
    ModelRuntimeHarness,
    OwaspExpertName,
    ReActLoopHarness,
    RetrievalBudget,
    RetrievalEvaluationHarness,
    RetrievalMode,
    SystemHarness,
    ValidationRuntimeHarness,
)
from .defaults import (
    AGENT_AUGMENTATION_TOKENS,
    AGENT_BASE_TOKENS,
    AGENT_GRAPH_HOPS,
    AGENT_TOP_K,
    COMMAND_POLICIES,
    COMPARABLE_AUGMENTATION_TOKENS,
    COMPARABLE_BASE_TOKENS,
    COMPARABLE_TOP_K,
    FULL_SYSTEM_HARNESS,
    OWASP_HARNESS,
    VULNGYM_RETRIEVAL_HARNESS,
    command_policy,
)
from .validation import (
    describe_project_harness,
    validate_full_system_harness,
    validate_owasp_harness,
    validate_project_harness,
    validate_vulngym_harness,
)
from .owasp_results import (
    validate_owasp_result_payload,
)
from .vulngym_results import (
    validate_vulngym_result_payload,
)

__all__ = [
    "AGENT_AUGMENTATION_TOKENS",
    "AGENT_BASE_TOKENS",
    "AGENT_GRAPH_HOPS",
    "AGENT_TOP_K",
    "AgentRuntimeMode",
    "AgentSystemHarness",
    "AgentSystemVersion",
    "COMMAND_POLICIES",
    "COMPARABLE_AUGMENTATION_TOKENS",
    "COMPARABLE_BASE_TOKENS",
    "COMPARABLE_TOP_K",
    "CommandPolicy",
    "DatasetRole",
    "EndToEndHarness",
    "ExperimentHarness",
    "ExpertAgentHarness",
    "ExpertName",
    "FULL_SYSTEM_HARNESS",
    "ModelRuntimeHarness",
    "OWASP_HARNESS",
    "OwaspExpertName",
    "ReActLoopHarness",
    "RetrievalBudget",
    "RetrievalEvaluationHarness",
    "RetrievalMode",
    "SystemHarness",
    "SystemVersion",
    "VULNGYM_RETRIEVAL_HARNESS",
    "ValidationRuntimeHarness",
    "command_policy",
    "describe_project_harness",
    "validate_full_system_harness",
    "validate_owasp_harness",
    "validate_owasp_result_payload",
    "validate_project_harness",
    "validate_vulngym_harness",
    "validate_vulngym_result_payload",
]

# Fail at import time if the single source of truth becomes internally inconsistent.
validate_project_harness()
