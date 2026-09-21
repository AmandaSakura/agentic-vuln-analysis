"""Candidate analysis primitives with lazy public API exports.

Importing the agent library does not initialize the deterministic baseline.
"""
from importlib import import_module as _import_module

_EXPORTS = {
    "AgentPipeline": ("cv_agent.baselines.workflow", "AgentPipeline"),
    "PipelineConfig": ("cv_agent.baselines.workflow", "PipelineConfig"),
    "Candidate": ("cv_agent.domain.types", "Candidate"),
    "CodeDocument": ("cv_agent.domain.types", "CodeDocument"),
    "SystemVersion": ("cv_agent.domain.types", "SystemVersion"),
    "Verdict": ("cv_agent.domain.types", "Verdict"),
    "QuorumPolicy": ("cv_agent.agents.voting", "QuorumPolicy"),
    "SingleExpertPolicy": ("cv_agent.agents.voting", "SingleExpertPolicy"),
    "RepositoryIndex": ("cv_agent.retrieval", "RepositoryIndex"),
}
__all__ = list(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module, attribute = _EXPORTS[name]
    value = getattr(_import_module(module), attribute)
    globals()[name] = value
    return value
