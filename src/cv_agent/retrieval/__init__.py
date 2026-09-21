"""Repository retrieval and bounded evidence context. Public imports remain stable."""

from cv_agent.code_adapters.java_lexical import ASSIGNMENT_RE, COLLECTION_GET_RE, COLLECTION_PUT_RE, IDENTIFIER_RE, NON_VALUE_IDENTIFIERS, SINK_VALUE_NAMES, STRING_LITERAL_RE
from cv_agent.retrieval.context import DOCUMENT_SPAN_RE, NON_ADJACENT_CONTEXT_MARKER, SECURITY_SINK_FOCUS_RE, SECURITY_SOURCE_FOCUS_RE, _line_bounds_from_path
from cv_agent.retrieval.dependencies import CALL_ARGUMENT_RE, IF_CONDITION_RE, INLINE_IF_RE, MAP_GET_RE, METHOD_RECEIVER_RE, SWITCH_RE, VALUE_TRANSFORM_RECEIVER_RE
from cv_agent.retrieval.index import RepositoryIndex
from cv_agent.retrieval.tokens import CONTEXT_TOKEN_RE, TOKEN_RE, context_text_token_count, context_token_count, fit_text_to_serialized_context, limit_evidence_context, prompt_token_upper_bound, tokenize

__all__ = [
    "ASSIGNMENT_RE",
    "CALL_ARGUMENT_RE",
    "COLLECTION_GET_RE",
    "COLLECTION_PUT_RE",
    "CONTEXT_TOKEN_RE",
    "DOCUMENT_SPAN_RE",
    "IDENTIFIER_RE",
    "IF_CONDITION_RE",
    "INLINE_IF_RE",
    "MAP_GET_RE",
    "METHOD_RECEIVER_RE",
    "NON_ADJACENT_CONTEXT_MARKER",
    "NON_VALUE_IDENTIFIERS",
    "RepositoryIndex",
    "SECURITY_SINK_FOCUS_RE",
    "SECURITY_SOURCE_FOCUS_RE",
    "SINK_VALUE_NAMES",
    "STRING_LITERAL_RE",
    "SWITCH_RE",
    "TOKEN_RE",
    "VALUE_TRANSFORM_RECEIVER_RE",
    "context_text_token_count",
    "context_token_count",
    "fit_text_to_serialized_context",
    "limit_evidence_context",
    "prompt_token_upper_bound",
    "tokenize",
]
