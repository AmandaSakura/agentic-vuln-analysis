"""Deterministic specialist experts and their default registry."""

from ..java_lexical import (
    ASSIGNMENT_RE,
    COLLECTION_GET_RE,
    COLLECTION_PUT_RE,
    IDENTIFIER_RE,
    NON_VALUE_IDENTIFIERS,
    SINK_VALUE_NAMES,
    STRING_LITERAL_RE,
)
from .authorization import AuthorizationExpert
from .common import Expert
from .flow import FlowRefutationExpert
from .registry import EXPERTS
from .scan import ScanExpert
from .syntax import (
    CASE_RE,
    CHAR_AT_RE,
    COLLECTION_ADD_RE,
    DEFAULT_RE,
    ELSE_RE,
    IF_RE,
    JAVA_TYPED_ASSIGNMENT_RE,
    LEADING_CAST_RE,
    RETURN_RE,
    SWITCH_RE,
    TERNARY_RE,
)
from .taint import TaintExpert

__all__ = [
    "ASSIGNMENT_RE",
    "AuthorizationExpert",
    "CASE_RE",
    "CHAR_AT_RE",
    "COLLECTION_ADD_RE",
    "COLLECTION_GET_RE",
    "COLLECTION_PUT_RE",
    "DEFAULT_RE",
    "ELSE_RE",
    "EXPERTS",
    "Expert",
    "FlowRefutationExpert",
    "IDENTIFIER_RE",
    "IF_RE",
    "JAVA_TYPED_ASSIGNMENT_RE",
    "LEADING_CAST_RE",
    "NON_VALUE_IDENTIFIERS",
    "RETURN_RE",
    "SINK_VALUE_NAMES",
    "STRING_LITERAL_RE",
    "SWITCH_RE",
    "ScanExpert",
    "TERNARY_RE",
    "TaintExpert",
]
