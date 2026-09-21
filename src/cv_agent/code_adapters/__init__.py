"""Source-language adapters and repository loading."""

from cv_agent.code_adapters.common import GUARD_RE
from cv_agent.code_adapters.fallback import FALLBACK_SUFFIXES, parse_fallback_source
from cv_agent.code_adapters.go import GO_LANGUAGE, parse_go_source
from cv_agent.code_adapters.javascript import JAVASCRIPT_LANGUAGE, JAVASCRIPT_SUFFIXES, JS_CLASS_NODES, JS_FUNCTION_NODES, JS_NAMED_FUNCTION_NODES, JS_ROUTE_METHODS, TSX_LANGUAGE, TYPESCRIPT_LANGUAGE, TYPESCRIPT_SUFFIXES, parse_javascript_source, parse_typescript_source
from cv_agent.code_adapters.models import CodeRepositoryDocuments, ParsedSource, SourceDocumentSpan
from cv_agent.code_adapters.repository import SKIPPED_DIRECTORIES, load_code_repository

__all__ = [
    "CodeRepositoryDocuments",
    "FALLBACK_SUFFIXES",
    "GO_LANGUAGE",
    "GUARD_RE",
    "JAVASCRIPT_LANGUAGE",
    "JAVASCRIPT_SUFFIXES",
    "JS_CLASS_NODES",
    "JS_FUNCTION_NODES",
    "JS_NAMED_FUNCTION_NODES",
    "JS_ROUTE_METHODS",
    "ParsedSource",
    "SKIPPED_DIRECTORIES",
    "SourceDocumentSpan",
    "TSX_LANGUAGE",
    "TYPESCRIPT_LANGUAGE",
    "TYPESCRIPT_SUFFIXES",
    "load_code_repository",
    "parse_fallback_source",
    "parse_go_source",
    "parse_javascript_source",
    "parse_typescript_source",
]
