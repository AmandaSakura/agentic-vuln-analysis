"""Lexical development units and serialized model-context budgets."""
from __future__ import annotations

from collections.abc import Callable, Iterable
import re

from ..types import Evidence


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")


CONTEXT_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def tokenize(text: str) -> list[str]:
    return [token.casefold() for token in TOKEN_RE.findall(text)]


def context_token_count(evidence: Iterable[Evidence]) -> int:
    return sum(context_text_token_count(item.text) for item in evidence)


def context_text_token_count(text: str) -> int:
    """Legacy lexical units for deterministic development experiments."""
    return len(CONTEXT_TOKEN_RE.findall(text))


def prompt_token_upper_bound(text: str) -> int:
    """UTF-8 byte bound for model-visible text, separate from provider usage.

    Byte-based tokenizers cannot require more text tokens than input bytes.
    Chat framing and tool schemas are outside this retrieved-text budget.
    """
    return len(text.encode("utf-8"))


def fit_text_to_serialized_context(
    text: str,
    *,
    token_budget: int,
    render: Callable[[str], str],
    count_tokens: Callable[[str], int] = context_text_token_count,
) -> tuple[str, str, int] | None:
    """Fit a text field while charging the exact serialized model-visible payload."""

    if token_budget < 0:
        raise ValueError("serialized context token budget cannot be negative")
    empty_payload = render("")
    empty_tokens = count_tokens(empty_payload)
    if empty_tokens > token_budget:
        return None
    full_payload = render(text)
    full_tokens = count_tokens(full_payload)
    if full_tokens <= token_budget:
        return text, full_payload, full_tokens

    token_ends = (
        range(1, len(text) + 1)
        if count_tokens is prompt_token_upper_bound
        else [match.end() for match in CONTEXT_TOKEN_RE.finditer(text)]
    )
    low = 0
    high = len(token_ends)
    best = ("", empty_payload, empty_tokens)
    while low <= high:
        middle = (low + high) // 2
        prefix = text[: token_ends[middle - 1]] if middle else ""
        payload = render(prefix)
        count = count_tokens(payload)
        if count <= token_budget:
            best = (prefix, payload, count)
            low = middle + 1
        else:
            high = middle - 1
    return best


def limit_evidence_context(
    evidence: Iterable[Evidence],
    *,
    token_budget: int,
) -> list[Evidence]:
    """Apply one deterministic context-token budget across ranked evidence."""

    if token_budget < 1:
        raise ValueError("context token budget must be positive")
    limited: list[Evidence] = []
    remaining = token_budget
    for item in evidence:
        matches = list(CONTEXT_TOKEN_RE.finditer(item.text))
        if not matches:
            continue
        if len(matches) <= remaining:
            limited.append(item)
            remaining -= len(matches)
        else:
            cutoff = matches[remaining - 1].end()
            limited.append(item.model_copy(update={"text": item.text[:cutoff]}))
            remaining = 0
        if remaining == 0:
            break
    return limited
