from __future__ import annotations

import math
import re
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from functools import lru_cache
from typing import Literal

from .harness import RetrievalBudget, RetrievalMode
from .types import Candidate, CodeDocument, Evidence


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
CONTEXT_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def tokenize(text: str) -> list[str]:
    return [token.casefold() for token in TOKEN_RE.findall(text)]


def context_token_count(evidence: Iterable[Evidence]) -> int:
    return sum(len(CONTEXT_TOKEN_RE.findall(item.text)) for item in evidence)


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


class RepositoryIndex:
    def __init__(self, documents: Iterable[CodeDocument]) -> None:
        docs = list(documents)
        if not docs:
            raise ValueError("repository index requires at least one document")
        self.documents = {doc.path: doc for doc in docs}
        if len(self.documents) != len(docs):
            raise ValueError("duplicate document path")
        self._term_frequency = {path: Counter(tokenize(doc.text)) for path, doc in self.documents.items()}
        document_frequency: Counter[str] = Counter()
        for terms in self._term_frequency.values():
            document_frequency.update(terms.keys())
        count = len(self.documents)
        self._idf = {term: math.log((count + 1) / (frequency + 1)) + 1.0 for term, frequency in document_frequency.items()}
        self._forward_graph, self._reverse_graph = self._build_graph(docs)

    @staticmethod
    def _build_graph(
        documents: list[CodeDocument],
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        definitions: dict[str, set[str]] = defaultdict(set)
        for doc in documents:
            for symbol in doc.defines:
                definitions[symbol].add(doc.path)
        forward: dict[str, set[str]] = {doc.path: set() for doc in documents}
        reverse: dict[str, set[str]] = {doc.path: set() for doc in documents}
        for caller in documents:
            for symbol in caller.calls:
                targets = definitions.get(symbol, set())
                # Bare symbols are useful only when they resolve uniquely. Linking every
                # same-named method creates artificial repository-wide shortcuts.
                if "." not in symbol and len(targets) != 1:
                    continue
                for callee_path in targets:
                    if callee_path != caller.path:
                        forward[caller.path].add(callee_path)
                        reverse[callee_path].add(caller.path)
        return forward, reverse

    @lru_cache(maxsize=1)
    def _lexical_scores(self, query: str) -> dict[str, float]:
        """Score one candidate query and reuse it across its V2-V5 retrieval calls."""

        query_terms = Counter(tokenize(query))
        scores: dict[str, float] = {}
        for path, terms in self._term_frequency.items():
            score = 0.0
            for term, query_count in query_terms.items():
                frequency = terms.get(term, 0)
                if frequency:
                    score += query_count * (1.0 + math.log(frequency)) * self._idf.get(term, 1.0)
            scores[path] = score
        return scores

    def local(self, candidate: Candidate) -> list[Evidence]:
        document = self.documents.get(candidate.path)
        if document is None:
            return []
        return [Evidence(evidence_id=f"local:{document.path}", path=document.path, text=document.text, retrieval="local", score=1.0)]

    def text_search(self, query: str, *, top_k: int = 5) -> list[Evidence]:
        scores = self._lexical_scores(query)
        ranked = sorted(scores, key=lambda path: (-scores[path], path))[:top_k]
        return [
            Evidence(
                evidence_id=f"text:{path}",
                path=path,
                text=self.documents[path].text,
                retrieval="text",
                score=scores[path],
            )
            for path in ranked
            if scores[path] > 0
        ]

    @staticmethod
    def _walk_graph(
        seeds: list[str],
        graph: dict[str, set[str]],
        *,
        max_hops: int,
    ) -> dict[str, int]:
        distances: dict[str, int] = {}
        queue: deque[tuple[str, int]] = deque((path, 0) for path in seeds)
        while queue:
            path, distance = queue.popleft()
            if path in distances and distances[path] <= distance:
                continue
            distances[path] = distance
            if distance >= max_hops:
                continue
            for neighbor in sorted(graph.get(path, ())):
                queue.append((neighbor, distance + 1))
        return distances

    def _rank_graph_evidence(
        self,
        distances: dict[str, int],
        lexical: dict[str, float],
        *,
        top_k: int,
        retrieval: Literal["graph", "hybrid"],
    ) -> list[Evidence]:
        ranked = sorted(
            distances,
            key=lambda path: (
                -(lexical.get(path, 0.0) + 1.0 / (1 + distances[path])),
                distances[path],
                path,
            ),
        )[:top_k]
        return [
            Evidence(
                evidence_id=f"{retrieval}:{path}",
                path=path,
                text=self.documents[path].text,
                retrieval=retrieval,
                score=lexical.get(path, 0.0) + 1.0 / (1 + distances[path]),
                graph_distance=distances[path],
            )
            for path in ranked
        ]

    def graph_search(
        self,
        candidate: Candidate,
        *,
        top_k: int = 8,
        max_hops: int = 2,
        direction: Literal["forward", "reverse", "both"] = "forward",
    ) -> list[Evidence]:
        """Search only nodes reachable from the candidate in the requested direction."""

        if candidate.path not in self.documents:
            return []
        lexical = self._lexical_scores(candidate.query)
        if direction == "forward":
            graph = self._forward_graph
        elif direction == "reverse":
            graph = self._reverse_graph
        else:
            graph = {
                path: self._forward_graph[path] | self._reverse_graph[path]
                for path in self.documents
            }
        distances = self._walk_graph([candidate.path], graph, max_hops=max_hops)
        return self._rank_graph_evidence(
            distances,
            lexical,
            top_k=top_k,
            retrieval="graph",
        )

    def hybrid_search(
        self,
        candidate: Candidate,
        *,
        top_k: int = 8,
        max_hops: int = 2,
    ) -> list[Evidence]:
        """Combine one lexical seed with forward call-graph expansion."""

        lexical = self._lexical_scores(candidate.query)
        seeds = [candidate.path] if candidate.path in self.documents else []
        lexical_seeds = [
            path
            for path in sorted(lexical, key=lambda item: (-lexical[item], item))
            if lexical[path] > 0 and path not in seeds
        ]
        seeds.extend(lexical_seeds[:1])
        if not seeds:
            return []
        distances = self._walk_graph(seeds, self._forward_graph, max_hops=max_hops)
        return self._rank_graph_evidence(
            distances,
            lexical,
            top_k=top_k,
            retrieval="hybrid",
        )

    def retrieve_context(
        self,
        candidate: Candidate,
        *,
        mode: RetrievalMode,
        budget: RetrievalBudget,
    ) -> list[Evidence]:
        """Assemble a fixed local base plus a separately budgeted augmentation."""

        base = limit_evidence_context(
            self.local(candidate),
            token_budget=budget.base_context_tokens,
        )
        if mode == RetrievalMode.LOCAL:
            return base

        requested = budget.top_k + 1
        if mode == RetrievalMode.TEXT:
            raw_augmentation = self.text_search(candidate.query, top_k=requested)
        elif mode == RetrievalMode.GRAPH:
            raw_augmentation = self.graph_search(
                candidate,
                top_k=requested,
                max_hops=budget.graph_hops,
            )
        elif mode == RetrievalMode.HYBRID:
            raw_augmentation = self.hybrid_search(
                candidate,
                top_k=requested,
                max_hops=budget.graph_hops,
            )
        else:
            raise ValueError(f"unsupported retrieval mode: {mode}")

        augmentation = [
            item for item in raw_augmentation if item.path != candidate.path
        ][: budget.top_k]
        if not augmentation or budget.augmentation_context_tokens == 0:
            return base
        limited_augmentation = limit_evidence_context(
            augmentation,
            token_budget=budget.augmentation_context_tokens,
        )
        return [*base, *limited_augmentation]
