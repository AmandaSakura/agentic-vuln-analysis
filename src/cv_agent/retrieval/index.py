"""Repository indexing, call graphs and local/text/graph retrieval."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from functools import lru_cache
from typing import Literal
import math
import re

from ..harness import RetrievalBudget, RetrievalMode
from ..types import Candidate, CodeDocument, Evidence
from .context import (
    _focused_text,
    _is_textual_get_cmd_helper,
    _line_bounds_from_path,
    _uses_get_cmd_shell_construction,
)
from .tokens import limit_evidence_context, tokenize


class RepositoryIndex:
    def __init__(self, documents: Iterable[CodeDocument]) -> None:
        docs = list(documents)
        if not docs:
            raise ValueError("repository index requires at least one document")
        self.documents = {doc.path: doc for doc in docs}
        if len(self.documents) != len(docs):
            raise ValueError("duplicate document path")
        self._term_frequency = {path: Counter(tokenize(doc.text)) for path, doc in self.documents.items()}
        self._path_term_frequency = {path: Counter(tokenize(path)) for path in self.documents}
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
            precise_bases = {
                symbol.split("(", 1)[0].split("#", 1)[0]
                for symbol in caller.calls
                if "(" in symbol or "#" in symbol
            }
            for symbol in caller.calls:
                if symbol in precise_bases:
                    continue
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
        path_query = query.casefold().strip()
        path_like_query = bool(re.search(r"(?:/|::|\.|\\)", path_query))
        path_fragments = tuple(
            sorted(
                {
                    fragment.casefold().strip(".,;:")
                    for fragment in re.findall(
                        r"[A-Za-z0-9_./\\-]+\.[A-Za-z0-9_./\\-]+", query
                    )
                }
            )
        )
        for path, terms in self._term_frequency.items():
            score = 0.0
            for term, query_count in query_terms.items():
                frequency = terms.get(term, 0)
                if frequency:
                    score += query_count * (1.0 + math.log(frequency)) * self._idf.get(term, 1.0)
                if path_like_query:
                    path_frequency = self._path_term_frequency[path].get(term, 0)
                    if path_frequency:
                        score += query_count * (4.0 + math.log(path_frequency))
            path_lower = path.casefold()
            if path_like_query and path_query and path_query in path_lower:
                score += 50.0
            for fragment in path_fragments:
                if fragment in path_lower:
                    score += 1000.0
            scores[path] = score
        return scores

    def local(self, candidate: Candidate) -> list[Evidence]:
        document = self.documents.get(candidate.path)
        if document is None:
            return []
        return [Evidence(evidence_id=f"local:{document.path}", path=document.path, text=document.text, retrieval="local", score=1.0)]

    def _focused_local(
        self,
        candidate: Candidate,
        *,
        token_budget: int,
    ) -> list[Evidence]:
        document = self.documents.get(candidate.path)
        if document is None:
            return []
        bounds = _line_bounds_from_path(candidate.path)
        fallback_relative_line = (
            candidate.line - bounds[0] + 1
            if bounds is not None and bounds[0] <= candidate.line <= bounds[1]
            else None
        )
        return [
            Evidence(
                evidence_id=f"local:{document.path}",
                path=document.path,
                text=_focused_text(
                    document.text,
                    query=candidate.query,
                    token_budget=token_budget,
                    fallback_relative_line=fallback_relative_line,
                ),
                retrieval="local",
                score=1.0,
            )
        ]

    def _focused_augmentation(
        self,
        evidence: list[Evidence],
        candidate: Candidate,
        *,
        token_budget: int,
    ) -> list[Evidence]:
        if not evidence:
            return []
        if len(evidence) == 1 or token_budget < len(evidence):
            item_budgets = [max(1, token_budget // len(evidence))] * len(evidence)
        else:
            equal_share = token_budget // len(evidence)
            priority_budget = min(
                token_budget - (len(evidence) - 1),
                max(equal_share, min(512, token_budget // 2)),
            )
            remaining = token_budget - priority_budget
            share, extra = divmod(remaining, len(evidence) - 1)
            item_budgets = [priority_budget] + [
                share + (1 if index < extra else 0)
                for index in range(len(evidence) - 1)
            ]
        return [
            item.model_copy(
                update={
                    "text": _focused_text(
                        item.text,
                        query=candidate.query,
                        token_budget=item_budget,
                        security_focus=(
                            item.retrieval in {"graph", "hybrid"}
                            and item.graph_distance is not None
                        ),
                    )
                }
            )
            for item, item_budget in zip(evidence, item_budgets, strict=True)
        ]

    def document(self, path: str) -> CodeDocument | None:
        return self.documents.get(path)

    def graph_neighbors(
        self,
        path: str,
        *,
        direction: Literal["forward", "reverse"],
    ) -> tuple[str, ...]:
        graph = self._forward_graph if direction == "forward" else self._reverse_graph
        return tuple(sorted(graph.get(path, ())))

    def _prioritize_textual_command_helpers(
        self,
        candidate: Candidate,
        evidence: list[Evidence],
    ) -> list[Evidence]:
        if not _uses_get_cmd_shell_construction(self.document(candidate.path)):
            return evidence
        helpers: list[Evidence] = []
        others: list[Evidence] = []
        for item in evidence:
            if _is_textual_get_cmd_helper(self.document(item.path)):
                helpers.append(item)
            else:
                others.append(item)
        return [*helpers, *others]

    def text_search(
        self,
        query: str,
        *,
        top_k: int = 5,
        allowed_paths: Iterable[str] | None = None,
    ) -> list[Evidence]:
        scores = self._lexical_scores(query)
        candidates = set(scores)
        if allowed_paths is not None:
            candidates &= set(allowed_paths)
        ranked = sorted(candidates, key=lambda path: (-scores[path], path))[:top_k]
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
        ranking: Literal["lexical", "distance"] = "lexical",
    ) -> list[Evidence]:
        ranked = sorted(
            distances,
            key=lambda path: (
                distances[path] if ranking == "distance" else 0,
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
        ranking: Literal["lexical", "distance"] = "lexical",
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
            ranking=ranking,
        )

    def hybrid_search(
        self,
        candidate: Candidate,
        *,
        top_k: int = 8,
        max_hops: int = 2,
    ) -> list[Evidence]:
        """Combine text retrieval with entry- and lexical-seeded graph retrieval."""

        lexical = self._lexical_scores(candidate.query)
        combined: list[Evidence] = []
        seen: set[str] = set()

        def branch_cap(items: Iterable[Evidence]) -> list[Evidence]:
            return [item for item in items if item.path != candidate.path][:top_k]

        def append(items: Iterable[Evidence]) -> None:
            for item in items:
                if item.path in seen:
                    continue
                seen.add(item.path)
                combined.append(
                    item.model_copy(
                        update={
                            "evidence_id": f"hybrid:{item.path}",
                            "retrieval": "hybrid",
                        }
                    )
                )

        if candidate.path in self.documents:
            append(
                branch_cap(
                    self.graph_search(
                        candidate,
                        top_k=top_k + 1,
                        max_hops=max_hops,
                    )
                )
            )

        append(branch_cap(self.text_search(candidate.query, top_k=top_k + 1)))

        lexical_seeds = [
            path
            for path in sorted(lexical, key=lambda item: (-lexical[item], item))
            if lexical[path] > 0 and path != candidate.path
        ]
        for seed in lexical_seeds[:1]:
            distances = self._walk_graph([seed], self._forward_graph, max_hops=max_hops)
            append(
                branch_cap(
                    self._rank_graph_evidence(
                        distances,
                        lexical,
                        top_k=top_k + 1,
                        retrieval="hybrid",
                    )
                )
            )
        return combined

    def retrieve_context(
        self,
        candidate: Candidate,
        *,
        mode: RetrievalMode,
        budget: RetrievalBudget,
    ) -> list[Evidence]:
        """Assemble a fixed local base plus a separately budgeted augmentation."""

        base = limit_evidence_context(
            self._focused_local(
                candidate,
                token_budget=budget.base_context_tokens,
            ),
            token_budget=budget.base_context_tokens,
        )
        if mode == RetrievalMode.LOCAL:
            return base
        if budget.top_k == 0:
            return base

        requested = budget.top_k + 1
        if mode == RetrievalMode.TEXT:
            raw_augmentation = self.text_search(
                candidate.query,
                top_k=max(requested, budget.top_k * 3),
            )
            raw_augmentation = self._prioritize_textual_command_helpers(
                candidate,
                raw_augmentation,
            )
        elif mode == RetrievalMode.GRAPH:
            raw_augmentation = self.graph_search(
                candidate,
                top_k=requested,
                max_hops=budget.graph_hops,
                direction=budget.graph_direction,
                ranking=budget.graph_ranking,
            )
        elif mode == RetrievalMode.HYBRID:
            raw_augmentation = self.hybrid_search(
                candidate,
                top_k=budget.top_k,
                max_hops=budget.graph_hops,
            )
        else:
            raise ValueError(f"unsupported retrieval mode: {mode}")

        filtered_augmentation = [
            item for item in raw_augmentation if item.path != candidate.path
        ]
        augmentation = (
            filtered_augmentation
            if mode == RetrievalMode.HYBRID
            else filtered_augmentation[: budget.top_k]
        )
        if not augmentation or budget.augmentation_context_tokens == 0:
            return base
        limited_augmentation = limit_evidence_context(
            self._focused_augmentation(
                augmentation,
                candidate,
                token_budget=budget.augmentation_context_tokens,
            ),
            token_budget=budget.augmentation_context_tokens,
        )
        return [*base, *limited_augmentation]
