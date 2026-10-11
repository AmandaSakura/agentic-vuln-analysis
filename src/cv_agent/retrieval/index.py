"""Repository indexing, call graphs and local/text/graph retrieval."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from functools import lru_cache
from typing import Literal
import ast
import hashlib
import math
import re
import symtable
import textwrap
from types import MappingProxyType

from cv_agent.harness import RetrievalBudget, RetrievalMode
from cv_agent.domain.types import Candidate, CodeDocument, Evidence
from cv_agent.retrieval.context import _focused_text, _is_textual_get_cmd_helper, _line_bounds_from_path, _uses_get_cmd_shell_construction
from cv_agent.retrieval.tokens import limit_evidence_context, tokenize


class RepositoryIndex:
    def __init__(self, documents: Iterable[CodeDocument] = ()) -> None:
        docs = list(documents)
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
        definitions: dict[str, set[str]] = defaultdict(set)
        for doc in docs:
            for symbol in doc.defines:
                definitions[symbol].add(doc.path)
        self._definitions = definitions

    @staticmethod
    def _source_file(path: str) -> str:
        return path.split("::", 1)[0]

    @staticmethod
    def _bare_call_names(document: CodeDocument) -> set[str]:
        try:
            source = textwrap.dedent(document.text)
            tree = ast.parse(source)
            symbols = symtable.symtable(source, document.path, "exec")
        except SyntaxError:
            return set()
        function_scopes = [
            child for child in symbols.get_children() if child.get_type() == "function"
        ]
        if not function_scopes:
            return set()
        function_scope = function_scopes[0]
        syntactic_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        return {
            name for name in syntactic_names
            if name not in document.module_rebindings
            and name in function_scope.get_identifiers()
            and not (
                function_scope.lookup(name).is_local()
                or function_scope.lookup(name).is_parameter()
                or function_scope.lookup(name).is_free()
                or function_scope.lookup(name).is_imported()
            )
        }

    @staticmethod
    def _qualified_call_is_bound(
        caller: CodeDocument, target: CodeDocument, symbol: str,
    ) -> bool:
        try:
            source = textwrap.dedent(caller.text)
            tree = ast.parse(source)
            symbols = symtable.symtable(source, caller.path, "exec")
        except SyntaxError:
            return False
        function_scopes = [
            child for child in symbols.get_children() if child.get_type() == "function"
        ]
        if not function_scopes:
            return False
        function_scope = function_scopes[0]
        root_function = next(
            (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))),
            None,
        )
        if root_function is None:
            return False

        def active_nodes(node: ast.AST):
            yield node
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                yield from active_nodes(child)

        nodes = tuple(active_nodes(root_function))
        local_assignments: dict[str, list[ast.expr]] = defaultdict(list)
        for node in nodes:
            if isinstance(node, ast.Assign):
                for target_name in node.targets:
                    if isinstance(target_name, ast.Name):
                        local_assignments[target_name.id].append(node.value)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    local_assignments[node.target.id].append(node.value)

        def alias_targets(value: ast.expr) -> set[str]:
            if isinstance(value, ast.Name):
                imported = caller.import_aliases.get(value.id)
                return {imported} if imported and value.id not in caller.module_rebindings else set()
            if isinstance(value, ast.IfExp):
                left = alias_targets(value.body)
                right = alias_targets(value.orelse)
                return left | right if left and right else set()
            return set()

        local_aliases = {
            name: alias_targets(values[0])
            for name, values in local_assignments.items()
            if len(values) == 1
        }
        caller_symbol = caller.path.split("::", 1)[-1].split("@", 1)[0]
        caller_class = caller_symbol.rsplit(".", 1)[0] if "." in caller_symbol else None
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            parts: list[str] = []
            value = node.func
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if not isinstance(value, ast.Name):
                continue
            parts.append(value.id)
            parts.reverse()
            head = parts[0]
            if head in caller.module_rebindings:
                continue
            if any(
                ".".join([target_prefix, *parts[1:]]) == symbol
                for target_prefix in local_aliases.get(head, set())
            ):
                return True
            if head not in {"self", "cls"} and head in function_scope.get_identifiers():
                binding = function_scope.lookup(head)
                if binding.is_local() or binding.is_parameter() or binding.is_free():
                    continue
            imported = caller.import_aliases.get(head)
            if imported and ".".join([imported, *parts[1:]]) == symbol:
                return True
            if RepositoryIndex._source_file(caller.path) == RepositoryIndex._source_file(target.path):
                if ".".join(parts) == symbol:
                    return True
                if (
                    caller_class is not None
                    and head in {"self", "cls"}
                    and len(parts) == 2
                    and symbol.endswith(f"{caller_class}.{parts[1]}")
                ):
                    return True
        return False

    def _bound_callees(self, source_path: str) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
        """Resolve only indexed calls with one source-backed target.

        A bare name must be a syntactic Name call with a definition in the
        caller's file. A qualified call must match one indexed definition.
        The ordinary graph remains available for broad retrieval, but its
        heuristic shortcuts do not receive admission priority.
        """

        caller = self.documents[source_path]
        bare_names = self._bare_call_names(caller)
        resolved: dict[str, str] = {}
        skipped: list[tuple[str, str, str]] = []
        for symbol in sorted(caller.calls, key=lambda value: (-len(value), value)):
            targets = {
                path for path in self._definitions.get(symbol, set()) - {source_path}
                if self.documents[path].repository_id == caller.repository_id
            }
            if not targets:
                continue
            if "." not in symbol:
                same_file = {
                    path for path in targets
                    if self._source_file(path) == self._source_file(source_path)
                }
                if symbol not in bare_names or symbol in caller.import_aliases:
                    skipped.extend((path, symbol, "unbound_bare_call") for path in sorted(targets))
                    continue
                targets = same_file
                if not targets:
                    skipped.extend(
                        (path, symbol, "cross_file_bare_call")
                        for path in sorted(
                            path for path in self._definitions[symbol] - {source_path}
                            if self.documents[path].repository_id == caller.repository_id
                        )
                    )
                    continue
            else:
                bound = {
                    path for path in targets
                    if self._qualified_call_is_bound(caller, self.documents[path], symbol)
                }
                if not bound:
                    skipped.extend((path, symbol, "unbound_qualified_call") for path in sorted(targets))
                    continue
                targets = bound
            if len(targets) != 1:
                skipped.extend((path, symbol, "ambiguous_definition") for path in sorted(targets))
                continue
            path = next(iter(targets))
            resolved.setdefault(path, symbol)
        return sorted(resolved.items()), skipped

    def _priority_callees(
        self,
        candidate: Candidate,
        *,
        budget: RetrievalBudget,
    ) -> tuple[list[tuple[str, str, str, int]], list[tuple[str, str, str, int, str]]]:
        if candidate.path not in self.documents or budget.graph_hops == 0:
            return [], []
        lexical = self._lexical_scores(candidate.query)
        selected: list[tuple[str, str, str, int]] = []
        skipped: list[tuple[str, str, str, int, str]] = []
        selected_paths = {candidate.path}
        frontier = [candidate.path]
        for depth in range(1, budget.graph_hops + 1):
            candidates: dict[str, tuple[str, str, str, int]] = {}
            for source_path in frontier:
                edges, unresolved = self._bound_callees(source_path)
                skipped.extend(
                    (path, source_path, symbol, depth, reason)
                    for path, symbol, reason in unresolved
                )
                for path, symbol in edges:
                    if path in selected_paths:
                        continue
                    candidates.setdefault(path, (path, source_path, symbol, depth))
            ranked = sorted(
                candidates.values(),
                key=lambda edge: (
                    0 if depth == 1 or self._source_file(edge[0]) == self._source_file(edge[1]) else 1,
                    -lexical.get(edge[0], 0.0),
                    edge[0],
                ),
            )
            frontier = []
            for path, source_path, symbol, distance in ranked:
                if len(selected) == budget.top_k:
                    skipped.append((path, source_path, symbol, distance, "top_k_budget"))
                    continue
                selected.append((path, source_path, symbol, distance))
                selected_paths.add(path)
                frontier.append(path)
            if not frontier:
                break
        return selected, skipped

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
        path_priority: dict[str, int] | None = None,
    ) -> list[Evidence]:
        priority = path_priority or {}
        ranked = sorted(
            distances,
            key=lambda path: (
                distances[path] if ranking == "distance" else 0,
                priority.get(path, 1 if path_priority is not None else 0),
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
        path_priority: dict[str, int] | None = None
        if direction == "forward":
            graph = self._forward_graph
        elif direction == "reverse":
            graph = self._reverse_graph
        else:
            forward_distances = self._walk_graph(
                [candidate.path],
                self._forward_graph,
                max_hops=max_hops,
            )
            path_priority = {path: 0 for path in forward_distances}
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
            path_priority=path_priority,
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

        return self.retrieve_context_with_admission(
            candidate, mode=mode, budget=budget,
        )[0]

    def retrieve_context_with_admission(
        self,
        candidate: Candidate,
        *,
        mode: RetrievalMode,
        budget: RetrievalBudget,
    ) -> tuple[list[Evidence], list[dict[str, object]]]:
        """Return bounded evidence and an audit of source-resolved callees."""

        base = limit_evidence_context(
            self._focused_local(
                candidate,
                token_budget=budget.base_context_tokens,
            ),
            token_budget=budget.base_context_tokens,
        )
        if mode == RetrievalMode.LOCAL:
            return base, []
        if budget.top_k == 0:
            return base, []

        preferred, skipped = (
            ([], []) if mode == RetrievalMode.GRAPH and budget.graph_direction == "reverse"
            else self._priority_callees(candidate, budget=budget)
        )
        admission_records: list[dict[str, object]] = []

        def record(path: str, source_path: str, symbol: str, distance: int,
                   status: str, reason: str) -> None:
            document = self.documents[path]
            admission_records.append({
                "path": path,
                "bound_call_source": source_path,
                "call_symbol": symbol,
                "graph_distance": distance,
                "document_sha256": hashlib.sha256(document.text.encode("utf-8")).hexdigest(),
                "source_sha256": document.source_sha256,
                "serialized_token_cost": 0,
                "status": status,
                "reason": reason,
            })

        for path, source_path, symbol, distance, reason in skipped:
            record(path, source_path, symbol, distance, "skipped", reason)

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

        preferred_paths = {path for path, _, _, _ in preferred}
        unbound_paths = {
            path for path, _, _, _, reason in skipped
            if reason == "unbound_bare_call" and path not in preferred_paths
        }
        raw_augmentation = [
            item for item in raw_augmentation if item.path not in unbound_paths
        ]

        priority_evidence = [
            Evidence(
                evidence_id=f"{mode.value}:{path}",
                path=path,
                text=self.documents[path].text,
                retrieval=mode.value,
                score=self._lexical_scores(candidate.query).get(path, 0.0),
                graph_distance=distance,
            )
            for path, _, _, distance in preferred
        ]
        augmentation: list[Evidence] = []
        seen = {candidate.path}
        augmentation_limit = (
            max(budget.top_k, len(raw_augmentation))
            if mode == RetrievalMode.HYBRID else budget.top_k
        )
        for item in [*priority_evidence, *raw_augmentation]:
            if item.path not in seen and len(augmentation) < augmentation_limit:
                augmentation.append(item)
                seen.add(item.path)
        if not augmentation or budget.augmentation_context_tokens == 0:
            for path, source_path, symbol, distance in preferred:
                record(path, source_path, symbol, distance, "skipped", "augmentation_context_budget")
            return base, admission_records
        limited_augmentation = limit_evidence_context(
            self._focused_augmentation(
                augmentation,
                candidate,
                token_budget=budget.augmentation_context_tokens,
            ),
            token_budget=budget.augmentation_context_tokens,
        )
        admitted = {item.path for item in limited_augmentation}
        for path, source_path, symbol, distance in preferred:
            record(
                path, source_path, symbol, distance,
                "admitted" if path in admitted else "skipped",
                "source_resolved_direct_callee" if path in admitted else "augmentation_context_budget",
            )
        return [*base, *limited_augmentation], admission_records


class FrozenRepositoryIndex(RepositoryIndex):
    """A v2 source view with sealed documents and one historical-format digest.

    Only supported public mutation is refused. Private Python reflection and
    arbitrary modifications of implementation storage are outside this API.
    Graph construction runs once, before sealing the document mapping.
    """

    def __init__(self, documents: Iterable[CodeDocument] = ()) -> None:
        self._source_sealed = False
        super().__init__(documents)
        self.documents = MappingProxyType(dict(self.documents))
        from cv_agent.tools.identity import _uncached_repository_source_digest
        self._sealed_source_digest = _uncached_repository_source_digest(self)
        self._source_sealed = True

    def __setattr__(self, name, value):
        if getattr(self, "_source_sealed", False) and name in {
            "documents", "source_digest", "_sealed_source_digest", "_source_sealed",
        }:
            raise AttributeError("the frozen source index refuses document or identity reassignment")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if getattr(self, "_source_sealed", False) and name in {
            "documents", "source_digest", "_sealed_source_digest", "_source_sealed",
        }:
            raise AttributeError("the frozen source index refuses document or identity deletion")
        super().__delattr__(name)

    @property
    def source_digest(self) -> str:
        return self._sealed_source_digest
