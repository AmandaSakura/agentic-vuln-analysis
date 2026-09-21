"""Explicit stronger lexical diagnostic; does not replace the frozen E2 baseline."""
from collections import Counter
from functools import lru_cache
import math

from .harness import RetrievalMode
from .retrieval import RepositoryIndex, tokenize


class MetadataBM25Index(RepositoryIndex):
    """BM25 on source text/path/symbols, using only detector-visible information."""
    def __init__(self, documents):
        super().__init__(documents)
        self._bm25_terms = {
            path: Counter(tokenize(' '.join((doc.path, *doc.defines, doc.text))))
            for path, doc in self.documents.items()}
        self._bm25_lengths = {path: sum(terms.values()) for path, terms in self._bm25_terms.items()}
        self._bm25_average = sum(self._bm25_lengths.values()) / len(self.documents)
        frequency = Counter()
        for terms in self._bm25_terms.values():
            frequency.update(terms.keys())
        count = len(self.documents)
        self._bm25_idf = {term: math.log(1+(count-df+.5)/(df+.5)) for term, df in frequency.items()}

    @lru_cache(maxsize=1)
    def _lexical_scores(self, query):
        scores = {}
        for path, terms in self._bm25_terms.items():
            norm = 1.2*(.25+.75*self._bm25_lengths[path]/self._bm25_average)
            scores[path] = sum(self._bm25_idf.get(term,0)*terms[term]*2.2/(terms[term]+norm)
                               for term in set(tokenize(query)) if terms[term])
        return scores

    def retrieve_context(self, candidate, *, mode, budget):
        if mode not in {RetrievalMode.TEXT, RetrievalMode.GRAPH}:
            raise ValueError('Metadata BM25 diagnostic only supports text or graph retrieval')
        query = f'{candidate.path} {candidate.query}'
        return super().retrieve_context(candidate.model_copy(update={'query':query}),mode=mode,budget=budget)
