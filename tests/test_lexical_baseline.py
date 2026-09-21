from cv_agent.lexical_baseline import MetadataBM25Index
from cv_agent.harness import FULL_SYSTEM_HARNESS,AgentSystemVersion
from cv_agent.types import CodeDocument,Candidate
import pytest


def test_metadata_baseline_uses_source_identity_not_reference_labels():
    documents=[CodeDocument(repository_id='repo',path=f'{name}.java::{method}@1',
                            text=f'void {method}(Request request) {{ process(request); }}')
               for name in ['Alpha','Beta','Gamma'] for method in ['doGet','doPost']]
    index=MetadataBM25Index(documents)
    spec=FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E2_TEXT_SINGLE)
    candidate=Candidate(candidate_id='opaque-id',case_id='opaque-id',repository_id='repo',
                        path='Beta.java::doGet@1',line=1,query='void doGet(Request request) { process(request); }')
    scored=index._lexical_scores(f'{candidate.path} {candidate.query}')
    assert scored['Beta.java::doPost@1'] > scored['Alpha.java::doPost@1']
    evidence=index.retrieve_context(candidate,mode=spec.retrieval,budget=spec.budget)
    assert any(item.path=='Beta.java::doPost@1' for item in evidence)
    local=FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E1_LOCAL_SINGLE)
    with pytest.raises(ValueError,match='only supports text or graph'):
        index.retrieve_context(candidate,mode=local.retrieval,budget=local.budget)
