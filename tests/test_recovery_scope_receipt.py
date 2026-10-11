import pytest
from cv_agent.application.service_v2 import run_review_v2


def test_public_scope_receipts_cannot_rewrite_completed_context_accounting(tmp_path):
    source=tmp_path/'owned';source.mkdir()
    (source/'entry.py').write_text('import os\nos.chmod("never-run",0o600)\n')
    result=run_review_v2(source,tmp_path/'run')
    before=result.model_dump(mode='json')['scope_admissions']
    with pytest.raises((TypeError,ValueError)):
        result.scope_admissions[0]['delivered_bytes']=999999
    assert result.model_dump(mode='json')['scope_admissions']==before
    receipt=result.scope_admissions[0]
    assert receipt.model_copy(update={'reason':'owned new reason'}).reason=='owned new reason'
    with pytest.raises(ValueError):receipt.model_copy(update={'delivered_bytes':-1})
    assert result.findings[0].property_state=='REFUTED'
