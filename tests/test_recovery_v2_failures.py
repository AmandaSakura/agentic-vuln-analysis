from pathlib import Path
import pytest
from cv_agent.application import service_v2
from cv_agent.application.local_evidence import LocalEvidenceError


def owned_source(tmp_path: Path):
    source=tmp_path/'owned';source.mkdir()
    (source/'entry.py').write_text('import os\nos.chmod("first",0o602)\nos.chmod("second",0o600)\nos.chmod("third",0o602)\n')
    return source


def test_complete_evidence_read_failure_retains_earlier_fact_without_strong_second_state(tmp_path,monkeypatch):
    source=owned_source(tmp_path)
    original=service_v2.read_descriptor
    def fail_second(descriptor,**kwargs):
        if descriptor['producer_id'].endswith('/2'):
            raise LocalEvidenceError('owned persistence fault')
        return original(descriptor,**kwargs)
    monkeypatch.setattr(service_v2,'read_descriptor',fail_second)
    result=service_v2.run_review_v2(source,tmp_path/'result')
    assert result.run_state=='PARTIAL'
    assert result.findings[0].property_state=='SUPPORTED'
    second=result.findings[1]
    assert second.property_state=='UNKNOWN'
    assert second.persistence_state=='FAILED'
    assert not second.record_refs
    assert service_v2.verify_bundle(tmp_path/'result')['valid']


def test_unexpected_internal_failure_preserves_first_and_stops_later_tools(tmp_path,monkeypatch):
    source=owned_source(tmp_path)
    original=service_v2.analyze_operation
    attempted=[]
    def fail_second(index,candidate,admitted,producer):
        attempted.append(producer)
        if producer.endswith('/2'):
            raise RuntimeError('owned analyzer fault')
        return original(index,candidate,admitted,producer)
    monkeypatch.setattr(service_v2,'analyze_operation',fail_second)
    result=service_v2.run_review_v2(source,tmp_path/'result')
    assert result.run_state=='PARTIAL'
    assert result.findings[0].property_state=='SUPPORTED'
    assert result.findings[1].analysis_state=='FAILED'
    assert result.findings[2].analysis_state=='NOT_STARTED'
    assert not any(p.endswith('/3')for p in attempted)
    assert result.counts.candidate_total==3
    assert result.counts.analysis_completed==result.counts.analysis_failed==result.counts.analysis_not_started==1


def test_zero_candidates_and_invalid_file_have_different_run_states(tmp_path):
    source=tmp_path/'source';source.mkdir()
    (source/'entry.py').write_text('value=1\n')
    empty=service_v2.run_review_v2(source,tmp_path/'empty')
    assert empty.run_state=='COMPLETED'and empty.counts.candidate_total==0
    (source/'broken.py').write_text('def bad(')
    partial=service_v2.run_review_v2(source,tmp_path/'partial')
    assert partial.run_state=='PARTIAL'
    assert partial.counts.source_files_enumerated==2
    assert partial.counts.parsed_files==partial.counts.parse_errors==1
    assert service_v2.verify_bundle(tmp_path/'partial')['valid']


def test_record_quota_keeps_all_candidates_and_stops_future_producers(tmp_path):
    source=owned_source(tmp_path)
    result=service_v2.run_review_v2(source,tmp_path/'quota',limits={'max_record_bytes':1})
    assert result.run_state=='PARTIAL'
    assert result.counts.candidate_total==3
    assert result.counts.analysis_completed==1
    assert result.counts.analysis_not_started==2
    assert result.counts.unknown==3
    assert result.accounting['analysis_tool_attempts']==1
    assert result.findings[0].persistence_state=='FAILED'
    assert service_v2.verify_bundle(tmp_path/'quota')['valid']


def test_cancellation_after_first_fact_stops_later_tools_and_preserves_denominator(tmp_path,monkeypatch):
    source=owned_source(tmp_path)
    original=service_v2.analyze_operation
    attempted=[]
    def cancel_second(index,candidate,admitted,producer):
        attempted.append(producer)
        if producer.endswith('/2'):raise KeyboardInterrupt()
        return original(index,candidate,admitted,producer)
    monkeypatch.setattr(service_v2,'analyze_operation',cancel_second)
    result=service_v2.run_review_v2(source,tmp_path/'cancelled')
    assert result.run_state=='CANCELLED'
    assert result.findings[0].property_state=='SUPPORTED'
    assert result.counts.analysis_completed==1
    assert result.counts.analysis_not_started==2
    assert not any(p.endswith('/3')for p in attempted)
    assert service_v2.verify_bundle(tmp_path/'cancelled')['valid']


def test_public_artifact_failure_has_presentation_stage_and_keeps_private_material(tmp_path,monkeypatch):
    source=owned_source(tmp_path)
    original=service_v2._write
    def fail_result(path,value):
        if Path(path).name=='result.json':raise OSError('owned public artifact fault')
        return original(path,value)
    monkeypatch.setattr(service_v2,'_write',fail_result)
    with pytest.raises(Exception)as caught:
        service_v2.run_review_v2(source,tmp_path/'not-committed')
    assert getattr(caught.value,'stage',None)=='presentation'
    assert getattr(caught.value,'reason_code',None)=='LOCAL_PACKAGE_PREPARATION_FAILED'
    assert not (tmp_path/'not-committed').exists()
    stage=next(tmp_path.glob('.not-committed-v2-*'))
    assert len(list((stage/'.private/evidence').glob('*.json')))==3


def test_public_copy_rejects_false_persisted_denominator_and_incomplete_verified_stage(tmp_path):
    from cv_agent.domain.product_result_v2 import ReviewResultV2
    source=owned_source(tmp_path)
    result=service_v2.run_review_v2(source,tmp_path/'valid')
    assert result.counts.evidence_persisted_candidates==3
    payload=result.model_dump(mode='json')
    payload['counts']['evidence_persisted_candidates']=0
    with pytest.raises(ValueError):ReviewResultV2.model_validate(payload)
    with pytest.raises(ValueError):result.findings[0].model_copy(update={'analysis_state':'NOT_STARTED'})
    assert result.findings[0].model_copy(update={'analysis_state':'COMPLETED'})==result.findings[0]
