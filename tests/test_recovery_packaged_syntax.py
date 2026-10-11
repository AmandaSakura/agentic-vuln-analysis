import base64
from cv_agent.application.service_v2 import derive_packaged_documents


def test_packaged_syntax_is_reparsed_from_bytes_with_binding_metadata():
    text='import os as system_module\ndef sample():\n    system_module.chmod("not-run",0o600)\n'
    files={'entry.py':{'raw':base64.b64encode(text.encode()).decode(),'error_stage':None}}
    docs=derive_packaged_documents(files)
    function=next(d for d in docs if '::<module>'not in d.path)
    assert function.import_aliases['system_module']=='os'
    assert 'os.chmod' in function.calls
    assert derive_packaged_documents(files)==docs


def test_partial_snapshot_keeps_parse_failures_and_limit_exclusions_distinct():
    files={'bad.py':{'raw':base64.b64encode(b'def invalid(').decode(),'error_stage':'parse'},
           'bounded.py':{'raw':base64.b64encode(b'import os\n').decode(),'error_stage':'limit'},
           'unread.py':{'raw':None,'error_stage':'read'}}
    assert derive_packaged_documents(files)==()


def test_packaged_operation_inventory_is_derived_from_complete_sealed_module():
    import hashlib
    from cv_agent.application.service_v2 import derive_packaged_operations
    from cv_agent.retrieval.index import FrozenRepositoryIndex
    text='import os\ndef sample():\n    os.chmod("first",0o600); os.chmod("second",0o602)\n'
    raw=text.encode()
    files={'entry.py':{'raw':base64.b64encode(raw).decode(),'error_stage':None}}
    hashes={'entry.py':hashlib.sha256(raw).hexdigest()}
    index=FrozenRepositoryIndex(derive_packaged_documents(files))
    candidates=derive_packaged_operations(files,hashes,index)
    assert len(candidates)==2
    assert len({c.candidate_id for c in candidates})==2
    assert [c.metadata['source_snippet']for c in candidates]==['os.chmod("first",0o600)','os.chmod("second",0o602)']
    assert all('sample@'in c.path for c in candidates)
