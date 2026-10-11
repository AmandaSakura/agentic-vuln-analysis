"""Offline replay of real prior outputs; no model transport or credential access."""
import hashlib
import json
from pathlib import Path
from reference_protocol import ProposalProtocolError,make_model_view,validate_proposal

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
OLD=ROOT/'artifacts/live_static_pilot_20261001/9930210894134fe29f99da8657c25d3c'

manifest=json.loads((OLD/'private-input-manifest.json').read_text())
events=[json.loads(line)for line in (OLD/'events.jsonl').read_text().splitlines()]
replies=[e['reply']for e in events if e['event']=='model_reply']
outcomes=[]
for row,reply in zip(manifest,replies):
    try:
        value=validate_proposal(reply['content'],row['payload'])
        outcomes.append({'accepted':True,'state':value.property_state})
    except ProposalProtocolError as error:
        outcomes.append({'accepted':False,'reason_code':error.reason_code,'invalid_refs':list(error.invalid_refs)})
assert outcomes[0]['accepted']and not outcomes[1]['accepted']
assert outcomes[1]['reason_code']=='wrong_reference_namespace'
for row in manifest:
    before=json.dumps(row['payload'],sort_keys=True)
    view=make_model_view(row['payload'])
    assert all('citation_id'not in o['observation_view']and'evidence_ids'not in o['observation_view']for o in view['observations'])
    assert json.dumps(row['payload'],sort_keys=True)==before
receipt={'schema':'reference-repair-offline-replay-v1','outcomes':outcomes,
    'private_original_records_unchanged':True,'all_five_model_views_projected':True,
    'original_protocol_rejection_preserved':True,'no_weak_reference_admission':True,
    'real_model_requests':0,'helper_sha256':hashlib.sha256((HERE/'reference_protocol.py').read_bytes()).hexdigest()}
(HERE/'reference-replay.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
