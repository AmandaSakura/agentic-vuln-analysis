"""Model-facing observation references; source/fact IDs carry no producer identity."""
import json
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,ValidationError

SYSTEM='''Read the supplied source slice and registered observation_view.
Determine only whether that observation establishes its declared bounded predicate.
Pattern presence, local coverage, unresolved dependencies or unsupported semantics
cannot establish a strong result. Do not assess whole-application safety,
exploitability or remote reachability. Do not propose attacks, patches or actions.
The only permitted output references are exact strings in available_evidence_refs.
Every observations item has an observation_ref from that list. Copy that exact ID.
Never copy tool-internal evidence_ids, source/fact labels, citation_id, source paths,
candidate_id or invented strings into evidence_refs. These are distinct namespaces.
No tools are available. Return one JSON object only with exactly these fields:
candidate_id (the supplied exact ID), property_state (SUPPORTED, REFUTED, UNKNOWN,
or CONFLICT), evidence_refs (subset of available_evidence_refs), reasoning (brief
factual explanation), limitation (remaining scope boundary). A strong state requires
matching observation references and sufficient registered evidence. Never treat an
unresolved observation as safety. Unknown facts stay UNKNOWN.'''


class Proposal(BaseModel):
    model_config=ConfigDict(extra='forbid')
    candidate_id:str
    property_state:Literal['SUPPORTED','REFUTED','UNKNOWN','CONFLICT']
    evidence_refs:list[str]
    reasoning:str=Field(min_length=1)
    limitation:str=Field(min_length=1)


class ProposalProtocolError(ValueError):
    def __init__(self,reason_code,*,invalid_refs=(),proposed=None):
        self.reason_code=reason_code
        self.invalid_refs=tuple(invalid_refs)
        self.proposed=proposed
        super().__init__(reason_code)


def make_model_view(payload):
    """Project presentation only; leave the original private record untouched."""
    refs=list(payload['available_evidence_refs'])
    if len(refs)!=1:raise ValueError('This pilot requires exactly one complete original observation')
    observation={key:value for key,value in payload['original_observation'].items()
        if key not in {'citation_id','evidence_ids'}}
    return {'candidate_id':payload['candidate_id'],'contract':payload['contract'],
        'operation_locator':payload['operation_locator'],'source_slice':payload['source_slice'],
        'reference_namespace':'producer-observation-only-v1','available_evidence_refs':refs,
        'observations':[{'observation_ref':refs[0],'observation_view':observation,
            'omitted_identity_fields':['citation_id','evidence_ids'],
            'complete_original_record_retained_locally':True}]}


def validate_proposal(content,payload):
    try:raw=json.loads(content)
    except (ValueError,TypeError)as error:
        raise ProposalProtocolError('reply_not_json')from error
    try:proposal=Proposal.model_validate(raw)
    except ValidationError as error:
        raise ProposalProtocolError('reply_schema_invalid',proposed=raw)from error
    value=proposal.model_dump()
    if proposal.candidate_id!=payload['candidate_id']:
        raise ProposalProtocolError('candidate_identity_mismatch',proposed=value)
    invalid=set(proposal.evidence_refs)-set(payload['available_evidence_refs'])
    if invalid:
        raise ProposalProtocolError('wrong_reference_namespace',invalid_refs=sorted(invalid),proposed=value)
    if proposal.property_state in {'SUPPORTED','REFUTED','CONFLICT'}and not proposal.evidence_refs:
        raise ProposalProtocolError('strong_state_missing_observation_reference',proposed=value)
    return proposal
