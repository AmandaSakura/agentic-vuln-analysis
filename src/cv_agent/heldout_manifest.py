"""Separate real-project detector inputs from evaluator-only vulnerability labels."""
from urllib.parse import urlparse


def repository_key(url):
    parsed=urlparse(url)
    parts=parsed.path.rstrip('/').removesuffix('.git').split('/')
    if parsed.scheme != 'https' or parsed.netloc.lower() != 'github.com' or len(parts)!=3:
        raise ValueError(f'Unsupported repository identity: {url}')
    return 'https://github.com/'+parts[1].lower()+'/'+parts[2].lower()


def prepare_heldout(rows, development_repositories):
    development={repository_key(url) for url in development_repositories}
    development_advisories={row['report_id'] for row in rows if repository_key(row['repo_url']) in development}
    labels={}
    excluded=[]
    subjects=set()
    seen=set()
    for row in rows:
        case_id=row['entry_id']
        if case_id in seen:
            raise ValueError(f'Duplicate entry identity: {case_id}')
        seen.add(case_id)
        repository=repository_key(row['repo_url'])
        reason = ('unverified' if row.get('verify') not in (1,True) else
                  'development_repository' if repository in development else
                  'development_advisory' if row['report_id'] in development_advisories else None)
        if reason:
            excluded.append(dict(entry_id=case_id,reason=reason))
            continue
        labels[case_id]=row
        subjects.add((repository,row['commit']))
    inputs=[dict(repository_url=repository,commit=commit) for repository,commit in sorted(subjects)]
    summary=dict(total_entries=len(rows),heldout_positive_entries=len(labels),
        heldout_repositories=len({repository for repository,_ in subjects}),
        heldout_advisories=len({(repository_key(row['repo_url']),row['report_id']) for row in labels.values()}),
        subject_checkouts=len(inputs),excluded_entries=len(excluded),verified_fixed_negatives=0,
        claim_eligible=False,
        limitations=['Dataset-supplied verification has not been independently reproduced.',
                     'No verified fixed counterparts are prepared; false-positive rate is not estimable.',
                     'No held-out model evaluation has been run.'])
    return dict(detector_inputs=inputs,evaluator_labels=labels,excluded=excluded,summary=summary)
