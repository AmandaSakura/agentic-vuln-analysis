"""Profile parsing and label-free candidate generation on existing real development checkouts."""
import json
from pathlib import Path
import sys
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from cv_agent.code_adapters import load_code_repository
from cv_agent.scanner import StaticScanner
from cv_agent.vulngym_subset import select_vulngym_subjects
from cv_agent.provenance import git_identity


def main():
    output=ROOT/'artifacts/development_source_profile'/uuid4().hex
    output.mkdir(parents=True)
    summaries=[]
    for subject in select_vulngym_subjects(ROOT/'data/raw/VulnGym/data/entries.jsonl'):
        checkout=ROOT/'data/subjects'/subject.slug/subject.commit
        identity=git_identity(checkout)
        if identity.revision!=subject.commit:
            raise ValueError(f'Unexpected checkout revision: {checkout}')
        repository=load_code_repository(subject.repository_url,checkout)
        candidates=StaticScanner().scan(subject.repository_url,repository.documents)
        (output/(subject.slug+'-candidates.json')).write_text(json.dumps(
            [candidate.model_dump(mode='json') for candidate in candidates],indent=2)+'\n')
        summary=dict(repository=subject.repository_url,identity=identity.model_dump(mode='json'),
            source_files=repository.source_file_count,documents=len(repository.documents),
            language_files=repository.language_file_counts,adapter_tier_files=repository.adapter_tier_file_counts,
            parse_error_paths=list(repository.parse_error_paths),candidate_count=len(candidates),
            detector_used_reference_locations=False,model_requests=0,claim_eligible=False)
        summaries.append(summary)
        print(f'{subject.slug}: files={repository.source_file_count} documents={len(repository.documents)} '
              f'candidates={len(candidates)} parse_errors={len(repository.parse_error_paths)}',flush=True)
    (output/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
    print(output)


if __name__=='__main__':
    main()
