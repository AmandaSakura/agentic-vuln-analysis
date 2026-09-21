"""Explicit repair of broken development worktree pointers; never checkout or overwrite source files."""
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from cv_agent.vulngym_subset import select_vulngym_subjects
from cv_agent.provenance import git_identity


def git(checkout,*args):
    subprocess.run(['git','-C',str(checkout),*args],check=True,timeout=180)


def main():
    backup=ROOT/'data/development_git_pointer_backups'
    backup.mkdir(exist_ok=True)
    records=[]
    for subject in select_vulngym_subjects(ROOT/'data/raw/VulnGym/data/entries.jsonl'):
        checkout=ROOT/'data/subjects'/subject.slug/subject.commit
        pointer=checkout/'.git'
        old=pointer.read_text()
        if not old.startswith('gitdir: '):
            raise ValueError(f'Expected a broken worktree pointer: {pointer}')
        target=Path(old.strip().removeprefix('gitdir: '))
        if target.exists():
            raise ValueError(f'Refusing to replace an existing Git metadata target: {target}')
        saved=backup/(subject.slug+'-'+subject.commit+'.git-pointer')
        with saved.open('x') as handle:
            handle.write(old)
        pointer.unlink()  # only the already-broken Git pointer, not repository source
        git(checkout,'init','--quiet','--initial-branch=restored')
        git(checkout,'remote','add','origin',subject.repository_url)
        git(checkout,'fetch','--quiet','--depth=1','origin',subject.commit)
        git(checkout,'update-ref','--no-deref','HEAD',subject.commit)
        git(checkout,'read-tree',subject.commit)  # index only: preserve every source byte
        identity=git_identity(checkout)
        if identity.revision!=subject.commit:
            raise ValueError(f'Restored revision mismatch: {checkout}')
        records.append(dict(repository=subject.repository_url,identity=identity.model_dump(mode='json'),
                            original_pointer_backup=str(saved),source_files_overwritten=False))
        print(f'{subject.slug}: revision={identity.revision} dirty={identity.dirty}',flush=True)
    report=ROOT/'artifacts/development_git_metadata_repair.json'
    report.write_text(json.dumps(records,indent=2)+'\n')
    print(report)


if __name__=='__main__':
    main()
