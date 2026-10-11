"""Record final owned source/test hashes without opening evaluation labels."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent


def fingerprint():
    files={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ('src','tests')for p in sorted((ROOT/folder).rglob('*.py'))}
    return {'files':files,'sha256':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()}


def main():
    destination=HERE/'final-source-freeze.json'
    if destination.exists():raise FileExistsError('The final freeze is an immutable receipt')
    receipt={'schema':'recovery-final-source-freeze-v1','recorded_at_utc':datetime.now(timezone.utc).isoformat(),
        'scope':'All src/tests Python source; no evaluation/config content read by this recorder',
        **fingerprint()}
    destination.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'receipt':str(destination.relative_to(ROOT)),'files':len(receipt['files']),'sha256':receipt['sha256']}))


if __name__=='__main__':main()
