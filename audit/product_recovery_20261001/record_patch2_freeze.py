"""Keep the prior freeze and record the final typed-receipt revision separately."""
from datetime import datetime,timezone
import json
from pathlib import Path
from record_final_freeze import fingerprint

path=Path(__file__).resolve().parent/'final-source-freeze-patch2.json'
if path.exists():raise FileExistsError('Patch2 freeze already recorded')
receipt={'schema':'recovery-final-source-freeze-v1','revision':'patch2',
    'recorded_at_utc':datetime.now(timezone.utc).isoformat(),**fingerprint()}
path.write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'receipt':str(path),'files':len(receipt['files']),'sha256':receipt['sha256']}))
