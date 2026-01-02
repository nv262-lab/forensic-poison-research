import json
from pathlib import Path
def quarantine(doc_id, store_path="data/faiss_index"):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    found=[d for d in docs if d["id"]==doc_id]
    if not found: return False
    remaining=[d for d in docs if d["id"]!=doc_id]
    qdir=Path(store_path)/"quarantine"; qdir.mkdir(parents=True, exist_ok=True)
    with open(qdir/f"{doc_id}.json","w") as f: json.dump(found[0], f, indent=2)
    with open(p,"w") as f: json.dump(remaining, f, indent=2)
    return True
