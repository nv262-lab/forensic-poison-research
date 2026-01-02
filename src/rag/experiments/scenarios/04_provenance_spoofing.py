import json, random
from pathlib import Path
SPOOFERS=[{"source":"unauthorized-collector"}]
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d.setdefault("meta",{}).update(random.choice(SPOOFERS))
        d["meta"]["experiment"]="provenance_spoofing"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
