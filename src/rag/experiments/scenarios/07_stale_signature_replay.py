import json, random
from pathlib import Path
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d["content"]=d["content"]+" [MODIFIED_BUT_OLD_SIG]"
        d.setdefault("meta",{})["experiment"]="stale_signature_replay"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
