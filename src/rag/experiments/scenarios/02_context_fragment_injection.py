import json, random
from pathlib import Path
FRAGMENTS=["TRIG-A-513","BEHAVIORAL_TRIGGER_07"]
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d["content"]=d["content"]+" -- "+random.choice(FRAGMENTS)
        d.setdefault("meta",{})["experiment"]="context_fragment_injection"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
