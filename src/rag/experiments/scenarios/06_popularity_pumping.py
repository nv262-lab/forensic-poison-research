import json, random
from pathlib import Path
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        m=d.setdefault("meta",{})
        m["popularity"]=m.get("popularity",0)+random.randint(200,1000)
        m["experiment"]="popularity_pumping"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
