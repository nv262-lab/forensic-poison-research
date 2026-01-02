import json, random
from pathlib import Path
SOURCES=["aws://bucket/doc","gcp://bucket/doc"]
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d.setdefault("meta",{})["canonical_source"]=random.choice(SOURCES)
        d["meta"]["experiment"]="cross_source_inconsistency"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
