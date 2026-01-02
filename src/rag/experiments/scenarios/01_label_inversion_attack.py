import json, random
from pathlib import Path
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    clean=[d for d in docs if d.get("meta",{}).get("experiment") is None]
    picked=random.sample(clean, min(count, len(clean)))
    for d in picked:
        d.setdefault("meta",{})["label"]="adversarial-label"
        d["meta"]["experiment"]="label_inversion"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
