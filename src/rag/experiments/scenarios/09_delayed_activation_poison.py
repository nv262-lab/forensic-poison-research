import json, random
from pathlib import Path
from datetime import datetime, timedelta
def run(store_path="data/faiss_index", count=5, delay_seconds=10):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d.setdefault("meta",{})["delayed_activate_at"]=(datetime.utcnow()+timedelta(seconds=delay_seconds)).isoformat()
        d["meta"]["experiment"]="delayed_activation_poison"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
