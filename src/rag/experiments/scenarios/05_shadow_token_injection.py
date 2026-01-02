import json, random
from pathlib import Path
TOKENS=["SERVICE_SHADOW_TOKEN_ABCDEF"]
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d.setdefault("meta",{})["shadow_token"]=random.choice(TOKENS)
        d["meta"]["experiment"]="shadow_token_injection"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
