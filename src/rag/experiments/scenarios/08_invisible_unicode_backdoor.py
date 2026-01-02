import json, random
from pathlib import Path
TRIGGERS=["\u200bZERO_WIDTH_BACKDOOR\u200b"]
def run(store_path="data/faiss_index", count=5):
    p=Path(store_path)/"docs.json"
    docs=json.load(open(p))
    picked=random.sample(docs, min(count,len(docs)))
    for d in picked:
        d["content"]=d["content"]+" "+random.choice(TRIGGERS)
        d.setdefault("meta",{})["experiment"]="invisible_unicode_backdoor"
    open(p,"w").write(json.dumps(docs, indent=2))
    return [d["id"] for d in picked]
