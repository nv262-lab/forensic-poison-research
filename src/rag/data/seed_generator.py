import json, uuid, random
from pathlib import Path
from datetime import datetime
BASE = Path(__file__).parent
OUT = BASE / "corpus"
OUT.mkdir(exist_ok=True, parents=True)
TEMPLATES = json.load(open(BASE/"templates"/"poison_templates.json"))
def make_doc(content, meta=None):
    return {"id": str(uuid.uuid4()), "content": content, "meta": meta or {"signed": False, "source":"synthetic"}}
def generate(n_clean=100, per_scenario=2):
    docs=[]
    for i in range(n_clean):
        docs.append(make_doc(f"Neutral synthetic document #{i} timestamp {datetime.utcnow().isoformat()}"))
    for k, arr in TEMPLATES.items():
        for i in range(per_scenario):
            s = random.choice(arr)
            content = f"{s} -- simulated attack {k} instance {i}"
            meta = {"signed": False, "experiment": k}
            docs.append(make_doc(content, meta))
    out = OUT / "corpus.jsonl"
    with open(out, "w") as f:
        for d in docs:
            f.write(json.dumps(d)+"\n")
    print(f"Wrote {len(docs)} docs to {out}")
    return out
if __name__=="__main__":
    generate()
