import json
from pathlib import Path
from ..vectorstore.faiss_store import FaissStore
def restore_local(backup="data/backups/faiss_docs.json", store_path="data/faiss_index"):
    b=Path(backup)
    if not b.exists(): raise SystemExit("Backup missing: "+backup)
    Path(store_path).mkdir(parents=True, exist_ok=True)
    docs=json.load(open(b))
    with open(Path(store_path)/"docs.json","w") as f: json.dump(docs, f, indent=2)
    FaissStore(store_path).build(docs)
    print("Restored and rebuilt local FAISS store.")
if __name__=="__main__":
    restore_local()
