import json
from pathlib import Path
from .utils import embed_texts
from .manifest import write_manifest
from ..detectors.integrity import rsa_sign_doc
from ..vectorstore.embeddings import embedding_hash
try:
    import faiss
except Exception:
    faiss = None
class FaissStore:
    def __init__(self, path="data/faiss_index"):
        self.path = Path(path)
        self.docs=[]
    def build(self, docs):
        texts=[d["content"] for d in docs]
        vecs = embed_texts(texts)
        manifest={}
        for i,d in enumerate(docs):
            d.setdefault("meta",{})
            d["meta"]["signed_token"]=rsa_sign_doc(d)
            d["meta"]["embedding_hash"]=embedding_hash(vecs[i])
            manifest[d["id"]]=d["meta"]["embedding_hash"]
        self.docs=docs
        self.path.mkdir(parents=True, exist_ok=True)
        with open(self.path/"docs.json","w") as f:
            json.dump(docs, f, indent=2)
        write_manifest(manifest)
        return True
    def search(self, q, top_k=5):
        return self.docs[:top_k]
