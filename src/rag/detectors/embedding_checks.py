import json
from ..vectorstore.embeddings import embedding_hash
def check_embedding_consistency(doc, vec):
    h = embedding_hash(vec)
    try:
        data = json.load(open("data/faiss_index/manifest.json"))
        manifest = data.get("manifest", {})
        exp = manifest.get(doc["id"])
        return (exp == h), exp
    except Exception:
        return False, None
