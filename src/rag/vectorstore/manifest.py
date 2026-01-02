import json, os
from pathlib import Path
MANIFEST_PATH = Path("data/faiss_index/manifest.json")
PRIV_PATH = os.environ.get("RAG_RSA_PRIV","keys_demo/rsa_priv.pem")
PUB_PATH  = os.environ.get("RAG_RSA_PUB","keys_demo/rsa_pub.pem")
def write_manifest(manifest):
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH,"w") as f:
        json.dump({"manifest": manifest}, f)
    return True
