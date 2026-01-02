from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib, json, os

PRIV_PATH = "keys_demo/rsa_priv.pem"
PUB_PATH = "keys_demo/rsa_pub.pem"

def _read_key(env_name, default_path):
    val = os.environ.get(env_name)
    if not val:
        return open(default_path, "rb").read()
    v = val.strip()
    # treat as PEM contents if it starts with PEM header, otherwise treat as path
    if v.startswith("-----BEGIN"):
        return v.encode()
    return open(v, "rb").read()

def rsa_sign_doc(doc):
    priv_pem = _read_key("RAG_RSA_PRIV", PRIV_PATH)
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    payload = {"id": doc["id"], "hash": hashlib.sha256(doc["content"].encode()).hexdigest()}
    b = json.dumps(payload, sort_keys=True).encode()
    sig = priv.sign(
        b,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return sig.hex()

def rsa_verify_token(token_hex, doc):
    try:
        pub_pem = _read_key("RAG_RSA_PUB", PUB_PATH)
        pub = serialization.load_pem_public_key(pub_pem)
        payload = {"id": doc["id"], "hash": hashlib.sha256(doc["content"].encode()).hexdigest()}
        b = json.dumps(payload, sort_keys=True).encode()
        sig = bytes.fromhex(token_hex)
        pub.verify(
            sig,
            b,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
