from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib, json, os
PRIV_PATH = os.environ.get("RAG_RSA_PRIV","keys_demo/rsa_priv.pem")
PUB_PATH  = os.environ.get("RAG_RSA_PUB","keys_demo/rsa_pub.pem")
def rsa_sign_doc(doc):
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv_pem = open(PRIV_PATH,"rb").read()
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    payload = {"id":doc["id"], "hash": hashlib.sha256(doc["content"].encode()).hexdigest()}
    b = json.dumps(payload).encode()
    sig = priv.sign(b, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return sig.hex()
def rsa_verify_token(token_hex, doc):
    try:
        pub_pem = open(PUB_PATH,"rb").read()
        pub = serialization.load_pem_public_key(pub_pem)
        payload = {"id":doc["id"], "hash": hashlib.sha256(doc["content"].encode()).hexdigest()}
        b = json.dumps(payload).encode()
        sig = bytes.fromhex(token_hex)
        pub.verify(sig, b, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        return False
