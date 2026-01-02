from src.rag.data.seed_generator import generate
from src.rag.detectors.integrity import rsa_sign_doc, rsa_verify_token
def test_rsa_sign_verify(tmp_path):
    out = generate(n_clean=5, per_scenario=1)
    docs = [__import__('json').loads(l) for l in open(out)]
    d = docs[0]
    token = rsa_sign_doc(d)
    assert rsa_verify_token(token, d)
