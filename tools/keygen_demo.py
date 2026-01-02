#!/usr/bin/env python3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
p=Path("keys_demo"); p.mkdir(parents=True, exist_ok=True)
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
pub = priv.public_key()
pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
(p/"rsa_priv.pem").write_bytes(priv_pem); (p/"rsa_pub.pem").write_bytes(pub_pem)
print("Demo RSA keys written to keys_demo/")
