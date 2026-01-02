import hashlib
def embedding_hash(vec):
    return hashlib.sha256(vec.tobytes()).hexdigest()
