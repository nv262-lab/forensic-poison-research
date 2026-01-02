import numpy as np
from ..vectorstore.utils import embed_texts
def drift_score(current_texts, baseline_centroid):
    cur = embed_texts(current_texts).mean(axis=0)
    base = baseline_centroid
    denom = (np.linalg.norm(cur)*np.linalg.norm(base))
    if denom==0: return 1.0
    cos = (cur @ base) / denom
    return 1.0 - cos
