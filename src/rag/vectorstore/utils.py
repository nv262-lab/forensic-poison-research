from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
def embed_texts(texts, max_features=384):
    vec = TfidfVectorizer(max_features=max_features, lowercase=True, ngram_range=(1,2))
    X = vec.fit_transform(texts).toarray()
    norms = (X**2).sum(axis=1, keepdims=True)**0.5
    norms[norms==0]=1.0
    return (X / norms).astype('float32')
