from src.rag.data.seed_generator import generate
from src.rag.vectorstore.faiss_store import FaissStore
def test_build_and_search(tmp_path):
    out = generate(n_clean=10, per_scenario=1)
    docs = [__import__('json').loads(l) for l in open(out)]
    store = FaissStore(path=str(tmp_path/"index"))
    store.build(docs)
    hits = store.search("synthetic", top_k=3)
    assert isinstance(hits, list)
