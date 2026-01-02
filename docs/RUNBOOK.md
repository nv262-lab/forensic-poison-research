Runbook (human)

1. Generate demo keys: python tools/keygen_demo.py
2. Seed corpus: python src/rag/data/seed_generator.py
3. Build index: python -c "from src.rag.vectorstore.faiss_store import FaissStore; import json; docs=[json.loads(l) for l in open('src/rag/data/corpus/corpus.jsonl')]; FaissStore('data/faiss_index').build(docs)"
