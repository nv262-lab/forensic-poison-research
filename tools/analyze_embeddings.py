#!/usr/bin/env python3
import json, sys
p=sys.argv[1] if len(sys.argv)>1 else "data/faiss_index"
try:
    docs=json.load(open(p+"/docs.json"))
    print(f"Index has {len(docs)} documents.")
except Exception as e:
    print("No index/docs found:", e)
