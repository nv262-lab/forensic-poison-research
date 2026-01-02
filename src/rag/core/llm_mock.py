import hashlib, json
def deterministic_response(prompt, contexts):
    ctx_summary = " || ".join([c.get("content","")[:120] for c in contexts])
    h = hashlib.sha256((prompt + ctx_summary).encode()).hexdigest()[:8]
    return {"answer": f"LLM-MOCK-RESP-{h}", "meta": {"signature": h}}
