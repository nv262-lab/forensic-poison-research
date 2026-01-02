BLOCKLIST_MARKERS = ["POISON_INDICATOR", "INVISIBLE_TRIGGER", "PROVENANCE_SPOOF", "EMBED_ATTRACTOR"]
def guard(prompt, contexts):
    reasons=[]
    for c in contexts:
        for m in BLOCKLIST_MARKERS:
            if m in c.get("content",""):
                reasons.append(m)
    return (len(reasons)==0), reasons
