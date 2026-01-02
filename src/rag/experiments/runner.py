import argparse, importlib, sys
SCENARIO_MAP = {
 "label_inversion":"src.rag.experiments.scenarios.01_label_inversion_attack",
 "context_fragment_injection":"src.rag.experiments.scenarios.02_context_fragment_injection",
 "embedding_attractor":"src.rag.experiments.scenarios.03_embedding_attractor_attack",
 "provenance_spoofing":"src.rag.experiments.scenarios.04_provenance_spoofing",
 "shadow_token_injection":"src.rag.experiments.scenarios.05_shadow_token_injection",
 "popularity_pumping":"src.rag.experiments.scenarios.06_popularity_pumping",
 "stale_signature_replay":"src.rag.experiments.scenarios.07_stale_signature_replay",
 "invisible_unicode_backdoor":"src.rag.experiments.scenarios.08_invisible_unicode_backdoor",
 "delayed_activation_poison":"src.rag.experiments.scenarios.09_delayed_activation_poison",
 "cross_source_inconsistency":"src.rag.experiments.scenarios.10_cross_source_inconsistency"
}
def run_scenario(key, store_path, count):
    module = importlib.import_module(SCENARIO_MAP[key])
    return module.run(store_path=store_path, count=count)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--scenarios", default="all")
    p.add_argument("--store-path", default="data/faiss_index")
    p.add_argument("--count", type=int, default=5)
    args=p.parse_args()
    keys = list(SCENARIO_MAP.keys()) if args.scenarios=="all" else [s.strip() for s in args.scenarios.split(",")]
    summary={}
    for k in keys:
        if k not in SCENARIO_MAP:
            print(f"Unknown scenario {k}", file=sys.stderr); continue
        print(f"Running scenario {k}")
        ids = run_scenario(k, args.store_path, args.count)
        summary[k]=ids
    print("Done. Summary:", summary)
if __name__=="__main__":
    main()
