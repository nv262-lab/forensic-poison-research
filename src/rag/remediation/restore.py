import sys
import json
import argparse
from pathlib import Path
from ..vectorstore.faiss_store import FaissStore

SUPPORTED_CLOUDS = {"aws", "gcp", "azure", "local"}

def validate_cloud_arg(cloud: str):
    if not cloud:
        print("ERROR: --cloud is required. Supported values: aws, gcp, azure, local", file=sys.stderr)
        sys.exit(2)
    if cloud not in SUPPORTED_CLOUDS:
        print(f"ERROR: Unsupported cloud '{cloud}'. Supported values: {', '.join(sorted(SUPPORTED_CLOUDS))}", file=sys.stderr)
        sys.exit(2)

def restore_local(backup="data/backups/faiss_docs.json", store_path="data/faiss_index"):
    b = Path(backup)
    if not b.exists():
        raise SystemExit("Backup missing: " + backup)
    Path(store_path).mkdir(parents=True, exist_ok=True)
    docs = json.load(open(b))
    with open(Path(store_path) / "docs.json", "w") as f:
        json.dump(docs, f, indent=2)
    FaissStore(store_path).build(docs)
    print("Restored and rebuilt local FAISS store.")

def main():
    parser = argparse.ArgumentParser(description="Restore remediation data")
    parser.add_argument("--sandbox-prefix", required=True)
    parser.add_argument("--cloud", required=True, help="Target cloud: aws, gcp, azure, local")
    args = parser.parse_args()

    validate_cloud_arg(args.cloud)

    # Dispatch by cloud. Extend these branches to implement real cloud restores.
    if args.cloud == "local":
        restore_local()
    elif args.cloud == "aws":
        # Placeholder: use local restore for now, or implement AWS-specific logic here.
        print("INFO: Running AWS restore using local restore logic (placeholder).")
        restore_local()
    else:
        # gcp/azure: not yet implemented
        print(f"ERROR: Restore for '{args.cloud}' not implemented.", file=sys.stderr)
        sys.exit(3)

if _name_ == "_main_":
    main()
