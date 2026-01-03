# src/rag/detectors/run_all.py
"""
Simple detection runner that scans collected cloud logs under data/logs/**
and emits SIEM events to a JSON file.

This is intentionally lightweight and rule-based so it works without external
dependencies. Replace or extend the detect function with real detectors.
"""

from _future_ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

LOG_ROOT = Path("data/logs")
DEFAULT_OUTPUT = Path("data/backups/siem_events.json")


def iter_log_files(root: Path = LOG_ROOT) -> Iterable[Path]:
    if not root.exists():
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix in {".log", ".txt", ".json", ".ndjson", ".jsonl"}:
            yield p


def read_lines(path: Path) -> Iterable[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line
    except Exception:
        return


def try_parse_json(s: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def basic_extract_fields(log_obj: Dict[str, Any], raw: str) -> Dict[str, Any]:
    # Normalize common fields if present
    fields = {}
    for k in ("timestamp", "time", "ts", "eventTime", "insertId"):
        if k in log_obj:
            fields["timestamp"] = log_obj[k]
            break
    for k in ("severity", "level"):
        if k in log_obj:
            fields["severity"] = log_obj[k]
            break
    for k in ("protoPayload", "message", "msg", "message_text", "text"):
        if k in log_obj:
            fields["message"] = log_obj.get(k)
            break
    # fallback
    if "message" not in fields:
        fields["message"] = raw
    return fields


# Rule set extended to cover the listed experiment scenarios.
RULES = [
    {
        "id": "suspicious_auth_failure",
        "description": "Repeated failed authentication or unauthorized access",
        "pattern": re.compile(r"unauthoriz|unauth|authentication failed|failed login", re.I),
        "severity": "high",
    },
    {
        "id": "s3_bucket_access",
        "description": "S3/GCS/Blob object access events",
        "pattern": re.compile(r"(s3|gs|blob).*object|storage.objects", re.I),
        "severity": "info",
    },
    {
        "id": "console_login",
        "description": "Console login detected (possible interactive access)",
        "pattern": re.compile(r"console.*login|login from|signIn", re.I),
        "severity": "medium",
    },
    {
        "id": "iam_changes",
        "description": "IAM or permission change event",
        "pattern": re.compile(r"(iam|role|policy|permission).*change|put-role|set-iam", re.I),
        "severity": "high",
    },
    {
        "id": "data_exfil",
        "description": "Large object read/download or suspicious data transfer",
        "pattern": re.compile(r"(GetObject|storage.objects.get|Download|read).*", re.I),
        "severity": "critical",
    },
    # Experiment-specific patterns (approximate/heuristic)
    {
        "id": "label_inversion",
        "description": "Possible label inversion poisoning indicators (unexpected labels/annotations)",
        "pattern": re.compile(r"label inversion|mislabeled|label.*changed|class.*flipped", re.I),
        "severity": "high",
    },
    {
        "id": "context_fragment_injection",
        "description": "Context fragment injection evidence (injected contextual snippets)",
        "pattern": re.compile(r"context fragment|injected snippet|injection.*context|malicious fragment", re.I),
        "severity": "high",
    },
    {
        "id": "embedding_attractor",
        "description": "Embedding attractor behavior (repeated similar vectors/tokens)",
        "pattern": re.compile(r"embedding attractor|similar vectors|repeated embeddings|vector cluster", re.I),
        "severity": "medium",
    },
    {
        "id": "provenance_spoofing",
        "description": "Provenance spoofing indicators (forged metadata/source)",
        "pattern": re.compile(r"provenance spoof|forged source|fake author|source spoof", re.I),
        "severity": "high",
    },
    {
        "id": "shadow_token_injection",
        "description": "Shadow token injection (unexpected tokens or credential material in logs)",
        "pattern": re.compile(r"shadow token|injected token|secret leak|api key leaked", re.I),
        "severity": "critical",
    },
    {
        "id": "popularity_pumping",
        "description": "Popularity pumping signs (unnatural traffic spikes or upvote manipulation)",
        "pattern": re.compile(r"popularity pump|vote spike|unnatural traffic|upvote.*spike", re.I),
        "severity": "medium",
    },
    {
        "id": "stale_signature_replay",
        "description": "Stale signature replay (replayed signed artifacts/old signatures used)",
        "pattern": re.compile(r"replay attack|stale signature|signature replay|old signature", re.I),
        "severity": "high",
    },
    {
        "id": "invisible_unicode_backdoor",
        "description": "Invisible unicode/backdoor patterns (zero-width/invisible chars in text)",
        "pattern": re.compile(r"zero-?width|zero_width|invisible unicode|\u200b|\u200c|\u200d", re.I),
        "severity": "high",
    },
    {
        "id": "delayed_activation_poison",
        "description": "Delayed activation poisoning (time-gated payloads or delayed triggers)",
        "pattern": re.compile(r"delayed activation|time-gated|time trigger|activate after|sleep.*payload", re.I),
        "severity": "high",
    },
    {
        "id": "cross_source_inconsistency",
        "description": "Cross-source inconsistency (mismatched metadata across sources)",
        "pattern": re.compile(r"cross[-_ ]source inconsistency|mismatch.*source|inconsistent provenance", re.I),
        "severity": "medium",
    },
]


def detect_log_entry(raw: str, source_path: Path) -> List[Dict[str, Any]]:
    events = []
    parsed = try_parse_json(raw)
    base = {"source": str(source_path)}
    if parsed:
        fields = basic_extract_fields(parsed, raw)
        msg = fields.get("message", "") or json.dumps(parsed)
    else:
        fields = {"message": raw}
        msg = raw

    # Apply rules
    for r in RULES:
        try:
            if r["pattern"].search(msg):
                ev = {
                    "id": r["id"],
                    "description": r["description"],
                    "severity": r["severity"],
                    "message": fields.get("message"),
                    "timestamp": fields.get("timestamp"),
                    "source_file": str(source_path),
                }
                # include raw JSON if parsed
                if parsed:
                    ev["raw"] = parsed
                events.append(ev)
        except Exception:
            continue

    return events


def run_all(output: str | Path = DEFAULT_OUTPUT) -> List[Dict[str, Any]]:
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_events: List[Dict[str, Any]] = []
    for f in iter_log_files(LOG_ROOT):
        for line in read_lines(f):
            try:
                events = detect_log_entry(line, f)
                all_events.extend(events)
            except Exception:
                # continue on per-line errors
                continue

    # Deduplicate simple duplicates
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for e in all_events:
        key = (e.get("id"), e.get("message"), e.get("source_file"), e.get("timestamp"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)

    # Write output
    try:
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump({"events": deduped, "count": len(deduped)}, fh, indent=2)
    except Exception as exc:
        raise RuntimeError(f"failed to write output {out_path}: {exc}")

    return deduped


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Run simple detectors over collected logs")
    p.add_argument("--output", "-o", default=str(DEFAULT_OUTPUT), help="Output JSON path")
    args = p.parse_args()
    events = run_all(output=args.output)
    print(f"Emitted {len(events)} SIEM events to {args.output}")
