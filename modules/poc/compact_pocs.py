#!/usr/bin/env python3
# modules/poc/compact_pocs.py
import json, os, sys

def compact(run_dir):
    p = os.path.join(run_dir, "reports", "pocs.json")
    out = os.path.join(run_dir, "reports", "pocs_compact.json")
    if not os.path.exists(p):
        raise SystemExit("pocs.json not found")
    with open(p) as f:
        data = json.load(f)
    seen = set()
    compacted = []
    for item in data:
        key = item.get("proof_url") or item.get("target")
        if not key or key in seen: 
            continue
        seen.add(key)
        compacted.append({
            "proof_url": key,
            "finding_type": item.get("finding_type"),
            "target": item.get("target"),
            "status": (item.get("captured") or {}).get("status"),
            "snippet": ((item.get("captured") or {}).get("snippet") or "")[:200]
        })
    with open(out, "w") as f:
        json.dump({"count": len(compacted), "pocs": compacted}, f, indent=2)
    print(out)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 modules/poc/compact_pocs.py runs/<domain>/<run>")
        raise SystemExit(2)
    compact(sys.argv[1])
