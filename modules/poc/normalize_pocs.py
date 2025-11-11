#!/usr/bin/env python3
"""
PoC normalizer.

Provides a callable function `normalize_pocs(run_dir)` which:
 - reads PoCs from known report files (reports/pocs.json or runs/.../pocs_*.json)
 - writes compact outputs:
     reports/pocs_compact.json        (list of compact PoC dicts)
     reports/pocs_compact_unique.json (deduped by normalized proof_url)
     reports/pocs_index.json          (map proof_url -> PoC)
Returns a dict summary for programmatic use.

This is intentionally conservative and non-destructive.
"""
from __future__ import annotations
import json
import os
import urllib.parse
from typing import Any, Dict, List, Optional


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)


def find_pocs_sources(run_dir: str) -> List[str]:
    rpt = os.path.join(run_dir, "reports")
    candidates = [
        os.path.join(rpt, "pocs.json"),
        os.path.join(rpt, "pocs_compact.json"),
        os.path.join(rpt, "pocs_index.json"),
    ]
    out = []
    for c in candidates:
        if os.path.isfile(c):
            out.append(c)
    return out


def normalize_url(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    u = u.strip()
    parsed = urllib.parse.urlparse(u)
    scheme = parsed.scheme or "http"
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or ""
    # strip trailing slash except root
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = parsed.query or ""
    return urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))


def compact_poc(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "proof_url": p.get("proof_url") or p.get("target") or p.get("url") or None,
        "finding_type": p.get("finding_type") or p.get("type") or p.get("category"),
        "status": p.get("status") or "unknown",
        # preserve raw for traceability (not required)
        "raw": p,
    }


def unique_by_proof_url(pocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for p in pocs:
        pu = normalize_url(p.get("proof_url") or p.get("target") or p.get("url"))
        pu = pu or (p.get("proof_url") or p.get("target") or p.get("url"))
        if not pu:
            # fallback: use stringified raw as dedupe key
            pu = json.dumps(p.get("raw") or p, sort_keys=True)
        if pu in seen:
            continue
        seen.add(pu)
        p["_norm_proof_url"] = pu
        out.append(p)
    return out


def normalize_pocs(run_dir: str) -> Dict[str, Any]:
    """
    Main entrypoint. Reads available PoC files and writes compact/unique/index outputs.
    Returns a summary dict.
    """
    run_dir = run_dir.rstrip("/")
    reports_dir = os.path.join(run_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # gather source PoC lists
    srcs = find_pocs_sources(run_dir)
    pocs_raw: List[Dict[str, Any]] = []

    for s in srcs:
        try:
            j = load_json(s)
            # accept different shapes
            if isinstance(j, dict) and "pocs" in j and isinstance(j["pocs"], list):
                pocs_raw.extend(j["pocs"])
            elif isinstance(j, list):
                pocs_raw.extend(j)
            elif isinstance(j, dict) and "results" in j and isinstance(j["results"], list):
                pocs_raw.extend(j["results"])
            else:
                # attempt to scan for plausible PoC objects in dict values
                for v in (j.values() if isinstance(j, dict) else []):
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and ("proof_url" in item or "target" in item or "url" in item):
                                pocs_raw.append(item)
        except Exception:
            # skip unreadable files
            continue

    # fallback: try to read runs/*/pocs/*.json if no reports file present
    if not pocs_raw:
        alt_dir = os.path.join(run_dir, "pocs")
        if os.path.isdir(alt_dir):
            for fname in os.listdir(alt_dir):
                if fname.endswith(".json"):
                    try:
                        j = load_json(os.path.join(alt_dir, fname))
                        if isinstance(j, list):
                            pocs_raw.extend(j)
                        elif isinstance(j, dict):
                            # if has 'pocs' key
                            if "pocs" in j and isinstance(j["pocs"], list):
                                pocs_raw.extend(j["pocs"])
                    except Exception:
                        continue

    # compact
    compacted = [compact_poc(p if isinstance(p, dict) else {}) for p in pocs_raw]

    # write compact list
    compact_path = os.path.join(reports_dir, "pocs_compact.json")
    write_json(compact_path, {"count": len(compacted), "pocs": compacted})

    # unique by normalized proof_url
    unique = unique_by_proof_url(compacted)
    unique_path = os.path.join(reports_dir, "pocs_compact_unique.json")
    write_json(unique_path, {"count": len(unique), "pocs": unique})

    # index by normalized proof_url
    index: Dict[str, Dict[str, Any]] = {}
    for p in unique:
        key = p.get("_norm_proof_url") or (p.get("proof_url") or "")
        index[key] = p
    index_path = os.path.join(reports_dir, "pocs_index.json")
    write_json(index_path, {"count": len(index), "index": index})

    summary = {
        "wrote": {
            "compact": os.path.relpath(compact_path, run_dir),
            "unique": os.path.relpath(unique_path, run_dir),
            "index": os.path.relpath(index_path, run_dir),
        },
        "counts": {"raw": len(pocs_raw), "compacted": len(compacted), "unique": len(unique)},
    }
    return summary


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: normalize_pocs.py <run_dir>")
        sys.exit(1)
    print(normalize_pocs(sys.argv[1]))
