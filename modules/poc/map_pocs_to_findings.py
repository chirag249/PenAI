#!/usr/bin/env python3
"""
Improved mapper with:
 - scoring and single-best selection per PoC (or multi-attach)
 - fuzzy matching using difflib.SequenceMatcher
 - query-parameter match scoring
 - optional debug dump of top-N scores
Outputs final_report_with_pocs_map.json and diagnostics in <run>/reports/
"""
from __future__ import annotations
import json
import os
import sys
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from difflib import SequenceMatcher

# ---------- I/O helpers ----------
def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def find_pocs_file(run_dir: str) -> Optional[str]:
    rpt = os.path.join(run_dir, "reports")
    candidates = [
        os.path.join(rpt, "pocs_compact_unique.json"),
        os.path.join(rpt, "pocs_compact.json"),
        os.path.join(rpt, "pocs.json"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

def find_report_file(run_dir: str) -> Optional[str]:
    rpt = os.path.join(run_dir, "reports")
    candidates = [
        os.path.join(rpt, "final_report_with_pocs.json"),
        os.path.join(rpt, "final_report.json"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

# ---------- URL normalization helpers ----------
def normalize_url(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    u = u.strip()
    parsed = urllib.parse.urlparse(u)
    scheme = parsed.scheme
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if scheme:
        return urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))
    return (netloc + path).rstrip("/") if netloc or path else None

def url_path_only(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    parsed = urllib.parse.urlparse(u)
    net = (parsed.netloc or "").lower()
    path = (parsed.path or "").rstrip("/")
    return f"{net}{path}" if net else (path or None)

def host_only(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    parsed = urllib.parse.urlparse(u)
    return parsed.netloc.lower() if parsed.netloc else None

def parse_query_params(u: Optional[str]) -> Dict[str, List[str]]:
    if not u:
        return {}
    parsed = urllib.parse.urlparse(u)
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

# ---------- PoC compacting and dedupe ----------
def compact_poc(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "proof_url": p.get("proof_url") or p.get("target"),
        "finding_type": p.get("finding_type"),
        "status": p.get("status"),
    }

def unique_by_proof_url(pocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for p in pocs:
        pu = normalize_url(p.get("proof_url") or p.get("target"))
        pu = pu or (p.get("proof_url") or p.get("target"))
        if not pu:
            continue
        if pu in seen:
            continue
        seen.add(pu)
        p["_norm_proof_url"] = pu
        out.append(p)
    return out

# ---------- Scoring logic ----------
def fuzzy_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()

def query_param_score(p_pq: Dict[str, List[str]], f_pq: Dict[str, List[str]]) -> float:
    if not p_pq and not f_pq:
        return 0.0
    p_names = set(p_pq.keys())
    f_names = set(f_pq.keys())
    if not p_names and not f_names:
        return 0.0
    name_overlap = len(p_names & f_names)
    name_union = len(p_names | f_names) if (p_names | f_names) else 1
    name_score = name_overlap / name_union
    exact = 0
    total_values = 0
    for k in p_names & f_names:
        p_vals = set(p_pq.get(k, []))
        f_vals = set(f_pq.get(k, []))
        total_values += max(len(p_vals), len(f_vals))
        exact += len(p_vals & f_vals)
    value_score = (exact / total_values) if total_values else 0.0
    return (0.6 * name_score) + (0.4 * value_score)

def score_poc_against_finding(poc: Dict[str, Any], finding: Dict[str, Any]) -> float:
    W_EXACT  = 0.35   # still strong for exact canonical matches
    W_PATH   = 0.12   # path equality matters
    W_HOST   = 0.05   # small host boost
    W_SUBSTR = 0.08   # substring containment (medium)
    W_FUZZY   = 0.15  # fuzzy helps when URLs slightly vary
    W_QPARAM = 0.25   # boost query-param overlap (important)


    poc_url = poc.get("_norm_proof_url") or (poc.get("proof_url") or "")
    f_url = normalize_url(finding.get("used_url") or finding.get("target")) or ""

    score = 0.0

    if poc_url and f_url and poc_url == f_url:
        score += W_EXACT

    p_path = url_path_only(poc.get("proof_url"))
    f_path = url_path_only(finding.get("used_url") or finding.get("target"))
    if p_path and f_path and p_path == f_path:
        score += W_PATH

    hp = host_only(poc.get("proof_url"))
    hf = host_only(finding.get("used_url") or finding.get("target"))
    if hp and hf and hp == hf:
        score += W_HOST

    if poc_url and f_url and (poc_url in f_url or f_url in poc_url):
        score += W_SUBSTR

    fuzz = fuzzy_ratio(poc_url, f_url)
    score += W_FUZZY * fuzz

    p_q = parse_query_params(poc.get("proof_url"))
    f_q = parse_query_params(finding.get("used_url") or finding.get("target"))
    qscore = query_param_score(p_q, f_q)
    score += W_QPARAM * qscore

    return min(score, 1.0)

# ---------- Main mapping routine ----------
def map_pocs(run_dir: str, best_only: bool = True, accept_threshold: float = 0.5, dump_top_n: int = 0) -> Dict[str, Any]:
    run_dir = run_dir.rstrip("/")
    reports_dir = os.path.join(run_dir, "reports")
    if not os.path.isdir(reports_dir):
        raise SystemExit("reports directory not found: " + reports_dir)

    pocs_file = find_pocs_file(run_dir)
    if not pocs_file:
        raise SystemExit("No pocs file found in reports (pocs_compact_unique.json / pocs_compact.json / pocs.json)")

    pocs_raw = load_json(pocs_file)
    if isinstance(pocs_raw, dict) and "pocs" in pocs_raw:
        pocs_list = pocs_raw["pocs"]
    elif isinstance(pocs_raw, list):
        pocs_list = pocs_raw
    else:
        raise SystemExit("Unexpected pocs file structure: " + pocs_file)

    pocs = unique_by_proof_url(pocs_list)

    report_file = find_report_file(run_dir)
    if not report_file:
        raise SystemExit("No final_report file found in reports")
    final = load_json(report_file)

    findings = final.get("findings", [])
    for f in findings:
        f.setdefault("pocs", [])

    unmapped = []
    diagnostics = {"matches": [], "unmapped": []}

    for p in pocs:
        scores: List[Tuple[float, Dict[str, Any]]] = []
        for f in findings:
            sc = score_poc_against_finding(p, f)
            scores.append((sc, f))
        scores.sort(key=lambda x: x[0], reverse=True)
        if not scores:
            p["_unmapped"] = True
            unmapped.append(p)
            diagnostics["unmapped"].append({"poc": compact_poc(p)})
            continue

        top_score, top_finding = scores[0]
        attached = False
        cp = compact_poc(p)

        if best_only:
            if top_score >= accept_threshold:
                if not any(cp.get("proof_url") == ex.get("proof_url") for ex in top_finding["pocs"]):
                    top_finding["pocs"].append(cp)
                attached = True
                diagnostics["matches"].append({
                    "poc": cp, "finding_target": top_finding.get("used_url") or top_finding.get("target"),
                    "score": top_score, "attached_to": "best"
                })
        else:
            attached_any = False
            for sc, f in scores:
                if sc >= accept_threshold:
                    if not any(cp.get("proof_url") == ex.get("proof_url") for ex in f["pocs"]):
                        f["pocs"].append(cp)
                    attached_any = True
                    diagnostics["matches"].append({
                        "poc": cp, "finding_target": f.get("used_url") or f.get("target"),
                        "score": sc, "attached_to": "multi"
                    })
            attached = attached_any

        if dump_top_n and scores:
            topN = [{"score": sc, "finding_target": (f.get("used_url") or f.get("target")), "finding_type": f.get("type")} for sc, f in scores[:dump_top_n]]
        else:
            topN = []

        if not attached:
            p["_unmapped"] = True
            p["_suggested_match"] = {
                "score": top_score,
                "suggested_finding_target": top_finding.get("used_url") or top_finding.get("target"),
                "suggested_finding_type": top_finding.get("type"),
                "topN": topN,
            }
            unmapped.append(p)
            diagnostics["unmapped"].append({"poc": cp, "suggested": p["_suggested_match"]})

    unmapped_compact = []
    for p in unmapped:
        cp = compact_poc(p)
        if p.get("_suggested_match"):
            cp["suggested_match"] = p["_suggested_match"]
        unmapped_compact.append(cp)

    meta = final.get("meta") or {}
    meta["pocs"] = {
        "count": len(pocs),
        "file": os.path.relpath(pocs_file, run_dir),
        "unmapped_count": len(unmapped_compact),
    }
    if unmapped_compact:
        meta["pocs"]["unmapped"] = unmapped_compact

    final["meta"] = meta
    final["findings"] = findings

    out_path = os.path.join(reports_dir, "final_report_with_pocs_map.json")
    write_json(out_path, final)

    # write diagnostics debug file
    diagnostics_path = os.path.join(reports_dir, "pocs_mapping_debug.json")
    write_json(diagnostics_path, diagnostics)

    return {"report": out_path, "diagnostics": diagnostics_path, "attached_count": len(pocs) - len(unmapped_compact), "unmapped_count": len(unmapped_compact)}

# ---------- CLI ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python3 modules/poc/map_pocs_to_findings.py <run_dir> [--multi] [--threshold 0.5] [--dump-top N]")
        sys.exit(1)
    run_dir = sys.argv[1]
    best_only = True
    threshold = 0.5
    dump_n = 0
    if "--multi" in sys.argv:
        best_only = False
    if "--threshold" in sys.argv:
        try:
            idx = sys.argv.index("--threshold") + 1
            threshold = float(sys.argv[idx])
        except Exception:
            pass
    if "--dump-top" in sys.argv:
        try:
            idx = sys.argv.index("--dump-top") + 1
            dump_n = int(sys.argv[idx])
        except Exception:
            pass
    out = map_pocs(run_dir, best_only=best_only, accept_threshold=threshold, dump_top_n=dump_n)
    print("wrote", out["report"])
    print("diagnostics:", out["diagnostics"])
    print("attached:", out["attached_count"], "unmapped:", out["unmapped_count"])
