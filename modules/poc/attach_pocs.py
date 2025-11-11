#!/usr/bin/env python3
"""
Attach PoCs to final report using the improved mapper.
If mapper is not available, does naive attach by exact proof_url -> finding URL match.
Returns a summary dict and writes final_report_with_pocs.json (and mapping diagnostic files via mapper).
"""
from __future__ import annotations
import json
import os
import sys
from typing import Any, Dict, List
from modules.poc.map_pocs_to_findings import map_pocs, find_pocs_file, find_report_file, load_json, write_json


def normalize_pocs_input(pocs_raw: Any) -> List[Dict[str, Any]]:
    """
    Accept either:
      - list of PoC dicts
      - { "pocs": [...] }
      - path to file (string)
    Return list of PoC dicts.
    """
    if isinstance(pocs_raw, str) and os.path.isfile(pocs_raw):
        return load_json(pocs_raw)
    if isinstance(pocs_raw, dict) and "pocs" in pocs_raw:
        return pocs_raw["pocs"]
    if isinstance(pocs_raw, list):
        return pocs_raw
    raise ValueError("Unsupported pocs input type")


def attach_pocs_to_report(run_dir: str,
                          best_only: bool = True,
                          threshold: float = 0.5,
                          dump_top_n: int = 0) -> Dict[str, Any]:
    run_dir = run_dir.rstrip("/")
    reports_dir = os.path.join(run_dir, "reports")
    if not os.path.isdir(reports_dir):
        raise SystemExit("reports directory not found: " + reports_dir)

    pocs_file = find_pocs_file(run_dir)
    if not pocs_file:
        raise SystemExit("No pocs file found in reports to attach")

    # --- Try intelligent mapper first ---
    try:
        try:
            # attempt full signature
            result = map_pocs(run_dir, best_only=best_only,
                              accept_threshold=threshold,
                              dump_top_n=dump_top_n)
        except TypeError:
            # fallback to simpler signature
            result = map_pocs(run_dir, best_only=best_only,
                              accept_threshold=threshold)

        summary = {
            "status": "mapped_with_mapper",
            "report": result.get("report"),
            "diagnostics": result.get("diagnostics"),
            "attached_count": result.get("attached_count"),
            "unmapped_count": result.get("unmapped_count"),
        }
        return summary
    except Exception:
        # --- Fallback: naive attach ---
        final_candidates = [os.path.join(reports_dir, "final_report_with_pocs.json"),
                            os.path.join(reports_dir, "final_report.json")]
        final = None
        for c in final_candidates:
            if os.path.isfile(c):
                final = load_json(c)
                break
        if final is None:
            raise SystemExit("No final report to attach PoCs to (fallback)")

        pocs_raw = load_json(pocs_file)
        pocs = normalize_pocs_input(pocs_raw)
        findings = final.get("findings", [])
        for f in findings:
            f.setdefault("pocs", [])

        attached = 0
        unmapped = []
        for p in pocs:
            if isinstance(p, str):
                if os.path.isfile(p):
                    try:
                        p = load_json(p)
                    except Exception:
                        p = {"proof_url": p}
                else:
                    p = {"proof_url": p}
            url = p.get("proof_url") or p.get("target")
            if not url:
                unmapped.append(p)
                continue
            normalized = url.strip().rstrip("/")
            attached_flag = False
            for f in findings:
                f_url = (f.get("used_url") or f.get("target") or "").strip().rstrip("/")
                if not f_url:
                    continue
                if normalized == f_url:
                    cp = {
                        "proof_url": url,
                        "finding_type": p.get("finding_type"),
                        "status": p.get("status"),
                    }
                    if not any(cp.get("proof_url") == ex.get("proof_url")
                               for ex in f["pocs"]):
                        f["pocs"].append(cp)
                        attached += 1
                    attached_flag = True
            if not attached_flag:
                unmapped.append(p)

        final["findings"] = findings
        meta = final.get("meta", {})
        meta["pocs"] = {
            "count": len(pocs),
            "file": os.path.relpath(pocs_file, run_dir),
            "unmapped_count": len(unmapped),
        }
        if unmapped:
            meta["pocs"]["unmapped"] = [
                {"proof_url": (p.get("proof_url") or p.get("target")),
                 "status": p.get("status")}
                for p in unmapped
            ]
        final["meta"] = meta

        out = os.path.join(reports_dir, "final_report_with_pocs.json")
        write_json(out, final)
        return {
            "status": "fallback_attached",
            "report": out,
            "attached_count": attached,
            "unmapped_count": len(unmapped),
        }


# CLI helper
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python3 modules/poc/attach_pocs.py <run_dir> [--multi] [--threshold 0.5] [--dump-top N]")
        sys.exit(1)
    rd = sys.argv[1]
    best = True
    th = 0.5
    dump = 0
    if "--multi" in sys.argv:
        best = False
    if "--threshold" in sys.argv:
        try:
            idx = sys.argv.index("--threshold") + 1
            th = float(sys.argv[idx])
        except Exception:
            pass
    if "--dump-top" in sys.argv:
        try:
            idx = sys.argv.index("--dump-top") + 1
            dump = int(sys.argv[idx])
        except Exception:
            pass
    res = attach_pocs_to_report(rd, best_only=best, threshold=th, dump_top_n=dump)
    print("attach summary:", res)
