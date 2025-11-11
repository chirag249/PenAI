#!/usr/bin/env python3
"""
modules/poc/curate_findings.py

Usage:
  python3 modules/poc/curate_findings.py runs/<domain>/<run-id>

Example:
  python3 modules/poc/curate_findings.py runs/testphp.vulnweb.com/poc3
"""
import sys
import json
import os
from pathlib import Path
from datetime import datetime

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def write_md(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def key_for_finding(f):
    # canonical url to dedupe on
    u = f.get("used_url") or f.get("target") or ""
    t = f.get("type") or ""
    return f"{t}::{u}"

def find_best_poc_for(finding, pocs_by_url):
    # prefer proof_url == used_url, else proof_url == target, else any poc containing the host
    used = finding.get("used_url") or finding.get("target")
    if not used:
        return None
    if used in pocs_by_url:
        return pocs_by_url[used][0]
    # fallback: match by target host substring
    for url, plist in pocs_by_url.items():
        if url and (url in used or used in url):
            return plist[0]
    # nothing matching
    return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 modules/poc/curate_findings.py runs/<domain>/<run-id>")
        sys.exit(1)

    run_dir = Path(sys.argv[1])
    if not run_dir.exists() or not run_dir.is_dir():
        print("Run directory not found:", run_dir)
        sys.exit(1)

    reports_dir = run_dir / "reports"
    if not reports_dir.exists():
        print("Reports directory not found:", reports_dir)
        sys.exit(1)

    # try to locate existing report that contains findings + pocs
    candidates = [
        reports_dir / "final_report_with_pocs_map.json",
        reports_dir / "final_report_with_pocs.json",
        reports_dir / "final_report.json",
    ]
    report = None
    for c in candidates:
        if c.exists():
            try:
                report = load_json(c)
                print("Loaded report:", c.name)
                break
            except Exception as e:
                print("Failed to load", c, e)
    if report is None:
        print("No usable final report found in", reports_dir)
        sys.exit(1)

    # Find pocs array either embedded or in companion file
    pocs = report.get("pocs") or report.get("meta", {}).get("pocs") or None
    if not pocs:
        alt = reports_dir / "pocs_compact.json"
        if alt.exists():
            pocs = load_json(alt).get("pocs") if isinstance(load_json(alt), dict) and "pocs" in load_json(alt) else load_json(alt)
            print("Loaded companion pocs_compact.json")
    if not pocs:
        # try pocs.json
        alt2 = reports_dir / "pocs.json"
        if alt2.exists():
            pocs = load_json(alt2)
            print("Loaded companion pocs.json")
    pocs = pocs or []

    # Index pocs by proof_url (preserve list in case multiple)
    pocs_by_url = {}
    for p in pocs:
        if not isinstance(p, dict):
            continue
        url = p.get("proof_url") or p.get("target") or p.get("url") or ""
        if url not in pocs_by_url:
            pocs_by_url[url] = []
        pocs_by_url[url].append(p)

    findings = report.get("findings") or []
    if not isinstance(findings, list):
        print("Report findings missing or not a list")
        sys.exit(1)

    # Dedupe: keep highest severity for same (type,url) key
    dedup = {}
    for f in findings:
        k = key_for_finding(f)
        existing = dedup.get(k)
        if existing is None:
            dedup[k] = dict(f)  # copy
        else:
            # compare severity (int), missing severity treated as -1
            s_new = f.get("severity", -1) if isinstance(f.get("severity", None), int) else (int(f.get("severity")) if isinstance(f.get("severity"), str) and f.get("severity").isdigit() else -1)
            s_old = existing.get("severity", -1) if isinstance(existing.get("severity", None), int) else (int(existing.get("severity")) if isinstance(existing.get("severity"), str) and existing.get("severity").isdigit() else -1)
            if s_new > s_old:
                dedup[k] = dict(f)

    curated_findings = []
    for k, f in dedup.items():
        fcopy = dict(f)
        # attach one PoC if available
        poc = find_best_poc_for(fcopy, pocs_by_url)
        if poc:
            fcopy["poc"] = {
                "proof_url": poc.get("proof_url") or poc.get("target") or poc.get("url"),
                "status": poc.get("status"),
                "raw": poc
            }
        else:
            fcopy["poc"] = None
        curated_findings.append(fcopy)

    # Sort curated findings by severity desc, then type
    curated_findings.sort(key=lambda x: (-(x.get("severity") or 0), x.get("type") or ""))

    out_json = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source_report": c.name if 'c' in locals() else None,
        "curated_count": len(curated_findings),
        "findings": curated_findings
    }

    out_json_path = reports_dir / "final_report_curated.json"
    out_md_path = reports_dir / "final_report_curated.md"

    write_json(out_json_path, out_json)

    # build markdown summary
    md_lines = []
    md_lines.append(f"# Curated Findings — {run_dir.name}")
    md_lines.append("")
    md_lines.append(f"Generated: {out_json['generated_at']}")
    md_lines.append("")
    md_lines.append("| # | Type | Target | Severity | PoC URL | PoC status |")
    md_lines.append("|---:|---|---|---:|---|---|")
    for i, f in enumerate(curated_findings, start=1):
        t = f.get("type","")
        u = (f.get("used_url") or f.get("target") or "")
        s = f.get("severity")
        poc = f.get("poc")
        poc_url = poc.get("proof_url") if poc else ""
        poc_status = poc.get("status") if poc else ""
        md_lines.append(f"| {i} | {t} | {u} | {s} | {poc_url} | {poc_status} |")

    md_text = "\n".join(md_lines) + "\n"
    write_md(out_md_path, md_text)

    print("Wrote:", out_json_path)
    print("Wrote:", out_md_path)

if __name__ == "__main__":
    main()
