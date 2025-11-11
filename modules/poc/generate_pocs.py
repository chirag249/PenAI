#!/usr/bin/env python3
"""
modules/poc/generate_pocs.py

Create non-destructive PoC snippets from a final report JSON.

Usage:
  python3 modules/poc/generate_pocs.py runs/<domain>/<run-id>

Outputs:
  runs/<domain>/<run-id>/reports/pocs.json
  runs/<domain>/<run-id>/reports/pocs_compact.json

PoCs are just read-only examples (curl + sample payload) and DO NOT perform any network action.
"""
import sys
import json
from pathlib import Path
from urllib.parse import urlparse, urlencode

def load_json(p: Path):
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def write_json(p: Path, obj):
    with p.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def build_xss_poc(url, param_name=None, method="GET"):
    marker = "<script>alert(1)</script>"
    if method.upper() == "GET":
        if "?" in url:
            return {
                "method": "GET",
                "payload": marker,
                "curl_example": f"curl -G --silent --show-error --data-urlencode \"{param_name}={marker}\" \"{url.split('?')[0]}\""
            }
        else:
            # no param known
            return {
                "method": "GET",
                "payload": marker,
                "curl_example": f"curl --silent --show-error \"{url}\""
            }
    else:
        # POST
        return {
            "method": "POST",
            "payload": marker,
            "curl_example": f"curl -X POST -d \"{param_name}={marker}\" \"{url}\""
        }

def build_sqli_poc(url, param_name=None, method="GET"):
    # non-destructive: use a tautology or benign time-free probe (no heavy payload)
    payload = "' OR '1'='1"
    if method.upper() == "GET":
        if "?" in url:
            return {
                "method": "GET",
                "payload": payload,
                "curl_example": f"curl -G --silent --show-error --data-urlencode \"{param_name}={payload}\" \"{url.split('?')[0]}\""
            }
        else:
            return {
                "method": "GET",
                "payload": payload,
                "curl_example": f"curl --silent --show-error \"{url}\""
            }
    else:
        return {
            "method": "POST",
            "payload": payload,
            "curl_example": f"curl -X POST -d \"{param_name}={payload}\" \"{url}\""
        }

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 modules/poc/generate_pocs.py runs/<domain>/<run-id>")
        sys.exit(1)

    run_dir = Path(sys.argv[1])
    reports_dir = run_dir / "reports"
    if not reports_dir.exists():
        print("Reports folder not found:", reports_dir)
        sys.exit(1)

    # prefer final_report_with_pocs_map.json, then final_report_with_pocs.json, then final_report.json
    candidates = [
        reports_dir / "final_report_with_pocs_map.json",
        reports_dir / "final_report_with_pocs.json",
        reports_dir / "final_report.json",
    ]
    report = None
    for c in candidates:
        if c.exists():
            report = c
            break
    if report is None:
        print("No final report found in", reports_dir)
        sys.exit(1)

    data = json.loads(report.read_text(encoding="utf-8"))
    findings = data.get("findings", [])

    pocs = []
    compact = []

    for f in findings:
        ftype = (f.get("type") or "").lower()
        # skip 'none' findings (no vuln)
        if "none" in ftype:
            continue

        used = f.get("used_url") or f.get("target") or ""
        # extract param name if present (simple heuristic)
        param_name = None
        if "?" in used:
            qs = used.split("?", 1)[1]
            if "=" in qs:
                param_name = qs.split("=")[0]

        poc = {
            "finding_type": f.get("type"),
            "target": f.get("target"),
            "used_url": used,
            "severity": f.get("severity"),
            "timestamp": f.get("timestamp") or None,
        }

        # generate safe, read-only PoC snippet
        if "xss" in ftype:
            g = build_xss_poc(used or f.get("target",""), param_name=param_name or "q", method="GET")
            poc.update({
                "proof_url": used or f.get("target"),
                "method": g["method"],
                "payload": g["payload"],
                "curl": g["curl_example"],
                "note": "Non-destructive reflected XSS check (marker). Do not run automated destructive payloads."
            })
        elif "sqli" in ftype:
            g = build_sqli_poc(used or f.get("target",""), param_name=param_name or "id", method="GET")
            poc.update({
                "proof_url": used or f.get("target"),
                "method": g["method"],
                "payload": g["payload"],
                "curl": g["curl_example"],
                "note": "Non-destructive SQLi probe (tautology). Avoid blind/time-based payloads here."
            })
        else:
            # generic PoC (just a GET example)
            poc.update({
                "proof_url": used or f.get("target"),
                "method": "GET",
                "payload": "",
                "curl": f"curl --silent --show-error \"{used or f.get('target','')}\"",
                "note": "Generic read-only probe"
            })

        pocs.append(poc)
        compact.append({
            "proof_url": poc["proof_url"],
            "finding_type": poc["finding_type"],
            "target": poc["target"],
            "status": None,   # not executed here; status filled by PoC runner if you have one
            "curl": poc.get("curl")
        })

    # write files
    write_json(reports_dir / "pocs.json", pocs)
    write_json(reports_dir / "pocs_compact.json", {"count": len(compact), "pocs": compact})

    print("Wrote", reports_dir / "pocs.json")
    print("Wrote", reports_dir / "pocs_compact.json")

if __name__ == "__main__":
    main()
