#!/usr/bin/env python3
"""
scripts/extract_findings_to_jsonl.py
Usage:
  PYTHONPATH=. python3 scripts/extract_findings_to_jsonl.py <report.json> <out.jsonl>
Simple heuristics map findings -> label. You can edit mapping rules to suit.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

def infer_label(f: dict) -> str:
    # Basic heuristics to pick a stable label from finding type or ai prediction if present
    t = str(f.get("type", "")).lower()
    # if AI attached, prefer coarse vuln_type
    meta = f.get("meta") or {}
    ai = meta.get("ai_prediction") or meta.get("ai") or {}
    if isinstance(ai, dict) and ai.get("vuln_type"):
        return str(ai.get("vuln_type"))
    if "xss" in t:
        return "xss"
    if "sqli" in t or "sql" in t:
        return "sqli"
    if "rce" in t or "exec" in t:
        return "rce"
    if "csrf" in t:
        return "csrf"
    if "open-port" in t or "nmap" in t:
        return "info-port"
    return "other"

def build_text(f: dict) -> str:
    parts = []
    for k in ("evidence", "description", "request", "response", "raw", "used_payload", "parameter"):
        v = f.get(k)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.extend([str(x) for x in v.values() if isinstance(x, str)])
    # also include type and source
    parts.append(str(f.get("type", "")))
    src = f.get("source") or {}
    if isinstance(src, dict):
        parts.append(str(src.get("tool", "")))
    return " ".join([p for p in parts if p])[:10000]

def main():
    if len(sys.argv) < 3:
        print("Usage: extract_findings_to_jsonl.py <report.json> <out.jsonl>")
        sys.exit(2)
    rpt = Path(sys.argv[1])
    out = Path(sys.argv[2])
    if not rpt.exists():
        print("report not found:", rpt)
        sys.exit(2)
    data = json.load(open(rpt, "r", encoding="utf-8"))
    findings = data.get("findings") or []
    with out.open("w", encoding="utf-8") as fh:
        for f in findings:
            text = build_text(f)
            label = infer_label(f)
            obj = {"text": text, "label": label}
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    print(f"Wrote {out} ({len(findings)} examples)")

if __name__ == "__main__":
    main()
