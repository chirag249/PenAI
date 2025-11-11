#!/usr/bin/env python3
# modules/parsers/wpscan_parser.py
"""
Simple parser for wpscan adapter output JSON produced under:
  runs/<domain>/<run_id>/generated/tools/wpscan.json

Provides:
  parse_wpscan_file(path) -> List[Dict]
  parse_wpscan_data(data) -> List[Dict]
Normalized finding dict format:
  {
    "type": "wp-plugin-vuln",
    "target": "<site>",
    "severity": 3,
    "evidence": "plugin X (v Y) - CVE ...",
    "source": {"tool": "wpscan", "raw": {...}}
  }
"""
from __future__ import annotations
import json
from typing import Dict, Any, List
from pathlib import Path

def _severity_from_string(s: str | None) -> int:
    if not s:
        return 3
    s = s.lower()
    if "critical" in s or "high" in s:
        return 5
    if "medium" in s:
        return 3
    if "low" in s:
        return 2
    return 3

def parse_wpscan_data(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return out

    target = data.get("target") or data.get("url") or "<unknown>"

    # Some adapter envelopes store metadata->result or meta/result envelope
    # Accept several shapes.
    if "result" in data and isinstance(data["result"], dict):
        payload = data["result"]
    else:
        payload = data

    # common keys used in our mock adapter: "vulnerable" or "vulnerabilities"
    vulns = payload.get("vulnerable") or payload.get("vulnerabilities") or payload.get("vulns") or []
    if isinstance(vulns, dict):
        # case: keyed by type -> flatten
        items = []
        for k, v in vulns.items():
            if isinstance(v, list):
                items.extend(v)
            else:
                items.append(v)
        vulns = items

    if isinstance(vulns, list) and vulns:
        for v in vulns:
            title = v.get("name") or v.get("title") or v.get("reference") or str(v)
            sev = _severity_from_string(v.get("severity") if isinstance(v, dict) else None)
            out.append({
                "type": "wp-plugin-vuln",
                "target": target,
                "severity": sev,
                "evidence": title,
                "source": {"tool": "wpscan", "raw": v},
            })
    else:
        # fallback: check stdout/stderr text
        stdout = payload.get("stdout") or payload.get("output") or ""
        if stdout and "vulnerable" in str(stdout).lower():
            out.append({
                "type": "wp-vuln-inferred",
                "target": target,
                "severity": 3,
                "evidence": str(stdout)[:2000],
                "source": {"tool": "wpscan", "raw": payload},
            })

    return out

def parse_wpscan_file(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return []
    return parse_wpscan_data(data)
