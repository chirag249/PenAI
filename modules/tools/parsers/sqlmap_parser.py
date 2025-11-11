#!/usr/bin/env python3
from __future__ import annotations
import json
from typing import Dict, Any, List

def parse_sqlmap_output(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    if not isinstance(data, dict):
        return out
    # Try shapes: envelope.result.vulnerabilities or result.vulnerabilities or result.vulns or data.vulnerabilities
    res = data.get("result") or data
    vulns = res.get("vulnerabilities") or res.get("vulns") or res.get("vulnerabilities", [])
    if isinstance(vulns, list) and vulns:
        for v in vulns:
            out.append({
                "type": "sqli-external-sqlmap",
                "target": v.get("url") or res.get("target") or "<unknown>",
                "severity": 5,
                "parameter": v.get("parameter") or v.get("param"),
                "evidence": v.get("payload") or v.get("evidence") or str(v)[:1000],
                "source": {"tool": "sqlmap", "raw": v},
            })
    else:
        # fallback: look for stdout that mentions 'is vulnerable' or similar
        stdout = res.get("stdout") or ""
        if isinstance(stdout, str) and ("is vulnerable" in stdout or "sql injection" in stdout.lower()):
            out.append({
                "type": "sqli-external-sqlmap",
                "target": res.get("target") or "<unknown>",
                "severity": 5,
                "evidence": stdout[:1000],
                "source": {"tool": "sqlmap", "raw": res},
            })
    return out
