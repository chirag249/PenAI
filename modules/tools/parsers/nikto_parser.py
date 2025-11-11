#!/usr/bin/env python3
"""
Nikto output parser.

Expects a JSON envelope (adapter/manager should place JSON under generated/tools/nikto.json)
Envelope shapes handled:
 - envelope["result"]["items"] (list)
 - envelope["result"]["stdout"] / stderr plain text
 - raw Nikto JSON array of findings

Returns list of normalized findings:
[
  {"type": "nikto-issue", "target": "...", "severity": 3, "evidence": "...", "source": {"tool": "nikto", "raw": {...}}},
  ...
]
"""
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional

def _coerce_target(t: Optional[str]) -> str:
    return str(t) if t else "<unknown>"

def parse_nikto_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    # if adapter already provided parsed findings, use them
    parsed = env.get("parsed_findings") or (env.get("result") or {}).get("parsed_findings")
    if isinstance(parsed, list) and parsed:
        for f in parsed:
            f.setdefault("source", {}).setdefault("tool", "nikto")
            out.append(f)
        return out

    res = env.get("result") or env

    # Case A: adapter/manager produced structured items list
    items = None
    if isinstance(res, dict):
        items = res.get("items") or res.get("findings") or res.get("issues")
    if isinstance(items, list) and items:
        for it in items:
            target = it.get("host") or it.get("url") or it.get("target")
            desc = it.get("description") or it.get("msg") or json.dumps(it)
            severity = 3
            # Nikto severity mapping heuristic
            if it.get("severity") in (4, "high", "High"):
                severity = 4
            out.append({
                "type": "nikto-issue",
                "target": _coerce_target(target),
                "severity": severity,
                "evidence": desc[:2000],
                "source": {"tool": "nikto", "raw": it},
            })
        return out

    # Case B: plain stdout text - try to parse lines
    stdout = (res.get("stdout") if isinstance(res, dict) else None) or env.get("stdout") or ""
    if stdout:
        lines = [L.strip() for L in stdout.splitlines() if L.strip()]
        # Nikto lines often contain host and vulnerability message
        for L in lines:
            # ignore banners
            if "nikto" in L.lower() and ("server" in L.lower() or "started" in L.lower()):
                continue
            # heuristic: host or http status at start
            target = None
            parts = L.split(" - ")
            if len(parts) >= 2:
                maybe_host = parts[0].strip()
                msg = " - ".join(parts[1:]).strip()
                target = maybe_host
            else:
                msg = L
            out.append({
                "type": "nikto-issue",
                "target": _coerce_target(target),
                "severity": 3,
                "evidence": msg[:1500],
                "source": {"tool": "nikto", "raw": L},
            })
        return out

    # fallback: return nothing
    return out
