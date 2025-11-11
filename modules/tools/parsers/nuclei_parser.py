#!/usr/bin/env python3
"""
Nuclei output parser.

Handles:
 - JSON-lines mode (each line is JSON)
 - adapter-produced parsed_findings
 - fallback plain stdout parsing

Returns normalized findings list similar to other parsers.
"""
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional

def _coerce_target(t: Optional[str]) -> str:
    return str(t) if t else "<unknown>"

def _map_severity_text(s: Optional[str]) -> int:
    if not s:
        return 3
    s = str(s).lower()
    if s.startswith("critical") or s.startswith("high"):
        return 4
    if s.startswith("medium") or s.startswith("med"):
        return 3
    if s.startswith("low"):
        return 2
    return 3

def parse_nuclei_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    # use adapter-parsed if present
    parsed = env.get("parsed_findings") or (env.get("result") or {}).get("parsed_findings")
    if isinstance(parsed, list) and parsed:
        for f in parsed:
            f.setdefault("source", {}).setdefault("tool", "nuclei")
            out.append(f)
        return out

    res = env.get("result") or env

    # 1) JSON-lines in stdout
    stdout = (res.get("stdout") if isinstance(res, dict) else None) or env.get("stdout") or ""
    if stdout:
        lines = [L for L in stdout.splitlines() if L.strip()]
        for L in lines:
            Ls = L.strip()
            try:
                j = json.loads(Ls)
                info = j.get("info") or {}
                host = j.get("host") or j.get("target") or info.get("name")
                sev = _map_severity_text(info.get("severity") or info.get("level") or j.get("severity"))
                evidence = json.dumps(j)[:2000]
                out.append({
                    "type": "nuclei-issue",
                    "target": _coerce_target(host),
                    "severity": sev,
                    "evidence": evidence,
                    "source": {"tool": "nuclei", "raw": j},
                })
                continue
            except Exception:
                # not JSON - heuristic parse below
                pass

            # Heuristic: look for known patterns "host: template [severity]"
            low = Ls.lower()
            if "severity" in low or "info" in low or "high" in low or "medium" in low or "low" in low:
                # attempt to extract host-like token
                # pick first token that contains ":" as host:port or hostname
                host_guess = None
                for tok in Ls.split():
                    if ":" in tok and (tok.count(".") >= 1 or "/" in tok):
                        host_guess = tok
                        break
                out.append({
                    "type": "nuclei-issue",
                    "target": _coerce_target(host_guess),
                    "severity": 3,
                    "evidence": Ls[:1500],
                    "source": {"tool": "nuclei", "raw": Ls},
                })
        if out:
            return out

    # 2) adapter may have "matches" array
    matches = (res.get("matches") if isinstance(res, dict) else None) or env.get("matches")
    if isinstance(matches, list) and matches:
        for m in matches:
            host = m.get("host") or m.get("target")
            sev = _map_severity_text(m.get("severity") or m.get("level"))
            out.append({
                "type": "nuclei-issue",
                "target": _coerce_target(host),
                "severity": sev,
                "evidence": m.get("matcher") or json.dumps(m)[:1500],
                "source": {"tool": "nuclei", "raw": m},
            })
        return out

    # fallback: empty
    return out
