#!/usr/bin/env python3
"""
Tool output parsers.

Each parser returns a list of normalized findings:
[
  {
    "type": "sqli-external-sqlmap",
    "target": "https://example.com/search.php",
    "severity": 5,
    "evidence": "...",
    "source": {"tool": "sqlmap", "raw": {...}}
  },
  ...
]

This central parser module is conservative and defensive: it accepts multiple
shapes of tool envelope files (the manager/adapters write envelopes with 'meta'/'result'
or generic dicts). If an adapter already produced `parsed_findings`, they are used.
"""
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional
from modules.tools.parsers import parse_tool_envelope

# ------------- helper utilities -------------
def _safe_get(obj: Optional[Dict[str, Any]], *keys, default=None):
    if not isinstance(obj, dict):
        return default
    for k in keys:
        if k in obj:
            return obj[k]
    return default

def _first_str(*vals):
    for v in vals:
        if isinstance(v, str) and v:
            return v
    return ""

def _coerce_target(t: Optional[str]) -> str:
    if not t:
        return "<unknown>"
    return str(t)

# ------------- per-tool parsers -------------
def parse_sqlmap_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # If adapter already parsed findings, use them
    parsed = _safe_get(env, "parsed_findings") or _safe_get(_safe_get(env, "result"), "parsed_findings")
    if isinstance(parsed, list) and parsed:
        for f in parsed:
            f.setdefault("source", {})
            f["source"].setdefault("tool", "sqlmap")
            out.append(f)
        return out

    # Try shapes: envelope.result.vulnerabilities or envelope.result.stdout
    res = _safe_get(env, "result") or env
    vulns = _safe_get(res, "vulnerabilities") or _safe_get(res, "vulns")
    if isinstance(vulns, list) and vulns:
        for v in vulns:
            target = _first_str(v.get("url") if isinstance(v, dict) else None,
                                v.get("target") if isinstance(v, dict) else None,
                                v.get("request") if isinstance(v, dict) else None)
            evidence = _first_str(v.get("payload") if isinstance(v, dict) else None,
                                  v.get("evidence") if isinstance(v, dict) else None,
                                  json.dumps(v))
            out.append({
                "type": "sqli-external-sqlmap",
                "target": _coerce_target(target),
                "severity": 5,
                "evidence": evidence,
                "source": {"tool": "sqlmap", "raw": v},
            })
        return out

    # fallback: inspect stdout/stderr for obvious lines
    stdout = _first_str(_safe_get(res, "stdout"), _safe_get(env, "stdout"))
    stderr = _first_str(_safe_get(res, "stderr"), _safe_get(env, "stderr"))
    combined = "\n".join([x for x in (stdout, stderr) if x])
    if combined:
        lower = combined.lower()
        if "is vulnerable" in lower or ("parameter" in lower and "vulner" in lower):
            out.append({
                "type": "sqli-external-sqlmap",
                "target": _coerce_target(_first_str(_safe_get(res, "target"), _safe_get(env, "target"))),
                "severity": 5,
                "evidence": combined[:2000],
                "source": {"tool": "sqlmap", "raw": env},
            })
        elif "error" in lower or "syntax error" in lower:
            out.append({
                "type": "sqli-error",
                "target": _coerce_target(_first_str(_safe_get(res, "target"), _safe_get(env, "target"))),
                "severity": 4,
                "evidence": combined[:2000],
                "source": {"tool": "sqlmap", "raw": env},
            })
    return out

def parse_nmap_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    res = _safe_get(env, "result") or env
    hosts = _safe_get(res, "hosts") or _safe_get(res, "scans") or (res.get("hosts") if isinstance(res, dict) else None)
    if isinstance(hosts, list):
        for h in hosts:
            addr = _first_str(h.get("address") if isinstance(h, dict) else None,
                              h.get("ip") if isinstance(h, dict) else None,
                              h.get("host") if isinstance(h, dict) else None)
            ports = (h.get("ports") if isinstance(h, dict) else []) or []
            out.append({
                "type": "port-scan-nmap",
                "target": _coerce_target(addr),
                "severity": 2,
                "evidence": f"open_ports_count: {len(ports)}",
                "source": {"tool": "nmap", "raw": h},
            })
    elif isinstance(hosts, dict):
        for host, info in hosts.items():
            ports = info.get("ports") or []
            out.append({
                "type": "port-scan-nmap",
                "target": _coerce_target(host),
                "severity": 2,
                "evidence": f"open_ports_count: {len(ports)}",
                "source": {"tool": "nmap", "raw": info},
            })
    else:
        text = _first_str(_safe_get(res, "stdout"), _safe_get(res, "stderr"))
        if text:
            lines = [L.strip() for L in text.splitlines() if L.strip()]
            ports = [L for L in lines if "/tcp" in L or "/udp" in L]
            if ports:
                out.append({
                    "type": "port-scan-nmap",
                    "target": _coerce_target(_first_str(_safe_get(res, "target"), _safe_get(env, "target"))),
                    "severity": 2,
                    "evidence": f"ports_text_sample: {ports[:6]}",
                    "source": {"tool": "nmap", "raw": env},
                })
    return out

def parse_wpscan_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    parsed = _safe_get(env, "parsed_findings") or _safe_get(_safe_get(env, "result"), "parsed_findings")
    if isinstance(parsed, list) and parsed:
        for f in parsed:
            f.setdefault("source", {})
            f["source"].setdefault("tool", "wpscan")
            out.append(f)
        return out

    res = _safe_get(env, "result") or env
    vulns = _safe_get(res, "vulnerable") or _safe_get(res, "vulnerabilities") or []
    if isinstance(vulns, list) and vulns:
        for v in vulns:
            evidence = _first_str(v.get("title") if isinstance(v, dict) else None,
                                  v.get("reference") if isinstance(v, dict) else None,
                                  json.dumps(v))
            out.append({
                "type": "wp-vuln",
                "target": _coerce_target(_first_str(v.get("target") if isinstance(v, dict) else None,
                                                    _safe_get(res, "target"),
                                                    _safe_get(env, "target"))),
                "severity": 4,
                "evidence": evidence,
                "source": {"tool": "wpscan", "raw": v},
            })
        return out

    stdout = _first_str(_safe_get(res, "stdout"), _safe_get(res, "stderr"), _safe_get(env, "stdout"))
    if stdout:
        if "vulnerable" in stdout.lower() or "found" in stdout.lower():
            out.append({
                "type": "wp-vuln",
                "target": _coerce_target(_first_str(_safe_get(res, "target"), _safe_get(env, "target"))),
                "severity": 3,
                "evidence": stdout[:1500],
                "source": {"tool": "wpscan", "raw": env},
            })
    return out

def parse_nuclei_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    parsed = _safe_get(env, "parsed_findings") or _safe_get(_safe_get(env, "result"), "parsed_findings")
    if isinstance(parsed, list) and parsed:
        for f in parsed:
            f.setdefault("source", {})
            f["source"].setdefault("tool", "nuclei")
            out.append(f)
        return out

    res = _safe_get(env, "result") or env
    stdout = _first_str(_safe_get(res, "stdout"), _safe_get(res, "stderr"))
    if stdout:
        lines = [L for L in stdout.splitlines() if L.strip()]
        for L in lines:
            try:
                j = json.loads(L)
                info = j.get("info") or {}
                host = j.get("host") or j.get("target") or info.get("name")
                severity = 3
                if isinstance(info, dict):
                    sev = info.get("severity")
                    if isinstance(sev, (int, float)):
                        severity = int(sev)
                    elif isinstance(sev, str):
                        if sev.lower().startswith("high"):
                            severity = 4
                        elif sev.lower().startswith("medium"):
                            severity = 3
                        elif sev.lower().startswith("low"):
                            severity = 2
                evidence = json.dumps(j)[:2000]
                out.append({
                    "type": "nuclei-issue",
                    "target": _coerce_target(host),
                    "severity": severity,
                    "evidence": evidence,
                    "source": {"tool": "nuclei", "raw": j},
                })
            except Exception:
                if "high" in L.lower() or "medium" in L.lower() or "low" in L.lower() or "info" in L.lower():
                    out.append({
                        "type": "nuclei-issue",
                        "target": _coerce_target(_first_str(_safe_get(res, "target"), _safe_get(env, "target"))),
                        "severity": 3,
                        "evidence": L[:1500],
                        "source": {"tool": "nuclei", "raw": L},
                    })
    return out

def parse_nikto_envelope(env: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    """
    Basic Nikto parser: Nikto stdout contains lines with '/path - ' and vulnerability description.
    This is intentionally conservative and returns informational findings.
    """
    out: List[Dict[str, Any]] = []
    parsed = _safe_get(env, "parsed_findings") or _safe_get(_safe_get(env, "result"), "parsed_findings")
    if isinstance(parsed, list) and parsed:
        for f in parsed:
            f.setdefault("source", {})
            f["source"].setdefault("tool", "nikto")
            out.append(f)
        return out

    res = _safe_get(env, "result") or env
    stdout = _first_str(_safe_get(res, "stdout"), _safe_get(res, "stderr"), _safe_get(env, "stdout"))
    if stdout:
        lines = [L.strip() for L in stdout.splitlines() if L.strip()]
        for L in lines:
            # common nikto patterns: "/path - description" or "OSVDB-xxxx: description"
            if " - " in L or "OSVDB" in L or "item " in L.lower():
                # extract path-like token if present
                parts = L.split(" - ", 1)
                target = _first_str(_safe_get(res, "target"), _safe_get(env, "target"))
                evidence = parts[0] + " - " + (parts[1] if len(parts) > 1 else L)
                out.append({
                    "type": "nikto-issue",
                    "target": _coerce_target(target),
                    "severity": 2,
                    "evidence": evidence[:1500],
                    "source": {"tool": "nikto", "raw": L},
                })
    return out

# ------------- dispatcher -------------
_DISPATCH = {
    "sqlmap": parse_sqlmap_envelope,
    "nmap": parse_nmap_envelope,
    "wpscan": parse_wpscan_envelope,
    "nuclei": parse_nuclei_envelope,
    "nikto": parse_nikto_envelope,
}

# Provide a normalized entrypoint
def parse_tool_envelope(tool_name: str, envelope: Dict[str, Any], run_dir: str) -> List[Dict[str, Any]]:
    fn = _DISPATCH.get(tool_name)
    if fn:
        try:
            return fn(envelope, run_dir) or []
        except Exception:
            # defensive: return fallback wrapper
            return [{
                "type": f"external-tool-{tool_name}",
                "target": _coerce_target(_first_str(_safe_get(envelope.get("result", {}), "target"), envelope.get("target"))),
                "severity": 2,
                "evidence": json.dumps(envelope)[:1500],
                "source": {"tool": tool_name, "raw": envelope},
            }]
    # no parser: generic fallback
    return [{
        "type": f"external-tool-{tool_name}",
        "target": _coerce_target(_first_str(_safe_get(envelope.get("result", {}), "target"), envelope.get("target"))),
        "severity": 2,
        "evidence": json.dumps(envelope)[:1500],
        "source": {"tool": tool_name, "raw": envelope},
    }]
