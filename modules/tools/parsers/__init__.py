# modules/tools/parsers/__init__.py
from __future__ import annotations
import importlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

# Candidate function name patterns a parser module might expose
_NORMALIZE_FN_NAMES = [
    "parse_{tool}_file",
    "parse_{tool}_data",
    "parse_{tool}_output",
    "parse_{tool}",
    "parse_output",
    "parse_data",
    "parse",
]


# ---------------- Lazy submodule import to avoid circular imports ----------------
def __getattr__(name: str):
    """
    Lazy import of submodules like `sqlmap_parser` when user does:
        from modules.tools.parsers import sqlmap_parser

    This avoids circular imports when parser modules import this package.
    """
    # only allow reasonable names (convention: *_parser)
    if not (name.endswith("_parser") or name in ("nikto_parser", "nuclei_parser")):
        raise AttributeError(f"module {__name__} has no attribute {name}")

    modname = f"{__name__}.{name}"
    try:
        mod = importlib.import_module(modname)
    except Exception as e:
        raise ImportError(f"cannot import submodule {modname}: {e}") from e
    globals()[name] = mod  # cache for next time
    return mod


# ---------------- Helpers ----------------
def _load_json_if_path(maybe_path: Any) -> Optional[Dict]:
    if isinstance(maybe_path, str) and os.path.isfile(maybe_path):
        try:
            with open(maybe_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None
    return None


def _try_call(fn, arg, run_dir: Optional[str] = None):
    """
    Try calling fn with several sensible argument signatures:
      - fn(arg)
      - fn(arg, run_dir)
      - fn()
    Return whatever the function returns or None.
    """
    try:
        return fn(arg)
    except TypeError:
        pass
    try:
        return fn(arg, run_dir)
    except TypeError:
        pass
    try:
        return fn()
    except TypeError:
        pass
    return None


def _import_module(module_name: str):
    try:
        return importlib.import_module(module_name)
    except Exception:
        return None


# ---------------- Main dispatcher ----------------
def parse_tool_envelope(tool_name: str, envelope_or_path: Any, run_dir: Optional[str] = None) -> List[Dict]:
    """
    Central dispatcher that accepts either:
      - a path to a JSON envelope (string path)
      - an already-loaded envelope dict

    Tries (in order):
      1) module `modules.tools.parsers.<tool>_parser`
      2) module `modules.parsers.<tool>_parser`
      3) module `modules.tools.<tool>_adapter`
      4) module `modules.parsers.<tool>`
      5) module `modules.tools.parsers.<tool>`

    For each imported module, it tries function names from _NORMALIZE_FN_NAMES.
    If a parser returns a list of normalized findings, they are returned; otherwise
    conservative heuristics are applied to infer findings (may return empty list).
    """
    data = envelope_or_path
    # if a path was passed, try to load as JSON (but keep the original path value for caller)
    if isinstance(envelope_or_path, str) and os.path.isfile(envelope_or_path):
        loaded = _load_json_if_path(envelope_or_path)
        if loaded is not None:
            data = loaded

    # if adapter already produced parsed_findings, prefer them
    if isinstance(data, dict):
        parsed = data.get("parsed_findings") or (data.get("result") and data["result"].get("parsed_findings"))
        if isinstance(parsed, list):
            return parsed

    candidate_modules = [
        f"modules.tools.parsers.{tool_name}_parser",
        f"modules.parsers.{tool_name}_parser",
        f"modules.tools.{tool_name}_adapter",
        f"modules.parsers.{tool_name}",
        f"modules.tools.parsers.{tool_name}",
    ]

    # try to import & call parser functions
    for modname in candidate_modules:
        mod = _import_module(modname)
        if not mod:
            continue
        for pattern in _NORMALIZE_FN_NAMES:
            fn_name = pattern.format(tool=tool_name)
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                try:
                    arg = envelope_or_path if isinstance(envelope_or_path, str) else data
                    res = _try_call(fn, arg, run_dir)
                    if isinstance(res, list):
                        for r in res:
                            if isinstance(r, dict):
                                r.setdefault("source", {}).setdefault("tool", tool_name)
                        return res
                    if isinstance(res, dict):
                        pf = res.get("parsed_findings") or (res.get("result") and res["result"].get("parsed_findings"))
                        if isinstance(pf, list):
                            for r in pf:
                                if isinstance(r, dict):
                                    r.setdefault("source", {}).setdefault("tool", tool_name)
                            return pf
                except Exception:
                    # parser function failed; try next candidate
                    continue

    # ---------------- Conservative heuristics fallback ----------------
    findings: List[Dict] = []

    def _norm_from_v(v: Any, target_hint: Optional[str] = None):
        if not isinstance(v, dict):
            return {
                "type": f"{tool_name}-raw",
                "target": target_hint or "",
                "severity": 3,
                "evidence": str(v)[:1000],
                "source": {"tool": tool_name, "raw": v},
            }
        t = v.get("target") or v.get("url") or target_hint or v.get("uri") or ""
        title = v.get("name") or v.get("title") or v.get("description") or v.get("evidence") or v.get("reference") or str(v)
        severity = v.get("severity") or v.get("level") or v.get("cvss") or 3
        # normalize severity to int 1..5 conservatively
        try:
            sev = int(severity)
            if sev < 1:
                sev = 1
            if sev > 5:
                sev = 5
        except Exception:
            s = str(severity).lower() if severity is not None else ""
            if "crit" in s or "high" in s:
                sev = 5
            elif "med" in s or "medium" in s:
                sev = 3
            elif "low" in s:
                sev = 2
            else:
                sev = 3
        return {"type": f"{tool_name}-vuln", "target": t, "severity": sev, "evidence": title, "source": {"tool": tool_name, "raw": v}}

    # if envelope is a dict, attempt to infer common shapes
    if isinstance(data, dict):
        # nmap-like hosts/ports
        if "hosts" in data or (data.get("result") and isinstance(data["result"], dict) and data["result"].get("hosts")):
            hosts = data.get("hosts") or (data.get("result") and data["result"].get("hosts")) or []
            for h in hosts:
                addr = h.get("address") or h.get("ip") or ""
                ports = h.get("ports") or []
                for p in ports:
                    findings.append({
                        "type": f"{tool_name}-open-port",
                        "target": f"{addr}:{p.get('port')}",
                        "severity": 2,
                        "evidence": f"port {p.get('port')} {p.get('state')}",
                        "source": {"tool": tool_name, "raw": p},
                    })
            return findings

        # common vulnerability lists
        for key in ("vulnerabilities", "vulnerable", "vulns", "results", "matches"):
            items = data.get(key) or (data.get("result") and data["result"].get(key))
            if items:
                if isinstance(items, dict):
                    flat = []
                    for v in items.values():
                        if isinstance(v, list):
                            flat.extend(v)
                        else:
                            flat.append(v)
                    items = flat
                if isinstance(items, list):
                    for v in items:
                        findings.append(_norm_from_v(v, data.get("target") or data.get("url")))
                    return findings

        # some adapters include raw stdout that mentions vulnerabilities
        stdout = data.get("result", {}).get("stdout") if isinstance(data.get("result"), dict) else data.get("stdout") or data.get("output")
        if stdout and isinstance(stdout, str) and ("vulnerable" in stdout.lower() or "cve" in stdout.lower()):
            findings.append({
                "type": f"{tool_name}-inferred",
                "target": data.get("target") or data.get("url") or "",
                "severity": 3,
                "evidence": (stdout[:1500] if isinstance(stdout, str) else str(stdout)),
                "source": {"tool": tool_name, "raw": data},
            })
            return findings

    # nothing matched -> return empty list
    return []
