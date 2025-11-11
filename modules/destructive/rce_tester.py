#!/usr/bin/env python3
# modules/destructive/rce_tester.py
from __future__ import annotations
import asyncio
import os
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def run_rce_tests(scope, outdir: str) -> List[Dict[str, Any]]:
    """
    Run RCE-capable checks in a controlled way.
    Returns list of normalized finding dicts:
      { type, target, severity, evidence, source }
    """
    results: List[Dict[str, Any]] = []

    # Safety gate: only proceed if full destructive allowed
    try:
        if not scope.is_destructive_allowed(outdir):
            logger.info("run_rce_tests: destructive not allowed for %s, skipping", outdir)
            return results
    except Exception:
        logger.exception("run_rce_tests: unable to determine destructive allowance; skipping")
        return results

    # Determine target + meta from run_meta.json if present
    target: Optional[str] = None
    meta: Dict[str, Any] = {}
    meta_path = os.path.join(outdir, "run_meta.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh) or {}
                targets = meta.get("targets") or meta.get("target") or []
                if isinstance(targets, list) and targets:
                    target = targets[0]
                elif isinstance(targets, str):
                    target = targets
        except Exception:
            meta = {}
            target = None

    # Inject simulated candidate when requested (tests expect both types)
    if meta.get("simulate_vuln"):
        results.append({
            "type": "rce-check-info",
            "target": target or "<unknown>",
            "severity": 3,
            "evidence": "Simulated RCE candidate (run_meta.simulate_vuln=True)",
            "source": {"tool": "rce_tester", "note": "simulated"},
        })
        results.append({
            "type": "rce-candidate",
            "target": target or "<unknown>",
            "severity": 4,
            "evidence": "Synthetic candidate injected for test",
            "source": {"tool": "rce_tester", "note": "simulated"},
        })

    if not target:
        logger.info("run_rce_tests: no target found in run_meta.json; skipping nuclei run")
        return results

    # Prefer manager to run nuclei (adapter or binary). Call in thread to avoid blocking loop.
    try:
        from modules.tools.manager import run_tool
    except Exception:
        run_tool = None  # type: ignore

    if run_tool is None:
        logger.warning("run_rce_tests: tools.manager.run_tool unavailable; skipping nuclei run")
        return results

    try:
        loop = asyncio.get_running_loop()
        envelope = await loop.run_in_executor(None, lambda: run_tool("nuclei", outdir, target=target, extra_args=[]))
        # normalize envelope -> finding(s)
        if isinstance(envelope, dict):
            result_obj = envelope.get("result") or envelope
            # if adapter returns structured vulnerabilities
            vulns = None
            if isinstance(result_obj, dict):
                for key in ("vulnerabilities", "results", "matches", "hits"):
                    if result_obj.get(key):
                        vulns = result_obj.get(key)
                        break
            # JSON-lines in stdout
            if not vulns and isinstance(result_obj, dict) and isinstance(result_obj.get("stdout"), str):
                stdout = result_obj.get("stdout", "")
                for ln in stdout.splitlines():
                    if not ln.strip():
                        continue
                    try:
                        j = json.loads(ln)
                        results.append({
                            "type": "nuclei-detected",
                            "target": j.get("host") or target,
                            "severity": 3,
                            "evidence": j.get("info", {}).get("name") if isinstance(j.get("info"), dict) else str(j)[:800],
                            "source": {"tool": "nuclei", "raw": j, "envelope": envelope},
                        })
                    except Exception:
                        if "cve" in ln.lower() or "vulnerab" in ln.lower():
                            results.append({
                                "type": "nuclei-inferred",
                                "target": target,
                                "severity": 3,
                                "evidence": ln[:1000],
                                "source": {"tool": "nuclei", "raw_line": ln, "envelope": envelope},
                            })
            if isinstance(vulns, list):
                for v in vulns:
                    evidence = v.get("info", {}).get("name") if isinstance(v.get("info"), dict) else str(v)[:800]
                    results.append({
                        "type": "nuclei-vuln",
                        "target": v.get("host") or target,
                        "severity": int(v.get("severity", 3)) if isinstance(v.get("severity"), int) else 3,
                        "evidence": evidence,
                        "source": {"tool": "nuclei", "raw": v, "envelope": envelope},
                    })
            # If nothing parsed, add an informational marker so test can still see execution happened
            if not any(r.get("type", "").startswith("nuclei-") for r in results):
                results.append({
                    "type": "nuclei-run",
                    "target": target,
                    "severity": 1,
                    "evidence": "nuclei executed (no structured vulns parsed)",
                    "source": {"tool": "nuclei", "envelope": envelope},
                })
        else:
            results.append({
                "type": "nuclei-run",
                "target": target,
                "severity": 1,
                "evidence": "nuclei executed (non-dict envelope)",
                "source": {"tool": "nuclei", "envelope": envelope},
            })
    except Exception as e:
        logger.exception("run_rce_tests: nuclei run failed: %s", e)
        results.append({
            "type": "nuclei-error",
            "target": target or "<unknown>",
            "severity": 1,
            "evidence": str(e)[:1000],
            "source": {"tool": "nuclei", "error": str(e)},
        })

    logger.info("run_rce_tests: completed (results=%s)", len(results))
    return results
