#!/usr/bin/env python3
"""
Async PoC generator/runner.

Provides:
  async def generate_pocs_for_findings(outdir: str, findings: list) -> list

Writes:
  <outdir>/reports/pocs.json
  <outdir>/reports/pocs_compact.json

Also writes raw HTTP snippets to:
  <outdir>/pocs/snippets/<safe_filename>.html

Features:
  - aiohttp with retries + timeouts
  - concurrency limit
  - response snippet capture for debugging
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import time
import hashlib
from typing import List, Dict, Any, Optional
import aiohttp
from aiohttp.client_exceptions import ClientError, ServerTimeoutError

# config
CONCURRENCY = 6
REQUEST_TIMEOUT = 10  # seconds
RETRIES = 3
BACKOFF_FACTOR = 1.5
SNIPPET_MAX = 20000  # chars to store from response body
USER_AGENT = "pentest-ai-poc-runner/1.0"

# I/O helpers
def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def _safe_name_for_url(url: str) -> str:
    # make short safe filename for snippet storage
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    # strip non-alnum from path
    s = re.sub(r'[^0-9A-Za-z._-]+', '_', url)
    s = (s[:80] + "_" + h) if len(s) > 80 else (s + "_" + h)
    return s

def _write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

async def _fetch_with_retries(session: aiohttp.ClientSession, url: str,
                              timeout: int = REQUEST_TIMEOUT,
                              retries: int = RETRIES,
                              backoff: float = BACKOFF_FACTOR) -> Dict[str, Any]:
    attempt = 0
    last_exc: Optional[Exception] = None
    while attempt <= retries:
        try:
            attempt += 1
            async with session.get(url, timeout=timeout) as resp:
                status = resp.status
                content_type = resp.headers.get("content-type", "")
                # read up to SNIPPET_MAX chars (decode robustly)
                raw = await resp.content.read(SNIPPET_MAX)
                try:
                    snippet = raw.decode("utf-8", errors="replace")
                except Exception:
                    snippet = str(raw)[:SNIPPET_MAX]
                return {
                    "status": status,
                    "content_type": content_type,
                    "snippet": snippet,
                    "url": str(resp.url),
                    "headers": dict(resp.headers),
                }
        except (asyncio.TimeoutError, ServerTimeoutError) as e:
            last_exc = e
            # transient timeout: backoff then retry
            if attempt <= retries:
                await asyncio.sleep(backoff ** attempt)
                continue
            return {"status": "error", "error": f"timeout after {attempt} attempts: {e}"}
        except ClientError as e:
            last_exc = e
            # connection errors: retry a few times
            if attempt <= retries:
                await asyncio.sleep(backoff ** attempt)
                continue
            return {"status": "error", "error": f"client error after {attempt} attempts: {e}"}
        except Exception as e:
            last_exc = e
            return {"status": "error", "error": f"unexpected error: {e}"}
    # fallback
    return {"status": "error", "error": f"failed, last_exc={last_exc}"}

async def _capture_proof(url: str, out_snippet_dir: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> Dict[str, Any]:
    async with sem:
        result = await _fetch_with_retries(session, url)
        # persist snippet if available and status is numeric
        status = result.get("status")
        snippet_path = None
        if isinstance(status, int) and result.get("snippet"):
            safe = _safe_name_for_url(url)
            _ensure_dir(out_snippet_dir)
            snippet_path = os.path.join(out_snippet_dir, f"{safe}.html")
            try:
                with open(snippet_path, "w", encoding="utf-8") as f:
                    f.write(result.get("snippet", "")[:SNIPPET_MAX])
            except Exception as e:
                # not fatal; attach note
                result.setdefault("meta", {})["snippet_write_error"] = str(e)
        result["snippet_path"] = snippet_path
        return result

async def generate_pocs_for_findings(outdir: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    For each high-confidence finding, attempt to capture a non-destructive PoC:
      - for XSS: visit proof_url (or target/used_url) with an innocuous marker if needed
      - for SQLi: visit proof_url
    This runner performs passive captures only (GETs). It does not perform destructive payloads.

    Returns list of PoC objects written to reports/pocs.json.
    """
    reports_dir = os.path.join(outdir, "reports")
    snippets_dir = os.path.join(outdir, "pocs", "snippets")
    _ensure_dir(reports_dir)
    _ensure_dir(snippets_dir)

    # build list of candidate URLs from findings
    candidates: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings):
        # only produce PoC for non-'none' types and severity >= 3 (tunable)
        ftype = (f.get("type") or "").lower()
        sev = f.get("severity") or 0
        if "none" in ftype:
            continue
        if sev < 3:
            continue
        url = f.get("used_url") or f.get("proof_url") or f.get("target")
        if not url:
            continue
        candidates.append({
            "finding_index": idx,
            "finding_type": ftype,
            "target": f.get("target"),
            "used_url": f.get("used_url"),
            "proof_url": url,
        })

    # dedupe by proof_url while keeping first occurrence
    seen_urls = set()
    deduped = []
    for c in candidates:
        pu = c["proof_url"]
        if pu in seen_urls:
            continue
        seen_urls.add(pu)
        deduped.append(c)
    candidates = deduped

    # aiohttp session + concurrency
    sem = asyncio.Semaphore(CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    headers = {"User-Agent": USER_AGENT}
    connector = aiohttp.TCPConnector(ssl=False, limit_per_host=CONCURRENCY)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=connector) as session:
        tasks = []
        for c in candidates:
            url = c["proof_url"]
            tasks.append(_capture_proof(url, snippets_dir, session, sem))
        results = []
        if tasks:
            for fut in asyncio.as_completed(tasks):
                try:
                    r = await fut
                    results.append(r)
                except Exception as e:
                    # shouldn't happen due to internal handling, but guard anyway
                    results.append({"status": "error", "error": f"unhandled: {e}"})

    # assemble PoC records aligned with findings (compact)
    pocs = []
    for c, r in zip(candidates, results):
        poc = {
            "proof_url": c["proof_url"],
            "finding_type": c["finding_type"],
            "target": c.get("target"),
            "used_url": c.get("used_url"),
            "status": r.get("status"),
            "content_type": r.get("content_type"),
            "snippet_path": r.get("snippet_path"),
        }
        if isinstance(r.get("status"), str) and r.get("status") == "error":
            poc["error"] = r.get("error")
        elif isinstance(r.get("status"), int):
            poc["http_status"] = r.get("status")
        pocs.append(poc)

    # write full pocs.json and compact (same here, but keep keys stable for other tools)
    pocs_path = os.path.join(reports_dir, "pocs.json")
    pocs_compact_path = os.path.join(reports_dir, "pocs_compact.json")
    try:
        _write_json(pocs_path, {"pocs": pocs})
    except Exception:
        _write_json(pocs_path, pocs)
    _write_json(pocs_compact_path, pocs)

    return pocs

# if run as script for quick debug
if __name__ == "__main__":
    import sys, asyncio
    if len(sys.argv) < 2:
        print("usage: python3 modules/poc/runner.py <run_dir>")
        sys.exit(1)
    run_dir = sys.argv[1].rstrip("/")
    # try to load final report and call generate_pocs_for_findings
    fr = os.path.join(run_dir, "reports", "final_report_with_pocs.json")
    if not os.path.exists(fr):
        fr = os.path.join(run_dir, "reports", "final_report.json")
    if not os.path.exists(fr):
        print("no final report found in", run_dir)
        sys.exit(1)
    with open(fr, "r", encoding="utf-8") as f:
        rep = json.load(f)
    findings = rep.get("findings", [])
    pocs = asyncio.run(generate_pocs_for_findings(run_dir, findings))
    print("wrote", os.path.join(run_dir, "reports", "pocs.json"), "entries:", len(pocs))
