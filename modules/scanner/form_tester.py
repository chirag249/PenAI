# modules/scanner/form_tester.py
import os
import json
import urllib.parse
import asyncio
import httpx
from config import DEFAULTS
from modules.utils import resolve_working_url
from modules.scanner.payloads import XSS_PAYLOADS, SQLI_PAYLOADS, HEADER_VARIANTS

# concurrency guard
_SEMAPHORE = asyncio.Semaphore(DEFAULTS.get("concurrency", 8))

async def _get_client(timeout=12):
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)

async def _try_request(client, method, url, headers=None, params=None, data=None, json_body=None, cookies=None):
    try:
        if method == "post":
            r = await client.post(url, headers=headers, params=params, data=data, json=json_body, cookies=cookies)
        else:
            r = await client.get(url, headers=headers, params=params, data=data, json=json_body, cookies=cookies)
        return r
    except Exception as e:
        return {"error": repr(e)}

async def _header_variants_request(method, url, **kwargs):
    # try variants, return first successful response object or error dict
    for hv in HEADER_VARIANTS:
        client = httpx.AsyncClient(timeout=12)
        try:
            merged_headers = {}
            if kwargs.get("headers"):
                merged_headers.update(kwargs["headers"])
            merged_headers.update(hv)
            r = await _try_request(client, method, url, headers=merged_headers,
                                   params=kwargs.get("params"),
                                   data=kwargs.get("data"),
                                   json_body=kwargs.get("json_body"),
                                   cookies=kwargs.get("cookies"))
            await client.aclose()
            # if r is httpx.Response
            if hasattr(r, "status_code"):
                return r
            # else r is error dict, try next variant
        except Exception:
            try:
                await client.aclose()
            except Exception:
                pass
            continue
    return {"error": "All header variants failed"}

async def _fuzz_query_param(client, working, param):
    findings = []
    sep = "&" if "?" in working else "?"
    for p in XSS_PAYLOADS:
        url = working + sep + f"{param}=" + urllib.parse.quote(p)
        r = await _try_request(client, "get", url)
        if hasattr(r, "text") and p in (r.text or ""):
            findings.append({"type":"xss-reflected","target": working, "param":param, "payload":p, "proof": url, "confidence":"high", "snippet": (r.text or "")[:400]})
            break
    for s in SQLI_PAYLOADS:
        url = working + sep + f"{param}=" + urllib.parse.quote(s)
        r = await _try_request(client, "get", url)
        if hasattr(r, "text"):
            lowb = (r.text or "").lower()
            for sig in DEFAULTS["sql_error_signatures"]:
                if sig.lower() in lowb:
                    findings.append({"type":"sqli-error","target":working,"param":param,"payload":s,"evidence":sig,"proof":url,"confidence":"high","snippet":lowb[:400]})
                    return findings
    return findings

async def _fuzz_form_fields(client, working, method, params):
    findings = []
    # single-parameter injection
    for param in params:
        for p in XSS_PAYLOADS:
            try:
                if method == "post":
                    r = await _try_request(client, "post", working, data={param: p})
                else:
                    r = await _try_request(client, "get", working, params={param: p})
                if hasattr(r, "text") and p in (r.text or ""):
                    findings.append({"type":"xss-reflected","target":working,"param":param,"payload":p,"method":method,"proof_used_url": str(r.url),"confidence":"high","snippet":(r.text or "")[:400]})
                    break
            except Exception as e:
                findings.append({"type":"form-request-error","target":working,"error":repr(e),"param":param,"payload":p})
        for s in SQLI_PAYLOADS:
            try:
                if method == "post":
                    r = await _try_request(client, "post", working, data={param: s})
                else:
                    r = await _try_request(client, "get", working, params={param: s})
                if hasattr(r, "text"):
                    lowb = (r.text or "").lower()
                    for sig in DEFAULTS["sql_error_signatures"]:
                        if sig.lower() in lowb:
                            findings.append({"type":"sqli-error","target":working,"param":param,"payload":s,"method":method,"evidence":sig,"proof_used_url": str(r.url),"confidence":"high","snippet":lowb[:400]})
                            break
            except Exception as e:
                findings.append({"type":"form-request-error","target":working,"error":repr(e),"param":param,"payload":s})
    # bulk injection
    if params:
        bulk_xss = {p: XSS_PAYLOADS[0] for p in params}
        bulk_sqli = {p: SQLI_PAYLOADS[0] for p in params}
        try:
            if method == "post":
                r = await _try_request(client, "post", working, data=bulk_xss)
            else:
                r = await _try_request(client, "get", working, params=bulk_xss)
            if hasattr(r, "text") and XSS_PAYLOADS[0] in (r.text or ""):
                findings.append({"type":"xss-reflected","target":working,"method":method,"proof_used_url": str(r.url),"confidence":"high","snippet":(r.text or "")[:400]})
        except Exception:
            pass
        try:
            if method == "post":
                r = await _try_request(client, "post", working, data=bulk_sqli)
            else:
                r = await _try_request(client, "get", working, params=bulk_sqli)
            if hasattr(r, "text"):
                lowb = (r.text or "").lower()
                for sig in DEFAULTS["sql_error_signatures"]:
                    if sig.lower() in lowb:
                        findings.append({"type":"sqli-error","target":working,"method":method,"evidence":sig,"proof_used_url": str(r.url),"confidence":"high","snippet":lowb[:400]})
                        break
        except Exception:
            pass
    return findings

async def _fuzz_json_body(client, working, params):
    findings = []
    # if working URL or path contains /api/ or response hints JSON, try JSON bodies
    for param in params:
        for p in XSS_PAYLOADS:
            try:
                r = await _try_request(client, "post", working, json_body={param: p}, headers={"Content-Type":"application/json"})
                if hasattr(r, "text") and p in (r.text or ""):
                    findings.append({"type":"xss-reflected","target":working,"param":param,"payload":p,"proof_used_url": str(r.url),"confidence":"high","snippet":(r.text or "")[:400]})
                    break
            except Exception as e:
                findings.append({"type":"json-request-error","target":working,"error":repr(e),"param":param,"payload":p})
        for s in SQLI_PAYLOADS:
            try:
                r = await _try_request(client, "post", working, json_body={param: s}, headers={"Content-Type":"application/json"})
                if hasattr(r, "text"):
                    lowb = (r.text or "").lower()
                    for sig in DEFAULTS["sql_error_signatures"]:
                        if sig.lower() in lowb:
                            findings.append({"type":"sqli-error","target":working,"param":param,"payload":s,"evidence":sig,"proof_used_url": str(r.url),"confidence":"high","snippet":lowb[:400]})
                            break
            except Exception as e:
                findings.append({"type":"json-request-error","target":working,"error":repr(e),"param":param,"payload":s})
    return findings

async def _fuzz_cookies(client, working, params):
    findings = []
    for param in params:
        for p in XSS_PAYLOADS:
            try:
                r = await _try_request(client, "get", working, cookies={param: p})
                if hasattr(r, "text") and p in (r.text or ""):
                    findings.append({"type":"xss-reflected","target":working,"in":"cookie","param":param,"payload":p,"proof_used_url": str(r.url),"confidence":"high","snippet":(r.text or "")[:400]})
                    break
            except Exception as e:
                findings.append({"type":"cookie-request-error","target":working,"error":repr(e),"param":param,"payload":p})
        for s in SQLI_PAYLOADS:
            try:
                r = await _try_request(client, "get", working, cookies={param: s})
                if hasattr(r, "text"):
                    lowb = (r.text or "").lower()
                    for sig in DEFAULTS["sql_error_signatures"]:
                        if sig.lower() in lowb:
                            findings.append({"type":"sqli-error","target":working,"in":"cookie","param":param,"payload":s,"evidence":sig,"proof_used_url": str(r.url),"confidence":"high","snippet":lowb[:400]})
                            break
            except Exception as e:
                findings.append({"type":"cookie-request-error","target":working,"error":repr(e),"param":param,"payload":s})
    return findings

async def _fuzz_header_reflection(client, working, params):
    findings = []
    # inject payloads into headers like Referer and X-Forwarded-For
    header_targets = ["Referer", "X-Forwarded-For", "User-Agent"]
    for header_name in header_targets:
        for p in XSS_PAYLOADS:
            headers = {header_name: p}
            r = await _try_request(client, "get", working, headers=headers)
            if hasattr(r, "text") and p in (r.text or ""):
                findings.append({"type":"xss-reflected","target":working,"in":"header","header":header_name,"payload":p,"proof_used_url": str(r.url),"confidence":"high","snippet":(r.text or "")[:400]})
                break
    # header-based SQLi detection (rare) - simple check
    for header_name in header_targets:
        for s in SQLI_PAYLOADS:
            headers = {header_name: s}
            r = await _try_request(client, "get", working, headers=headers)
            if hasattr(r, "text"):
                lowb = (r.text or "").lower()
                for sig in DEFAULTS["sql_error_signatures"]:
                    if sig.lower() in lowb:
                        findings.append({"type":"sqli-error","target":working,"in":"header","header":header_name,"payload":s,"evidence":sig,"proof_used_url": str(r.url),"confidence":"high","snippet":lowb[:400]})
                        break
    return findings

async def test_form_endpoint(entry, outdir):
    os.makedirs(outdir, exist_ok=True)
    findings = []
    try:
        working = await resolve_working_url(entry["url"], timeout=6.0)
    except Exception as e:
        findings.append({"type":"form-error","target": entry.get("url"), "error": repr(e)})
        return findings

    async with _SEMAPHORE:
        client = await _get_client()
        try:
            # Query param endpoints
            if entry.get("type") == "query":
                param = entry.get("param")
                findings.extend(await _fuzz_query_param(client, working, param))
                # also test cookie and header injection for query endpoints
                findings.extend(await _fuzz_cookies(client, working, [param]))
                findings.extend(await _fuzz_header_reflection(client, working, [param]))
                await client.aclose()
                return findings

            # Form endpoints
            method = entry.get("method","get").lower()
            params = entry.get("params",[])
            # basic form fuzzing
            findings.extend(await _fuzz_form_fields(client, working, method, params))
            # JSON body fuzzing if endpoint looks like API or accepts JSON
            if "/api/" in working or working.endswith(".json"):
                findings.extend(await _fuzz_json_body(client, working, params))
            else:
                # also attempt JSON fuzzing heuristically for forms with many params
                if len(params) >= 2:
                    findings.extend(await _fuzz_json_body(client, working, params))
            # cookie and header fuzzing
            findings.extend(await _fuzz_cookies(client, working, params))
            findings.extend(await _fuzz_header_reflection(client, working, params))

        finally:
            try:
                await client.aclose()
            except Exception:
                pass

    return findings

async def test_all_params(outdir):
    src = f"{outdir}/params.json"
    if not os.path.exists(src):
        return []
    with open(src) as f:
        items = json.load(f)
    results = []
    for e in items:
        res = await test_form_endpoint(e, outdir)
        results.extend(res)
    # append to existing forms_results if present
    path = f"{outdir}/forms_results.json"
    existing = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.extend(results)
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)
    return existing
