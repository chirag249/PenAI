# modules/scanner/param_discovery.py
import os, json, asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import httpx
from bs4 import BeautifulSoup, Tag
from modules.utils import resolve_working_url

# Import adaptive scanning capabilities (for future use)
try:
    from modules.scanner.adaptive_scanner import get_adaptive_config
    adaptive_available = True
except ImportError:
    adaptive_available = False

async def extract_from_page(url, client):
    try:
        working = await resolve_working_url(url, timeout=6.0)
    except Exception:
        return []
    try:
        r = await client.get(working)
    except Exception:
        return []
    out = []
    text = r.text or ""
    # query params from URL
    qs = parse_qs(urlparse(working).query)
    for k in qs.keys():
        out.append({"type":"query","url":working,"param":k})
    # forms
    soup = BeautifulSoup(text, "lxml")
    for form in soup.find_all("form"):
        # Ensure we're working with a Tag object
        if isinstance(form, Tag):
            action = str(form.get("action", "")) if form.get("action") else ""
            method = str(form.get("method", "get")).lower() if form.get("method") else "get"
            action_url = urljoin(working, action)
            inputs = []
            for inp in form.find_all(["input","textarea","select"]):
                # Ensure input is a Tag object
                if isinstance(inp, Tag):
                    name = str(inp.get("name", "")) if inp.get("name") else ""
                    if not name: continue
                    inputs.append(name)
            if inputs:
                out.append({"type":"form","url": action_url, "method": method, "params": inputs})
    # links with query strings
    for a in soup.find_all("a", href=True):
        # Ensure we're working with a Tag object
        if isinstance(a, Tag):
            href = str(a.get("href", "")) if a.get("href") else ""
            if href:
                full = urljoin(working, href)
                parsed = urlparse(full)
                if parsed.query:
                    for k in parse_qs(parsed.query).keys():
                        out.append({"type":"query","url": full, "param": k})
    return out

async def discover_params(scope, outdir):
    os.makedirs(outdir, exist_ok=True)
    src = f"{outdir}/urls.json"
    if not os.path.exists(src):
        return []
    with open(src) as f:
        pages = json.load(f)
    results = []
    async with httpx.AsyncClient(timeout=12, headers={"User-Agent":"PenAI-Min/1.0"}) as client:
        tasks = [ extract_from_page(p.get("used_url") or p.get("url"), client) for p in pages ]
        res = await asyncio.gather(*tasks)
        for r in res:
            results.extend(r)
    # dedupe
    seen = set()
    dedup = []
    for e in results:
        key = json.dumps(e, sort_keys=True)
        if key in seen: continue
        seen.add(key)
        dedup.append(e)
    with open(f"{outdir}/params.json","w") as f:
        json.dump(dedup, f, indent=2)
    return dedup