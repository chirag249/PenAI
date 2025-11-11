# modules/crawler.py
import os, json
from urllib.parse import urljoin, urldefrag, urlparse
import httpx
from modules.utils import resolve_working_url

async def crawl(scope, outdir, max_pages=200):
    os.makedirs(outdir, exist_ok=True)
    visited = set()
    to_visit = list(scope.targets)
    results = []
    async with httpx.AsyncClient(timeout=12, headers={"User-Agent":"PenAI-Min/1.0"}) as client:
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            try:
                # resolve working scheme
                working = await resolve_working_url(url, timeout=6.0)
            except Exception:
                visited.add(url)
                continue
            try:
                r = await client.get(working)
                snippet = (r.text or "")[:800]
                results.append({"url": url, "used_url": working, "status": r.status_code, "snippet": snippet})
                visited.add(url)
                # extract hrefs naively
                for part in (r.text or "").split('href="')[1:]:
                    href = part.split('"',1)[0]
                    if not href:
                        continue
                    next_url = urljoin(working, href)
                    next_url = urldefrag(next_url)[0]
                    if urlparse(next_url).netloc == urlparse(working).netloc and next_url not in visited:
                        to_visit.append(next_url)
            except Exception:
                visited.add(url)
                continue
    with open(f"{outdir}/urls.json","w") as f:
        json.dump(results, f, indent=2)
    return results
