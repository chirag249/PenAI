# modules/recon/passive.py
import asyncio, json, os
import httpx
from modules.utils import resolve_working_url

async def passive_recon(scope, outdir):
    os.makedirs(outdir, exist_ok=True)
    results = {}
    for t in scope.targets:
        try:
            working = await resolve_working_url(t, timeout=8.0)
        except Exception as e:
            results[t] = {"error": repr(e)}
            continue
        async with httpx.AsyncClient(timeout=12, headers={"User-Agent":"PenAI-Min/1.0"}) as client:
            try:
                r = await client.get(working)
                results[t] = {"status": r.status_code, "title": _extract_title(r.text), "snippet": r.text[:400], "used_url": working}
            except Exception as e:
                results[t] = {"error": repr(e), "used_url": working}
    with open(f"{outdir}/passive.json","w") as f:
        json.dump(results, f, indent=2)
    return results

def _extract_title(html):
    start = html.find("<title>")
    end = html.find("</title>")
    if start!=-1 and end!=-1:
        return html[start+7:end].strip()
    return ""
