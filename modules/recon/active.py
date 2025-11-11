# modules/recon/active.py
import asyncio, json, os
import httpx
from modules.portscan import async_port_scan
from modules.utils import resolve_working_url

async def _probe_target(client, target):
    try:
        working = await resolve_working_url(target, timeout=6.0)
    except Exception as e:
        return {target: {"error": repr(e)}}
    try:
        r = await client.head(working, follow_redirects=True)
        return {target: {"status": r.status_code, "headers": dict(r.headers), "used_url": working}}
    except Exception as e:
        return {target: {"error": repr(e), "used_url": working}}

async def active_recon(scope, outdir, concurrency=10):
    os.makedirs(outdir, exist_ok=True)
    results = {}
    async with httpx.AsyncClient(timeout=10, headers={"User-Agent":"PenAI-Min/1.0"}) as client:
        tasks = []
        for t in scope.targets:
            tasks.append(_probe_target(client, t))
        res = await asyncio.gather(*tasks)
        for r in res:
            results.update(r)
    ports = await async_port_scan(scope.targets, outdir)
    results["ports"] = ports
    with open(f"{outdir}/active.json","w") as f:
        json.dump(results, f, indent=2)
    return results
