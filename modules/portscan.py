import asyncio, socket, json, os

async def _tcp_connect(host, port, timeout=1):
    loop = asyncio.get_running_loop()
    try:
        fut = loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout))
        conn = await asyncio.wait_for(fut, timeout+0.5)
        conn.close()
        return True
    except Exception:
        return False

async def async_port_scan(targets, outdir, ports=None):
    if ports is None:
        ports = [80,443,8080,8000,22,21]
    os.makedirs(outdir, exist_ok=True)
    results = {}
    for t in targets:
        host = t.split("//")[-1].split("/")[0]
        results[host] = {}
        tasks = [ _tcp_connect(host, p) for p in ports ]
        res = await asyncio.gather(*tasks)
        for p, r in zip(ports, res):
            results[host][p] = r
    with open(f"{outdir}/ports.json","w") as f:
        json.dump(results, f, indent=2)
    return results
