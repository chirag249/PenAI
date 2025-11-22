# modules/fingerprint.py
import json, os, re
from urllib.parse import urlparse
import httpx
from modules.utils import resolve_working_url

# COMMON_HEADERS = ["server","x-powered-by","via","x-cms","set-cookie"]

async def fingerprint(scope, outdir):
    os.makedirs(outdir, exist_ok=True)
    findings = {}
    for t in scope.targets:
        try:
            working = await resolve_working_url(t, timeout=6.0)
        except Exception as e:
            findings[t] = {"error": repr(e)}
            continue
        try:
            async with httpx.AsyncClient(timeout=10, headers={"User-Agent":"PenAI-Min/1.0"}) as client:
                r = await client.get(working)
                headers = dict(r.headers)
                info = {"used_url": working, "status": r.status_code, "headers": {}}
                for h in COMMON_HEADERS:
                    if h in headers:
                        info["headers"][h] = headers[h]
                # simple body fingerprint: look for common CMS markers
                body = (r.text or "").lower()
                cms = None
                if "wp-content" in body or "wordpress" in body:
                    cms = "wordpress"
                elif "django" in body:
                    cms = "django"
                elif "joomla" in body:
                    cms = "joomla"
                if cms:
                    info["cms"] = cms
                # version-like regex in headers/body
                vers = re.findall(r"(php|apache|nginx|wordpress)[/ ]?([0-9\.]+)", (r.headers.get("server","")+" "+body))
                if vers:
                    info["versions"] = vers[:3]
                findings[t] = info
        except Exception as e:
            findings[t] = {"error": repr(e), "used_url": working}
    with open(f"{outdir}/fingerprint.json","w") as f:
        json.dump(findings, f, indent=2)
    return findings
