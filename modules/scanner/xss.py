# modules/scanner/xss.py
import httpx, urllib.parse, json, os
from config import DEFAULTS
from modules.utils import resolve_working_url

# Import adaptive scanning capabilities
adaptive_available = False
get_adaptive_config = None
get_adaptive_payloads = None

try:
    from modules.scanner.adaptive_scanner import get_adaptive_config as _get_adaptive_config, get_adaptive_payloads as _get_adaptive_payloads
    get_adaptive_config = _get_adaptive_config
    get_adaptive_payloads = _get_adaptive_payloads
    adaptive_available = True
except ImportError:
    pass

async def xss_check(url, outdir, config=None):
    os.makedirs(outdir, exist_ok=True)
    findings = []
    
    # Get adaptive configuration
    if config is None:
        config = {"timeout": 10, "payload_intensity": "normal"}
        if adaptive_available and get_adaptive_config:
            try:
                config = get_adaptive_config("xss", url, outdir)
            except Exception:
                pass
    
    try:
        working = await resolve_working_url(url, timeout=float(config["timeout"]))
    except Exception as e:
        findings.append({"type":"xss-error","target":url,"error":repr(e)})
        with open(f"{outdir}/xss.json","w") as f:
            json.dump(findings, f, indent=2)
        return findings

    async with httpx.AsyncClient(timeout=config["timeout"], headers={"User-Agent":DEFAULTS["user_agent"]}) as client:
        try:
            # Get adaptive payloads
            payloads = ["<script>alert(1)</script>"]  # Default payload
            if adaptive_available and get_adaptive_payloads:
                try:
                    adaptive_payloads = get_adaptive_payloads("xss", url, outdir)
                    if adaptive_payloads:
                        payloads = adaptive_payloads
                except Exception:
                    pass
            
            # Test each payload
            for payload in payloads:
                sep = "&" if "?" in working else "?"
                test_url = working + sep + "penai_xss_test=" + urllib.parse.quote(payload)
                try:
                    r = await client.get(test_url)
                    body = r.text or ""
                    if payload in body:
                        findings.append({
                            "type":"xss-reflected",
                            "target": url,
                            "used_url": working,
                            "evidence": "marker reflected in response",
                            "proof_url": test_url,
                            "confidence":"high",
                            "snippet": body[:400]
                        })
                        # If we found a vulnerability, we might want to stop testing more payloads
                        break
                except Exception as e:
                    findings.append({"type":"xss-error","target":url,"error":repr(e),"used_url": working})
                    break  # Stop on error
            
            # If no XSS found, add a none finding
            if not any(f.get("type") == "xss-reflected" for f in findings):
                # Test a simple request to get status code
                try:
                    r = await client.get(working)
                    findings.append({"type":"xss-none","target":url,"used_url": working,"confidence":"low","note":"marker not found","status":r.status_code,"snippet":(r.text or "")[:300]})
                except Exception as e:
                    findings.append({"type":"xss-none","target":url,"used_url": working,"confidence":"low","note":f"request failed: {repr(e)}","snippet":""})
        except Exception as e:
            findings.append({"type":"xss-error","target":url,"error":repr(e),"used_url": working})
    with open(f"{outdir}/xss.json","w") as f:
        json.dump(findings, f, indent=2)
    return findings