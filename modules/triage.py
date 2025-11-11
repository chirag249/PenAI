# modules/triage.py
def score_finding(f):
    # confidence -> base
    base_map = {"info":1,"low":2,"medium":3,"high":4,"critical":5}
    conf = f.get("confidence","low")
    score = base_map.get(conf,2)

    t = f.get("type","").lower()
    # promote scores for high-impact types
    if "sqli-error" in t:
        # if evidence present and proof URL, escalate
        if f.get("evidence") or f.get("proof") or f.get("proof_used_url"):
            score = max(score,5)
        else:
            score = max(score,4)
    if "xss-reflected" in t:
        # reflected XSS reliable -> high
        score = max(score,4)
        # if target is auth-protected or shopping cart (sensitive), escalate
        url = f.get("target","").lower()
        if any(k in url for k in ["/login","/cart","/user","/checkout","/signup"]):
            score = max(score,5)
    if "sqli-none" in t and f.get("status") and f["status"]>=500:
        score = max(score,3)

    # downgrade if only redirect to login or page indicates auth required
    snippet = (f.get("snippet") or "").lower()
    if "you must login" in snippet or "please login" in snippet:
        score = min(score,3)

    return min(max(int(score),0),5)

def triage_all(findings):
    out = []
    for f in findings:
        s = score_finding(f)
        f["severity"] = s
        out.append(f)
    return out
