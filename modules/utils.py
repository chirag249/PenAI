# modules/utils.py
import httpx
from urllib.parse import urlparse, urlunparse

DEFAULT_TIMEOUT = 8.0

async def resolve_working_url(url, timeout=DEFAULT_TIMEOUT):
    """
    Return a reachable URL for the given host. Prefer original scheme,
    fallback to the other (http <-> https). Raises RuntimeError if neither works.
    """
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    if not host:
        raise RuntimeError(f"Invalid URL: {url}")
    candidates = []
    if parsed.scheme in ("http","https"):
        candidates.append(parsed.scheme)
        candidates.append("https" if parsed.scheme == "http" else "http")
    else:
        candidates = ["https","http"]

    path = parsed.path or "/"
    query = parsed.query or ""
    for scheme in candidates:
        test = urlunparse((scheme, host, path, parsed.params, query, parsed.fragment))
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=True) as client:
                # try HEAD first
                try:
                    r = await client.head(test)
                    if r.status_code and r.status_code < 600:
                        return test
                except Exception:
                    # fallback to GET
                    r = await client.get(test)
                    if r.status_code and r.status_code < 600:
                        return test
        except Exception:
            continue
    raise RuntimeError(f"Neither http nor https reachable for {host}")
