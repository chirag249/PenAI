# debug_http2.py
import httpx, socket, os, sys

hosts = ["https://testphp.vulnweb.com", "http://testphp.vulnweb.com"]
timeout = 15.0

def tcp_check(host, port=443, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return True, None
    except Exception as e:
        return False, repr(e)

for h in hosts:
    print("=== CHECK", h)
    try:
        r = httpx.get(h, timeout=timeout, verify=False, follow_redirects=True)
        print("HTTPX OK", r.status_code)
        print("HEADERS:", dict(r.headers))
        print("BODY SNIPPET:", r.text[:400].replace('\\n',' '))
    except Exception as e:
        print("HTTPX EXCEPTION:", repr(e))

# raw TCP tests
host = "testphp.vulnweb.com"
for p in (443,80):
    ok, err = tcp_check(host, p, timeout=5)
    print(f"TCP {host}:{p} =>", ok, err)

# print proxy env for diagnosis
print("PROXY ENV:", {k:os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy')})
