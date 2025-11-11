TEMPLATE = """#!/usr/bin/env python3
\"\"\"Generated test script
Safe-mode checks present. Run in sandboxed environment only.
\"\"\"
import os, sys, httpx, json, signal

# safety checks
if os.environ.get("PENTEST_DESTRUCTIVE") != "1":
    print("Script blocked: destructive env not set.")
    sys.exit(2)

TIMEOUT = 8
TARGET = "{target}"

def handler(sig, frame):
    print("Timeout/abort received.")
    sys.exit(1)

signal.signal(signal.SIGALRM, handler)
# signal.alarm(30)

def run():
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.get(TARGET)
            print(r.status_code)
            print(r.text[:500])
    except Exception as e:
        print("err", e)

if __name__=="__main__":
    run()
"""
