#!/usr/bin/env python3
"""Adapter stub for medusa.

This is a **safe** stub:
 - looks for binary on PATH
 - runs with conservative flags when available
 - writes envelope to runs/<run>/generated/tools/medusa.json

Please edit to add tool-specific flags and parsing.
"""
from pathlib import Path
import shutil, subprocess, json, os

def run(outdir, target=None, extra_args=None, timeout=60):
    tool = "medusa"
    gen = Path(outdir) / "generated" / "tools"
    gen.mkdir(parents=True, exist_ok=True)
    envelope = { "meta": { "tool": tool }, "result": {} }
    binp = shutil.which(tool)
    if not binp:
        envelope["meta"]["status"] = "mocked_no_binary"
        envelope["result"]["stdout"] = f"mock output for {tool}"
        envelope["parsed_findings"] = []
    else:
        cmd = [binp]
        # conservative defaults - override in actual implementation
        if target:
            cmd += ["-u", target] if "medusa" in ("sqlmap","nuclei") else [target]
        if extra_args:
            cmd += extra_args
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
            envelope["meta"]["status"] = "ran"
            envelope["result"].update({"cmd": cmd, "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr})
            envelope["parsed_findings"] = []
        except subprocess.TimeoutExpired:
            envelope["meta"]["status"] = "timeout"
            envelope["result"].update({"cmd": cmd, "rc": None, "stderr": "timeout"})
            envelope["parsed_findings"] = []
        except Exception as e:
            envelope["meta"]["status"] = "error"
            envelope["result"].update({"cmd": cmd, "rc": None, "stderr": str(e)})
            envelope["parsed_findings"] = []
    outp = gen / f"{tool}.json"
    with open(outp, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2)
    return envelope
