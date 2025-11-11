#!/usr/bin/env python3
"""
scripts/generate_adapters_stubs.py

Usage:
  PYTHONPATH=. python3 scripts/generate_adapters_stubs.py tool1 tool2 tool3 ...
Example:
  PYTHONPATH=. python3 scripts/generate_adapters_stubs.py nmap nuclei sqlmap nikto ffuf
"""
from pathlib import Path
import sys, os, textwrap

ADAPTER_TMPL = """#!/usr/bin/env python3
\"\"\"Adapter stub for {tool}.

This is a **safe** stub:
 - looks for binary on PATH
 - runs with conservative flags when available
 - writes envelope to runs/<run>/generated/tools/{tool}.json

Please edit to add tool-specific flags and parsing.
\"\"\"
from pathlib import Path
import shutil, subprocess, json, os

def run(outdir, target=None, extra_args=None, timeout=60):
    tool = "{tool}"
    gen = Path(outdir) / "generated" / "tools"
    gen.mkdir(parents=True, exist_ok=True)
    envelope = {{ "meta": {{ "tool": tool }}, "result": {{}} }}
    binp = shutil.which(tool)
    if not binp:
        envelope["meta"]["status"] = "mocked_no_binary"
        envelope["result"]["stdout"] = f"mock output for {{tool}}"
        envelope["parsed_findings"] = []
    else:
        cmd = [binp]
        # conservative defaults - override in actual implementation
        if target:
            cmd += ["-u", target] if "{tool}" in ("sqlmap","nuclei") else [target]
        if extra_args:
            cmd += extra_args
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
            envelope["meta"]["status"] = "ran"
            envelope["result"].update({{"cmd": cmd, "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}})
            envelope["parsed_findings"] = []
        except subprocess.TimeoutExpired:
            envelope["meta"]["status"] = "timeout"
            envelope["result"].update({{"cmd": cmd, "rc": None, "stderr": "timeout"}})
            envelope["parsed_findings"] = []
        except Exception as e:
            envelope["meta"]["status"] = "error"
            envelope["result"].update({{"cmd": cmd, "rc": None, "stderr": str(e)}})
            envelope["parsed_findings"] = []
    outp = gen / f"{{tool}}.json"
    with open(outp, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2)
    return envelope
"""

PARSER_TMPL = """#!/usr/bin/env python3
\"\"\"Parser stub for {tool}.

Implement `parse_{tool}_output` or similar functions. The top-level parse_tool_envelope dispatcher
will try several function names. This stub provides a simple normalizer.

Returns list of normalized findings:
  {{ type, target, severity, evidence, source }}
\"\"\"
def parse_{tool}_output(envelope, run_dir=None):
    out = []
    # prefer adapter-provided parsed_findings
    pf = envelope.get("parsed_findings") or (envelope.get("result") or {{}}).get("parsed_findings")
    if isinstance(pf, list) and pf:
        for p in pf:
            out.append({{
                "type": p.get("type") or "{tool}-vuln",
                "target": p.get("target") or envelope.get("result",{{}}).get("target") or "<unknown>",
                "severity": int(p.get("severity") or 3),
                "evidence": p.get("evidence") or str(p)[:500],
                "source": {{"tool": "{tool}", "raw": p}}
            }})
        return out

    # fallback: look at stdout text
    res = envelope.get("result") or envelope
    stdout = (res.get("stdout") if isinstance(res, dict) else None) or ""
    if isinstance(stdout, str) and ("vulnerable" in stdout.lower() or "cve" in stdout.lower()):
        out.append({{
            "type": "{tool}-inferred",
            "target": envelope.get("result",{{}}).get("target") or "<unknown>",
            "severity": 3,
            "evidence": stdout[:1000],
            "source": {{"tool": "{tool}", "raw": stdout}},
        }})
    return out
"""

def safe_mkdir(p: Path):
    p.parent.mkdir(parents=True, exist_ok=True)

def write_file(p: Path, content: str):
    if p.exists():
        print("exists, skipping:", p)
        return
    safe_mkdir(p)
    p.write_text(content, encoding="utf-8")
    print("wrote:", p)

def main(names):
    repo_root = Path(__file__).resolve().parent.parent
    tools_dir = repo_root / "modules" / "tools"
    parsers_dir = repo_root / "modules" / "tools" / "parsers"
    tools_dir.mkdir(parents=True, exist_ok=True)
    parsers_dir.mkdir(parents=True, exist_ok=True)
    for n in names:
        tool = n.strip().lower()
        if not tool:
            continue
        adapter_path = tools_dir / f"{tool}_adapter.py"
        parser_path = parsers_dir / f"{tool}_parser.py"
        write_file(adapter_path, ADAPTER_TMPL.format(tool=tool))
        write_file(parser_path, PARSER_TMPL.format(tool=tool))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: generate_adapters_stubs.py tool1 tool2 ...")
        raise SystemExit(1)
    main(sys.argv[1:])
