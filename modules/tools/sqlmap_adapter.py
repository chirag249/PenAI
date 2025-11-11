#!/usr/bin/env python3
"""
Simple sqlmap adapter used by tests/CI.

Writes a JSON envelope to:
 - runs/<run>/generated/tools/sqlmap.json
 - and also to runs/<run>/generated/sqlmap.json (compat shim)
Returns the envelope dict with output_file set.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 90
GENERATED_TOOLS_SUBDIR = "generated/tools"
GENERATED_SUBDIR = "generated"


def _ensure_dir(outdir: str, sub: str) -> Path:
    p = Path(outdir) / sub
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_json(path: Path, data: Dict[str, Any]) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return str(path)


def _mock_parse_stdout(stdout: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    s = (stdout or "").lower()
    if ("is vulnerable" in s or "vulnerable" in s) and "parameter" in s:
        lines = stdout.splitlines()
        for L in lines:
            if "parameter" in L.lower() or "payload" in L.lower() or "title:" in L.lower():
                findings.append({
                    "type": "sqli-sqlmap",
                    "severity": 5,
                    "evidence": L.strip()[:1000],
                })
        if not findings:
            findings.append({
                "type": "sqli-sqlmap",
                "severity": 5,
                "evidence": stdout.strip()[:2000],
            })
    if "syntax error" in s or ("mysql" in s and "error" in s):
        findings.append({
            "type": "sqli-error",
            "severity": 4,
            "evidence": "sql error seen in output",
        })
    return findings


def run(outdir: str, target: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        timeout: Optional[int] = None) -> Dict[str, Any]:
    extra_args = extra_args or []
    timeout = int(timeout or DEFAULT_TIMEOUT)
    bin_path = shutil.which("sqlmap")
    tool_name = "sqlmap"

    envelope: Dict[str, Any] = {"meta": {"tool": tool_name}, "result": {}}

    gen_tools = _ensure_dir(outdir, GENERATED_TOOLS_SUBDIR)
    gen_root = _ensure_dir(outdir, GENERATED_SUBDIR)

    if not bin_path:
        envelope["meta"]["status"] = "mocked_no_binary"
        envelope["result"]["note"] = "sqlmap not on PATH; returning mock"
        envelope["result"]["stdout"] = "Mock: web application is vulnerable (parameter: q)"
        envelope["parsed_findings"] = _mock_parse_stdout(envelope["result"]["stdout"])
        outp1 = gen_tools / f"{tool_name}.json"
        outp2 = gen_root / f"{tool_name}.json"
        envelope["output_file"] = str(outp1)
        _write_json(outp1, envelope)
        _write_json(outp2, envelope)
        envelope["status"] = envelope["meta"]["status"]
        return envelope

    cmd = [bin_path]
    if target:
        cmd += ["-u", target]
    cmd += ["--batch", "--risk=1", "--level=1", "--random-agent", "--timeout=10"]
    if extra_args:
        cmd += extra_args

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        envelope["meta"]["status"] = "ran"
        envelope["result"].update({
            "cmd": cmd,
            "rc": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        })
        envelope["parsed_findings"] = _mock_parse_stdout(stdout + "\n" + stderr)
    except subprocess.TimeoutExpired:
        envelope["meta"]["status"] = "timeout"
        envelope["result"].update({
            "cmd": cmd,
            "rc": None,
            "stdout": "",
            "stderr": f"timeout after {timeout}s",
        })
        envelope["parsed_findings"] = []
    except Exception as e:
        envelope["meta"]["status"] = "error"
        envelope["result"].update({
            "cmd": cmd,
            "rc": None,
            "stdout": "",
            "stderr": str(e),
        })
        envelope["parsed_findings"] = []

    outp1 = gen_tools / f"{tool_name}.json"
    outp2 = gen_root / f"{tool_name}.json"
    envelope["output_file"] = str(outp1)
    _write_json(outp1, envelope)
    _write_json(outp2, envelope)
    envelope["status"] = envelope["meta"]["status"]
    return envelope


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("outdir")
    p.add_argument("--target", default=None)
    args = p.parse_args()
    print(run(args.outdir, target=args.target))
