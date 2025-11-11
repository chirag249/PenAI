# modules/tools/nuclei_adapter.py
from __future__ import annotations
import shutil, subprocess, json
from pathlib import Path
from typing import Dict, Any, Optional

def _run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": None, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"rc": None, "stdout": "", "stderr": str(e)}

def _parse_nuclei_stdout(stdout: str):
    # nuclei default line format: <target> <template> <info>
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line: continue
        parts = line.split(" ", 2)
        if len(parts) >= 2:
            findings.append({"target": parts[0], "template": parts[1], "raw": parts[2] if len(parts) > 2 else ""})
    return findings

def run(outdir: str, target: Optional[str], extra_args=None, timeout=60) -> Dict[str, Any]:
    extra_args = extra_args or []
    binp = shutil.which("nuclei")
    if not binp:
        return {"tool": "nuclei", "status": "adapter_missing_binary", "note": "nuclei not found on PATH"}
    cmd = [binp, "-silent"]
    if target:
        cmd += ["-u", target]
    # avoid heavy checks by default; users can supply extra_args for templates
    cmd += extra_args
    info = _run(cmd, timeout=timeout)
    findings = _parse_nuclei_stdout(info["stdout"])
    res = {"tool": "nuclei", "status": "ran", "rc": info["rc"], "findings": findings, "stdout": info["stdout"], "stderr": info["stderr"]}
    gen_dir = Path(outdir) / "generated" / "tools"
    gen_dir.mkdir(parents=True, exist_ok=True)
    of = gen_dir / "nuclei_adapter.json"
    of.write_text(json.dumps(res, indent=2), encoding="utf-8")
    res["output_file"] = str(of)
    return res
