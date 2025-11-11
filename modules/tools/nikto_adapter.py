# modules/tools/nikto_adapter.py
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

def _parse_nikto(stdout: str):
    # Nikto prints findings lines often prefixed by + or OSVDB; collect those
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("+ ") or line.startswith("OSVDB-") or "Server may leak" in line:
            findings.append(line)
    return findings

def run(outdir: str, target: Optional[str], extra_args=None, timeout=60) -> Dict[str, Any]:
    extra_args = extra_args or []
    binp = shutil.which("nikto")
    if not binp:
        return {"tool": "nikto", "status": "adapter_missing_binary", "note": "nikto not found on PATH"}
    cmd = [binp, "-host", target] if target else [binp]
    # don't use intrusive options by default
    cmd += extra_args
    info = _run(cmd, timeout=timeout)
    findings = _parse_nikto(info["stdout"])
    res = {"tool": "nikto", "status": "ran", "rc": info["rc"], "findings": findings, "stdout": info["stdout"], "stderr": info["stderr"]}
    gen_dir = Path(outdir) / "generated" / "tools"
    gen_dir.mkdir(parents=True, exist_ok=True)
    of = gen_dir / "nikto_adapter.json"
    of.write_text(json.dumps(res, indent=2), encoding="utf-8")
    res["output_file"] = str(of)
    return res
