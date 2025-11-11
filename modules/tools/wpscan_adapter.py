# modules/tools/wpscan_adapter.py
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

def _parse_wpscan(stdout: str):
    # Very light parse: look for plugin/vuln lines that contain 'Vulnerable'
    vulns = []
    for line in stdout.splitlines():
        line = line.strip()
        if "Vulnerable" in line or "vulnerable" in line.lower():
            vulns.append(line)
    return vulns

def run(outdir: str, target: Optional[str], extra_args=None, timeout=60) -> Dict[str, Any]:
    extra_args = extra_args or []
    binp = shutil.which("wpscan")
    if not binp:
        return {"tool": "wpscan", "status": "adapter_missing_binary", "note": "wpscan not found on PATH"}
    cmd = [binp, "--url", target] if target else [binp]
    cmd += ["--no-banner"] + extra_args
    info = _run(cmd, timeout=timeout)
    vulns = _parse_wpscan(info["stdout"])
    res = {"tool": "wpscan", "status": "ran", "rc": info["rc"], "vulnerabilities": vulns, "stdout": info["stdout"], "stderr": info["stderr"]}
    gen_dir = Path(outdir) / "generated" / "tools"
    gen_dir.mkdir(parents=True, exist_ok=True)
    of = gen_dir / "wpscan_adapter.json"
    of.write_text(json.dumps(res, indent=2), encoding="utf-8")
    res["output_file"] = str(of)
    return res
