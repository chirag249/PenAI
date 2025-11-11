# modules/tools/adapters/sqlmap_adapter.py
import os
import subprocess
from typing import Dict, Any, Optional

SQLMAP_BIN = os.environ.get("SQLMAP_BIN", "sqlmap")

def run(target: str, run_dir: str, options: Optional[Dict[str,Any]] = None, timeout: int = 300) -> Dict[str,Any]:
    options = options or {}
    args = [SQLMAP_BIN, "-u", target, "--batch", "--flush-session"]
    if "level" in options:
        args += ["--level", str(options["level"])]
    if "risk" in options:
        args += ["--risk", str(options["risk"])]
    if "data" in options:
        args += ["--data", options["data"]]

    os.makedirs(run_dir, exist_ok=True)
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        out = {
            "returncode": proc.returncode,
            "stdout": stdout[:20000],
            "stderr": stderr[:20000],
        }
        low = (stdout + stderr).lower()
        out["vuln"] = ("is vulnerable" in low) or ("sql injection" in low) or ("payload:" in low)
        return out
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "timeout": timeout}
    except FileNotFoundError as e:
        return {"error": "binary_not_found", "message": str(e)}
    except Exception as e:
        return {"error": "exception", "message": str(e)}
