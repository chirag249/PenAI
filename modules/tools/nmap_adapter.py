# modules/tools/manager.py
"""Tools manager: run CLI tools (nmap, sqlmap, wpscan, ...) or fall back to mocks.

Save this file as modules/tools/manager.py (overwrite previous).
"""
from __future__ import annotations
import os
import json
import shutil
import subprocess
import importlib.util
from pathlib import Path
from typing import Dict, Any, List, Optional

# default per-tool timeout (seconds)
DEFAULT_TIMEOUT = 60

# directory (relative to run outdir) where tool JSON outputs are written
GENERATED_SUBDIR = "generated/tools"

# ----------------- helpers -----------------
def _ensure_generated_dir(outdir: str) -> Path:
    p = Path(outdir) / GENERATED_SUBDIR
    p.mkdir(parents=True, exist_ok=True)
    return p

def _read_run_meta(outdir: str) -> Dict[str, Any]:
    meta_path = Path(outdir) / "run_meta.json"
    if meta_path.exists():
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _write_json(outdir: str, tool: str, data: Dict[str, Any]) -> str:
    gen = _ensure_generated_dir(outdir)
    path = gen / f"{tool}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)

def _mock_result(tool: str, target: Optional[str]) -> Dict[str, Any]:
    t = target or "http://example.com"
    if tool == "sqlmap":
        return {
            "tool": tool,
            "status": "mock",
            "target": t,
            "vulnerabilities": [
                {"url": f"{t}/search.php", "param": "q", "payload": "' OR '1'='1", "confidence": 0.8}
            ],
        }
    if tool == "nmap":
        return {"tool": tool, "status": "mock", "target": t, "hosts": [{"address": t, "ports": [{"port": 80, "state": "open"}]}]}
    if tool == "wpscan":
        return {"tool": tool, "status": "mock", "target": t, "vulnerable_plugins": [{"name": "example-plugin", "severity": "high"}]}
    return {"tool": tool, "status": "mock", "target": t, "message": "mock output"}

def _run_subproc(cmd: List[str], timeout: int) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": None, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except Exception as e:
        return {"rc": None, "stdout": "", "stderr": str(e)}

# ----------------- core run helpers -----------------
def run_tool_cmd(cmd: List[str], outdir: str, tool: str, timeout: int = DEFAULT_TIMEOUT, env: Optional[Dict[str,str]] = None) -> Dict[str, Any]:
    """
    Run arbitrary command, capture stdout/stderr, save result to generated/tools/<tool>.json.
    Returns a dict with metadata and path to saved file.
    """
    env = env or os.environ.copy()
    result = {"tool": tool, "cmd": cmd}
    info = _run_subproc(cmd, timeout)
    result.update({
        "status": "ran" if info.get("rc") is not None else "error",
        "rc": info.get("rc"),
        "stdout": info.get("stdout"),
        "stderr": info.get("stderr"),
    })
    result["output_file"] = _write_json(outdir, tool, result)
    return result

def _load_adapter_if_exists(tool_name: str):
    """Try to dynamically load modules/tools/<tool_name>_adapter.py and return module or None."""
    adapters_dir = Path(__file__).parent
    adapter_path = adapters_dir / f"{tool_name}_adapter.py"
    if not adapter_path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"modules.tools.{tool_name}_adapter", str(adapter_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore
    return module

# ----------------- public API -----------------
def run_tool(tool_name: str, outdir: str, target: Optional[str] = None, extra_args: Optional[List[str]] = None, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    High-level entry to run a tool.
    - If an adapter module `modules/tools/<tool_name>_adapter.py` exists, it will be used.
    - Otherwise, if a binary of the tool exists on PATH, a conservative command will be run.
    - Otherwise, a mock result is returned and saved.
    """
    extra_args = extra_args or []
    meta = _read_run_meta(outdir)
    # prefer explicit target param, otherwise get first target from run_meta
    if not target:
        t = meta.get("targets") or meta.get("target") or meta.get("primary_domain")
        if isinstance(t, list):
            target = t[0] if t else None
        else:
            target = t

    # 1) adapter override
    adapter = _load_adapter_if_exists(tool_name)
    if adapter:
        # adapter can provide run(outdir, target, extra_args)
        if hasattr(adapter, "run") and callable(adapter.run):
            try:
                res = adapter.run(outdir=outdir, target=target, extra_args=extra_args, timeout=timeout)
                # ensure saved
                if isinstance(res, dict):
                    if "output_file" not in res:
                        res["output_file"] = _write_json(outdir, tool_name, res)
                    return res
            except Exception as e:
                err = {"tool": tool_name, "status": "adapter_error", "error": str(e)}
                err["output_file"] = _write_json(outdir, tool_name, err)
                return err

    # 2) binary exists?
    bin_path = shutil.which(tool_name)
    if bin_path:
        # conservative defaults per-known-tool; adapters preferred for complex flags
        if tool_name == "sqlmap":
            cmd = [bin_path, "-u", target] if target else [bin_path]
            # safe flags
            cmd += ["--batch", "--risk=1", "--level=1", "--random-agent", "--timeout=10"] + extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=timeout)
        if tool_name == "nmap":
            cmd = [bin_path, "-Pn", "-sS", "--top-ports", "100"]
            if target:
                cmd.append(target)
            cmd += extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=timeout)
        if tool_name == "wpscan":
            cmd = [bin_path, "--url", target] if target else [bin_path]
            cmd += ["--no-banner"] + extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=timeout)

        # generic fallback run (safe: pass target as first arg)
        cmd = [bin_path] + ([target] if target else []) + extra_args
        return run_tool_cmd(cmd, outdir, tool_name, timeout=timeout)

    # 3) no binary -> return mock (useful for CI/dev)
    mock = {"tool": tool_name, "status": "mocked_no_binary", "note": f"{tool_name} not on PATH; returning mock", "target": target}
    mock["output"] = _mock_result(tool_name, target)
    mock["output_file"] = _write_json(outdir, tool_name, mock)
    return mock
