#!/usr/bin/env python3
"""
Tools manager: run CLI tools (nmap, sqlmap, wpscan, ...) or fall back to mocks.

Hardened implementation:
 - centralizes timeouts and per-tool timeouts
 - sanitizes subprocess environment
 - uses adapters when available (modules/tools/<tool>_adapter.py)
 - writes stable JSON envelope for outputs under generated/tools/
"""
from __future__ import annotations
import os
import json
import shutil
import subprocess
import importlib.util
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
import sys
import platform

logger = logging.getLogger(__name__)
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(os.environ.get("PENAI_LOGLEVEL", "INFO"))

# Optional centralized parser helper (if present)
try:
    from modules.tools.parsers import parse_tool_envelope  # may exist in tree
except Exception:
    parse_tool_envelope = None  # type: ignore

# Import tool configuration system
try:
    from modules.tools.tool_config import get_tool_args, get_tool_timeout, get_scan_profile
    tool_config_available = True
except Exception:
    tool_config_available = False
    # Fallback functions
    def get_tool_args(tool_name: str, profile: Optional[str] = None) -> List[str]:
        return []
    
    def get_tool_timeout(tool_name: str, profile: Optional[str] = None) -> int:
        return 120
    
    def get_scan_profile() -> str:
        return "normal"

# Default timeouts (seconds)
DEFAULT_TIMEOUT = 120

# directory (relative to run outdir) where tool JSON outputs are written
GENERATED_SUBDIR = "generated/tools"

# Optional per-tool timeout overrides (seconds)
TOOL_TIMEOUTS: Dict[str, int] = {
    "sqlmap": 120,
    "nmap": 60,
    "wpscan": 90,
    "nuclei": 45,
}

# POSIX detection for optional resource limiting
_POSIX = platform.system() != "Windows"
resource = None  # type: ignore
if _POSIX:
    try:
        import resource  # type: ignore
    except Exception:
        _POSIX = False
        resource = None  # type: ignore


# ---------------- Helpers ----------------
def _ensure_generated_dir(outdir: str) -> Path:
    p = Path(outdir) / GENERATED_SUBDIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_json(outdir: str, tool: str, data: Dict[str, Any]) -> str:
    """
    Write a stable JSON envelope for a tool under runs/.../generated/tools/<tool>.json
    Returns the path written.
    """
    gen = _ensure_generated_dir(outdir)
    safe_name = f"{tool}.json"
    path = gen / safe_name
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except Exception:
        logger.exception("Failed writing tool output JSON %s", path)
    return str(path)


def _mock_result(tool: str, target: Optional[str]) -> Dict[str, Any]:
    t = target or "<no-target>"
    if tool == "sqlmap":
        return {
            "tool": "sqlmap",
            "status": "mock",
            "target": t,
            "vulnerabilities": [
                {"url": f"{t}/search.php", "parameter": "q", "payload": "' OR '1'='1", "confidence": 0.8}
            ],
        }
    if tool == "nmap":
        return {"tool": "nmap", "status": "mock", "target": t, "hosts": [{"address": t, "ports": [{"port": 80, "state": "open"}]}]}
    if tool == "wpscan":
        return {"tool": "wpscan", "status": "mock", "target": t, "vulnerable": [{"type": "plugin", "name": "example-plugin", "severity": "high"}]}
    return {"tool": tool, "status": "mock", "target": t, "message": "no-op mock output"}


def _run_subproc(cmd: List[str], timeout: int) -> Dict[str, Any]:
    """
    Run subprocess with a sanitized environment and optional POSIX resource limits.
    Returns a dict with rc, stdout, stderr (on timeout rc is None).
    """
    env = os.environ.copy()
    # Keep a minimal PATH so tools found if installed by user
    env["PATH"] = env.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

    preexec_fn = None
    if _POSIX:
        def _preexec():
            try:
                # avoid core dumps
                if resource is not None:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
        preexec_fn = _preexec

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            env=env,
            start_new_session=True,
            preexec_fn=preexec_fn if _POSIX else None,
        )
        return {"rc": proc.returncode, "stdout": proc.stdout or "", "stderr": proc.stderr or ""}
    except subprocess.TimeoutExpired:
        return {"rc": None, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except Exception as e:
        return {"rc": None, "stdout": "", "stderr": str(e)}


def _load_adapter_if_exists(tool_name: str):
    """
    Try to dynamically load modules/tools/<tool_name>_adapter.py or modules/tools/<tool_name>.py
    Return module or None.

    Resolve adapters relative to this manager file: either modules/tools/ (if manager in modules/)
    or the same dir (if manager is already in modules/tools/).
    """
    adapters_dir = Path(__file__).parent
    # if this file is modules/manager.py, adapters are in modules/tools/
    if (adapters_dir / "tools").is_dir():
        adapters_dir = adapters_dir / "tools"

    # First try to load enhanced adapters if available
    enhanced_names = [f"{tool_name}_enhanced_adapter.py"]
    candidate_names = enhanced_names + [f"{tool_name}_adapter.py", f"{tool_name}.py"]
    adapter_path: Optional[Path] = None
    for n in candidate_names:
        p = adapters_dir / n
        if p.exists():
            adapter_path = p
            break

    if not adapter_path:
        return None

    try:
        spec = importlib.util.spec_from_file_location(f"modules.tools.{adapter_path.stem}", str(adapter_path))
        if spec is None or spec.loader is None:
            logger.debug("Spec or loader missing for adapter %s", adapter_path)
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore
        return module
    except Exception:
        logger.exception("Failed to load adapter %s", adapter_path)
        return None


# ---------------- Run helpers ----------------
def run_tool_cmd(cmd: List[str], outdir: str, tool: str, timeout: int) -> Dict[str, Any]:
    """
    Run a command and write envelope JSON. Returns the result dict including output_file.
    """
    logger.debug("Invoking tool command: %s (timeout=%s)", cmd, timeout)
    info = _run_subproc(cmd, timeout)
    status = "ran" if info.get("rc") is not None else "error"
    envelope: Dict[str, Any] = {
        "meta": {"tool": tool, "status": status},
        "result": {"cmd": cmd, "rc": info.get("rc"), "stdout": info.get("stdout"), "stderr": info.get("stderr")},
    }
    envelope["output_file"] = _write_json(outdir, tool, envelope)
    return envelope


# ---------------- Public API ----------------
def run_tool(tool_name: str, outdir: str, target: Optional[str] = None, extra_args: Optional[List[str]] = None, timeout: Optional[int] = None) -> Dict[str, Any]:
    """
    Run a tool by (in order):
      - using an adapter if available (calls adapter.run(outdir=..., target=..., extra_args=..., timeout=...))
      - running the binary on PATH with safe flags
      - returning a mock result if no binary/adapter available

    Writes output JSON under runs/<domain>/<run_id>/generated/tools/<tool>.json
    """
    extra_args = list(extra_args or [])
    timeout = int(timeout or TOOL_TIMEOUTS.get(tool_name, DEFAULT_TIMEOUT))
    logger.info("run_tool: tool=%s target=%s timeout=%s", tool_name, target, timeout)

    # 1) adapter override (preferred)
    adapter = _load_adapter_if_exists(tool_name)
    if adapter:
        run_fn = getattr(adapter, "run", None) or getattr(adapter, "run_sync", None) or getattr(adapter, "main", None)
        if callable(run_fn):
            try:
                # allow adapter to be async / coroutine-returning
                try:
                    res = run_fn(outdir=outdir, target=target, extra_args=extra_args, timeout=timeout)
                except TypeError:
                    # adapter may use positional args
                    res = run_fn(outdir, target, extra_args, timeout)
                if hasattr(res, "__await__"):
                    import asyncio
                    if asyncio.iscoroutine(res):
                        res = asyncio.run(res)
                # Adapter returns an envelope or raw result dict; ensure envelope and persist
                if isinstance(res, dict) and "meta" in res and "result" in res:
                    if "output_file" not in res:
                        res["output_file"] = _write_json(outdir, tool_name, res)
                    return res
                # adapter returned raw result -> wrap into envelope
                envelope = {"meta": {"tool": tool_name, "status": "adapter_return"}, "result": res}  # type: ignore
                envelope["output_file"] = _write_json(outdir, tool_name, envelope)
                return envelope
            except Exception as e:
                logger.exception("Adapter %s raised exception", tool_name)
                err = {"meta": {"tool": tool_name, "status": "adapter_error"}, "result": {"error": str(e)}}  # type: ignore
                err["output_file"] = _write_json(outdir, tool_name, err)  # type: ignore
                return err
        else:
            logger.debug("Adapter loaded for %s but no callable run() found; falling back", tool_name)

    # 2) binary exists? use conservative flags per-known-tool
    bin_path = shutil.which(tool_name)
    if bin_path:
        tool_timeout = TOOL_TIMEOUTS.get(tool_name, timeout)
        # Safe, conservative invocations for known tools
        if tool_name == "sqlmap":
            cmd = [bin_path]
            if target:
                cmd += ["-u", target]
            # Get tool-specific arguments based on profile
            if tool_config_available:
                profile = get_scan_profile()
                tool_args = get_tool_args("sqlmap", profile)
                cmd += tool_args + extra_args
                tool_timeout = get_tool_timeout("sqlmap", profile)
            else:
                # safe flags for CI/dev
                cmd += ["--batch", "--risk=1", "--level=1", "--random-agent", "--timeout=10"] + extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

        if tool_name == "nmap":
            cmd = [bin_path]
            # Get tool-specific arguments based on profile
            if tool_config_available:
                profile = get_scan_profile()
                tool_args = get_tool_args("nmap", profile)
                cmd += tool_args
                tool_timeout = get_tool_timeout("nmap", profile)
            else:
                cmd += ["-Pn", "-sS", "--top-ports", "100"]
            if target:
                cmd.append(target)
            cmd += extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

        if tool_name == "wpscan":
            cmd = [bin_path]
            if target:
                cmd += ["--url", target]
            # Get tool-specific arguments based on profile
            if tool_config_available:
                profile = get_scan_profile()
                tool_args = get_tool_args("wpscan", profile)
                cmd += tool_args + extra_args
                tool_timeout = get_tool_timeout("wpscan", profile)
            else:
                cmd += ["--no-banner"] + extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

        if tool_name == "nuclei":
            cmd = [bin_path, "-silent", "-json"]
            if target:
                cmd += ["-u", target]
            # Get tool-specific arguments based on profile
            if tool_config_available:
                profile = get_scan_profile()
                tool_args = get_tool_args("nuclei", profile)
                cmd += tool_args + extra_args
                tool_timeout = get_tool_timeout("nuclei", profile)
            else:
                cmd += extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

        if tool_name == "nikto":
            cmd = [bin_path, "-h"]
            if target:
                cmd += ["-host", target]
            # Get tool-specific arguments based on profile
            if tool_config_available:
                profile = get_scan_profile()
                tool_args = get_tool_args("nikto", profile)
                cmd += tool_args + extra_args
                tool_timeout = get_tool_timeout("nikto", profile)
            else:
                cmd += extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

        if tool_name == "wapiti":
            cmd = [bin_path, "-u", target] if target else [bin_path]
            cmd += ["-o", "json"] + extra_args
            return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

        # generic fallback: pass target as first arg if present
        cmd = [bin_path] + ([target] if target else []) + extra_args
        return run_tool_cmd(cmd, outdir, tool_name, timeout=tool_timeout)

    # 3) no binary -> return mock (useful for CI/dev)
    logger.info("Tool %s not found on PATH; returning mock output", tool_name)
    mock_envelope = {"meta": {"tool": tool_name, "status": "mocked_no_binary"}, "result": {"note": f"{tool_name} not on PATH; returning mock", "target": target}}
    mock_envelope["result"]["mock_output"] = _mock_result(tool_name, target)
    mock_envelope["output_file"] = _write_json(outdir, tool_name, mock_envelope)
    return mock_envelope
