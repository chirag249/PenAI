#!/usr/bin/env python3
"""
Nmap parser.

Reads JSON output from nmap_adapter and normalizes into findings list.
Each finding = {type, severity, target, evidence}
"""

from __future__ import annotations
import json
import os
from typing import List, Dict, Any


def parse_nmap_file(path: str) -> List[Dict[str, Any]]:
    """
    Parse the JSON envelope produced by nmap_adapter.
    Returns list of normalized findings.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"nmap result file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    findings: List[Dict[str, Any]] = []
    result = data.get("result") or {}
    stdout = result.get("stdout", "")

    # If adapter already parsed hosts, prefer that
    hosts = result.get("hosts") or data.get("parsed_hosts")
    if hosts:
        for host in hosts:
            addr = host.get("address") or data.get("target")
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    findings.append({
                        "type": "open-port",
                        "severity": 2,
                        "target": addr,
                        "evidence": f"Port {port.get('port')}/tcp open",
                    })

    # Fallback: crude stdout parse
    if not findings and stdout:
        for line in stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                try:
                    port_proto = parts[0]
                    findings.append({
                        "type": "open-port",
                        "severity": 2,
                        "target": data.get("meta", {}).get("tool_target") or "<unknown>",
                        "evidence": line.strip()[:200],
                    })
                except Exception:
                    continue

    return findings


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("file", help="Path to nmap.json produced by adapter")
    args = p.parse_args()
    parsed = parse_nmap_file(args.file)
    print(json.dumps(parsed, indent=2))
