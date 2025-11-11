# modules/ai/gemini_post.py
from __future__ import annotations
import os
import json
from typing import Dict, Any, List
from modules.ai.gemini_client import generate_findings

def enrich_with_gemini(tool_name: str, envelope: Dict[str, Any], outdir: str) -> List[Dict[str, Any]]:
    findings = generate_findings(tool_name, envelope, run_dir=outdir)
    if not findings:
        return []
    # persist alongside tool JSON
    gen_dir = os.path.join(outdir, "generated", "tools")
    os.makedirs(gen_dir, exist_ok=True)
    path = os.path.join(gen_dir, f"{tool_name}_gemini.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": {"tool": tool_name, "producer": "gemini"}, "findings": findings}, f, indent=2, ensure_ascii=False)
    return findings
