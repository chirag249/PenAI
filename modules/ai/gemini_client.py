#!/usr/bin/env python3
# modules/ai/gemini_client.py
from __future__ import annotations
import os
import json
import time
from typing import Any, Dict, List, Optional

# Optional import — keep your code runnable without the SDK installed
try:
    import google.generativeai as genai  # pip install google-generativeai
except Exception:  # pragma: no cover
    genai = None  # type: ignore


DEFAULT_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-pro")
MAX_RETRIES = 2

# Stable response schema for structured findings
FINDING_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "type":       {"type": "string"},
            "target":     {"type": "string"},
            "severity":   {"type": "integer", "minimum": 1, "maximum": 5},
            "evidence":   {"type": "string"},
            "source":     {"type": "object"},
            "confidence": {"type": "number"},  # 0.0..1.0
        },
        "required": ["type", "target", "severity", "evidence", "source"],
        "additionalProperties": True,
    }
}


PROMPT_TEMPLATE = """You are a security triage assistant.
Input is the JSON envelope from a CLI security tool run (stdout/stderr, target, meta).

Return a JSON array of normalized findings with this exact schema:
[
  {{
    "type": "<short machine-consumable vuln type, e.g. sqli-reflected, xss-reflected, open-port, nuclei-issue>",
    "target": "<url/host:port, or best target string>",
    "severity": <int 1..5>,
    "evidence": "<concise excerpt or explanation>",
    "source": {{
      "tool": "{tool_name}",
      "details": "<optional short note>"
    }},
    "confidence": <0.0..1.0>
  }},
  ...
]

Guidelines:
- Only emit issues you can reasonably infer from the provided output.
- If nothing meaningful is present, return [] (an empty array).
- Prefer HIGH=5, MED=3, LOW=2; reserve 4 and 1 when appropriate.
- Keep evidence short (<= 400 chars).
"""


def _coerce_envelope(envelope_or_path: Any) -> Dict[str, Any]:
    if isinstance(envelope_or_path, str) and os.path.isfile(envelope_or_path):
        with open(envelope_or_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return envelope_or_path if isinstance(envelope_or_path, dict) else {"input": str(envelope_or_path)}


def _ensure_config() -> Optional[str]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or genai is None:
        return None
    genai.configure(api_key=api_key)
    return api_key


def _call_model(prompt: str, model_name: str, system: Optional[str], json_schema: Optional[dict]) -> str:
    model = genai.GenerativeModel(
        model_name,
        system_instruction=system or "You return strictly valid JSON according to the provided schema.",
        generation_config={
            "temperature": 0.2,
            "top_p": 0.9,
            "candidate_count": 1,
            "max_output_tokens": 2048,
            "response_mime_type": "application/json",
            "response_schema": json_schema or FINDING_SCHEMA,
        },
    )
    resp = model.generate_content(prompt)
    # SDK already enforces JSON via response_mime_type; get text
    return resp.text or "[]"


def _safe_json_load(s: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(s)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def generate_findings(
    tool_name: str,
    envelope_or_path: Any,
    run_dir: Optional[str] = None,
    model: Optional[str] = None,
    include_raw: bool = False,
) -> List[Dict[str, Any]]:
    """
    Use Gemini to convert a tool envelope (stdout/stderr/meta) into normalized findings.
    Returns a list of dicts with keys: type, target, severity, evidence, source, confidence.
    If GEMINI_API_KEY or SDK is missing, returns [].
    """
    if _ensure_config() is None:
        return []

    env = _coerce_envelope(envelope_or_path)
    # Compact the envelope to keep token usage reasonable
    compact = {
        "meta": env.get("meta") or {},
        "target": env.get("target") or env.get("url"),
        "result": {
            "rc": ((env.get("result") or {}).get("rc") if isinstance(env.get("result"), dict) else None),
            "stdout": ((env.get("result") or {}).get("stdout") if isinstance(env.get("result"), dict) else env.get("stdout")) or "",
            "stderr": ((env.get("result") or {}).get("stderr") if isinstance(env.get("result"), dict) else env.get("stderr")) or "",
        },
    }
    if include_raw:
        compact["__raw_truncated__"] = str(env)[:4000]

    prompt = PROMPT_TEMPLATE.format(tool_name=tool_name) + "\n\n" + json.dumps(compact, ensure_ascii=False, indent=2)
    model_name = model or DEFAULT_MODEL

    # Retry a couple of times if JSON parse fails
    last_txt = "[]"
    for i in range(MAX_RETRIES + 1):
        try:
            txt = _call_model(prompt, model_name, system=None, json_schema=FINDING_SCHEMA)
            last_txt = txt
            parsed = _safe_json_load(txt)
            if isinstance(parsed, list):
                # normalize & enforce fields
                out: List[Dict[str, Any]] = []
                for f in parsed:
                    if not isinstance(f, dict):
                        continue
                    f.setdefault("type", f"{tool_name}-issue")
                    f.setdefault("target", compact.get("target") or "<unknown>")
                    try:
                        sev = int(f.get("severity", 3))
                    except Exception:
                        sev = 3
                    f["severity"] = max(1, min(5, sev))
                    f.setdefault("evidence", "")
                    src = f.get("source") if isinstance(f.get("source"), dict) else {}
                    src.setdefault("tool", tool_name)
                    f["source"] = src
                    # clamp confidence
                    try:
                        conf = float(f.get("confidence", 0.6))
                    except Exception:
                        conf = 0.6
                    f["confidence"] = max(0.0, min(1.0, conf))
                    out.append(f)
                return out
        except Exception:
            if i < MAX_RETRIES:
                time.sleep(0.6 * (i + 1))
                continue
            break
    # If everything failed, return empty
    return []
