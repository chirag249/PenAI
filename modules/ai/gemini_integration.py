#!/usr/bin/env python3
# modules/ai/gemini_integration.py
"""
Gemini integration helper for:
 - synthesizing labeled training data
 - lightweight runtime prediction (when local model missing)

Expectations:
 - a `gemini_client` module is available and exposes a `generate(prompt: str, max_tokens:int=..., **kwargs) -> str`
   or similar. If your gemini client function is named differently, update the import/call below.
 - trainer.train_from_examples(run_dir, examples) exists and accepts List[(text,label)].

Environment:
 - GEMINI_API_KEY (or whatever your gemini_client expects) should be set.
"""
from __future__ import annotations
import os
import json
import logging
import time
from typing import List, Tuple, Dict, Any, Optional

logger = logging.getLogger(__name__)

# try to import your gemini client and trainer
try:
    import gemini_client
except Exception:
    gemini_client = None  # type: ignore

try:
    from modules.ai import trainer as ai_trainer
except Exception:
    ai_trainer = None  # type: ignore

# Default labels / prompt templates — extend as desired
DEFAULT_LABELS = [
    "xss-reflected",
    "xss-stored",
    "sqli-error",
    "sqli-blind",
    "rce",
    "sensitive-info-disclosure",
    "open-redirect",
    "auth-bypass",
]

SAMPLE_PROMPT_TEMPLATE = """You are a vulnerability example generator. Produce a realistic short text snippet that could appear in a security scanner finding or a pen-test report, and label it clearly.

Label: {label}

Instructions:
- Provide a single example per response.
- Include short evidence text (1-3 lines) and a concise description.
- Format the output as JSON with keys: "evidence", "description", "payload" (payload may be empty), and "notes".
- Do NOT include any extra commentary outside the JSON.

Example output (exact formatting required):
{{"evidence":"<evidence text>","description":"<one-sentence description>","payload":"<payload-or-empty>","notes":"<optional notes>"}}
"""

def _call_gemini(prompt: str, max_tokens: int = 512, temperature: float = 0.2) -> Optional[str]:
    if gemini_client is None:
        logger.error("gemini_client not available")
        return None
    try:
        # try common names for generation function
        if hasattr(gemini_client, "generate"):
            return gemini_client.generate(prompt, max_tokens=max_tokens, temperature=temperature)
        if hasattr(gemini_client, "completion") and callable(getattr(gemini_client, "completion")):
            return gemini_client.completion(prompt, max_tokens=max_tokens, temperature=temperature)
        # fallback: try a generic call
        return gemini_client(prompt, max_tokens=max_tokens, temperature=temperature)  # type: ignore
    except Exception as e:
        logger.exception("Gemini call failed: %s", e)
        return None

def synthesize_examples(run_dir: str, labels: Optional[List[str]] = None, per_label: int = 40, sleep_between: float = 0.2) -> List[Tuple[str, str]]:
    """
    Generate synthetic training examples using Gemini.

    Returns list of (text, label) tuples. Also writes examples to:
      <run_dir>/generated/ai_training_examples.json
    """
    labels = labels or DEFAULT_LABELS
    examples: List[Tuple[str, str]] = []
    os.makedirs(os.path.join(run_dir, "generated"), exist_ok=True)
    out_path = os.path.join(run_dir, "generated", "ai_training_examples.json")

    logger.info("Starting synthetic data generation: labels=%s per_label=%s", labels, per_label)
    for label in labels:
        prompt = SAMPLE_PROMPT_TEMPLATE.format(label=label)
        for i in range(per_label):
            text = _call_gemini(prompt)
            if not text:
                logger.warning("No response from Gemini for label %s (i=%d)", label, i)
                continue
            # try to parse JSON from response; be tolerant
            parsed = None
            try:
                # Some clients return raw string; strip and load
                s = text.strip()
                # Sometimes there is trailing commentary; take the first {...}
                start = s.find("{")
                end = s.rfind("}")
                if start != -1 and end != -1 and end > start:
                    jtext = s[start:end+1]
                    parsed = json.loads(jtext)
            except Exception:
                parsed = None

            if parsed:
                # Build combined text used for training: evidence + description + payload
                parts = []
                for k in ("evidence", "description", "payload", "notes"):
                    v = parsed.get(k)
                    if isinstance(v, str) and v.strip():
                        parts.append(v.strip())
                combined = " || ".join(parts)[:10000]
                examples.append((combined, label))
            else:
                # fallback: use raw text as training example
                examples.append((text.strip()[:10000], label))

            # brief pause to avoid rate-limits
            time.sleep(sleep_between)

    # save examples
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump([{"text": t, "label": l} for t, l in examples], fh, indent=2, ensure_ascii=False)
        logger.info("Wrote %d synthetic examples to %s", len(examples), out_path)
    except Exception:
        logger.exception("Failed to write synthetic examples")

    return examples

def train_model_from_synthetic(run_dir: str, labels: Optional[List[str]] = None, per_label: int = 40) -> Dict[str, Any]:
    """
    Synthesizes examples via Gemini and calls the trainer to build a model.
    Returns trainer result dict or raises if trainer missing.
    Model files are written under run_dir/generated/.
    """
    if ai_trainer is None:
        raise RuntimeError("ai.trainer not available in modules.ai")

    examples = synthesize_examples(run_dir, labels=labels, per_label=per_label)
    # trainer expects list[tuple(text,label)]
    res = ai_trainer.train_from_examples(run_dir, examples)
    return res

def predict_with_gemini(finding: Dict[str, Any], max_tokens: int = 256) -> Dict[str, Any]:
    """
    Use Gemini to predict vuln_type for a single finding.
    Returns {vuln_type, confidence, explanation} similar to predictor.predict_for_finding.
    """
    # Build prompt from finding contents
    pieces = []
    for k in ("evidence", "description", "request", "response", "raw", "payload", "parameter", "used_url", "target"):
        v = finding.get(k)
        if isinstance(v, str) and v.strip():
            pieces.append(f"{k}: {v.strip()}")
    context = "\n".join(pieces)[:6000]
    prompt = (
        "You are a security classification assistant. Given the following scanner finding context, "
        "return a short JSON with keys: vuln_type (one-word label), confidence (0..1), explanation (short).\\n"
        f"Context:\\n{context}\\n\\n"
        "Output example: {\"vuln_type\":\"xss-reflected\",\"confidence\":0.87,\"explanation\":\"evidence indicates reflected script\"}"
    )
    resp = _call_gemini(prompt, max_tokens=max_tokens, temperature=0.0)
    if not resp:
        return {"vuln_type": "unknown", "confidence": 0.0, "explanation": "no response from gemini"}

    # parse JSON from response
    try:
        s = resp.strip()
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            j = json.loads(s[start:end+1])
            # ensure keys exist
            vuln = str(j.get("vuln_type") or j.get("vuln") or "unknown")
            conf = float(j.get("confidence") or j.get("score") or 0.0)
            expl = str(j.get("explanation") or "")
            return {"vuln_type": vuln, "confidence": conf, "explanation": expl}
    except Exception:
        logger.exception("Failed to parse Gemini response: %s", resp)
    # fallback: very conservative attempt to extract token
    single = resp.strip().splitlines()[0][:200]
    return {"vuln_type": "unknown", "confidence": 0.0, "explanation": f"raw: {single}"}


# CLI helpers
def _cli_train():
    import argparse
    ap = argparse.ArgumentParser(prog="gemini_integration.train")
    ap.add_argument("run_dir", help="run directory to write model into (will use run_dir/generated/)")
    ap.add_argument("--per-label", type=int, default=40, help="examples per label")
    ap.add_argument("--labels", nargs="+", default=None, help="override default labels")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    res = train_model_from_synthetic(args.run_dir, labels=args.labels, per_label=args.per_label)
    print("Trainer result:", res)

def _cli_predict():
    import argparse
    ap = argparse.ArgumentParser(prog="gemini_integration.predict")
    ap.add_argument("--evidence", required=True)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    out = predict_with_gemini({"evidence": args.evidence})
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    # convenience entry: generate+train
    _cli_train()
