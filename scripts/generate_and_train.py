#!/usr/bin/env python3
# scripts/generate_and_train.py
from __future__ import annotations
import os
import random
import json
from modules.ai.trainer import train_from_examples

# Small seed bank of (text, label) examples
PROMPT_BANK = [
    ("Reflected script tag <script>alert(1)</script> in query parameter q", "xss"),
    ("Boolean-based SQL injection detected via ' OR 1=1-- in id parameter", "sqli"),
    ("Stack trace disclosure on /debug reveals framework versions", "info"),
    ("File inclusion via ../../etc/passwd observed in include parameter", "lfi"),
    ("Remote code execution via eval(payload) in user agent handler", "rce"),
]

def synthesize_examples(synth_per_label: int = 8):
    examples = list(PROMPT_BANK)
    synonyms = {
        "xss": ["alert box", "html injection", "payload executes in browser", "reflected script"],
        "sqli": ["database error", "union select", "sql error-based", "boolean-based"],
        "info": ["server header", "verbose error", "stack trace", "debug info"],
        "lfi": ["directory traversal", "file read", "path traversal"],
        "rce": ["remote code execution", "exec payload", "command injection"],
    }
    for text, label in PROMPT_BANK:
        for _ in range(synth_per_label):
            extra = random.choice(synonyms.get(label, ["additional context"]))
            examples.append((f"{text}. Also observed: {extra}.", label))
    return examples

def main(run_dir: str, synth_per_label: int = 8):
    os.makedirs(os.path.join(run_dir, "generated"), exist_ok=True)
    examples = synthesize_examples(synth_per_label)
    # Save a sample of training examples for review
    try:
        with open(os.path.join(run_dir, "generated", "train_examples.json"), "w", encoding="utf-8") as fh:
            json.dump(examples, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass

    out = train_from_examples(run_dir, examples)
    print("train result:", out)

if __name__ == "__main__":
    import sys
    run_dir = sys.argv[1] if len(sys.argv) > 1 else "runs/local_ai_train"
    synth_per_label = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    main(run_dir, synth_per_label)
