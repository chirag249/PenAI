#!/usr/bin/env python3
"""
scripts/generate_synth_examples.py
Usage:
  PYTHONPATH=. python3 scripts/generate_synth_examples.py <seed.jsonl> <out.jsonl> --append N

If Gemini client available (modules.ai.gemini_client.call_gemini_generate), it will be used.
Otherwise performs simple deterministic mutations.
"""
from __future__ import annotations
import sys
import json
import random
from pathlib import Path

def load_jsonl(p: Path):
    if not p.exists(): return []
    out=[]
    for L in p.read_text(encoding="utf-8").splitlines():
        if not L.strip(): continue
        out.append(json.loads(L))
    return out

def simple_augment(text: str) -> str:
    # short deterministic augmentations
    variants = [
        lambda s: s,
        lambda s: s + " (proof: observed payload in parameter)",
        lambda s: "Observed: " + s,
        lambda s: s.replace("http", "https"),
        lambda s: s + " -- sample header: User-Agent: test",
    ]
    return random.choice(variants)(text)

def try_gemini_generate(prompt: str):
    try:
        from modules.ai.gemini_client import call_gemini_generate
    except Exception:
        return None
    try:
        return call_gemini_generate(prompt)
    except Exception:
        return None

def main():
    if len(sys.argv) < 4:
        print("Usage: generate_synth_examples.py <seed.jsonl> <out.jsonl> --append N")
        sys.exit(2)
    seed = Path(sys.argv[1])
    out = Path(sys.argv[2])
    args = sys.argv[3:]
    append = 0
    if "--append" in args:
        idx = args.index("--append")
        if idx+1 < len(args):
            append = int(args[idx+1])
    examples = load_jsonl(seed)
    if not examples:
        print("No seed examples found in", seed)
        sys.exit(1)
    generated=[]
    rng = random.Random(42)
    for _ in range(append):
        base = rng.choice(examples)
        text = base["text"]
        label = base["label"]
        # prefer gemini if configured
        prompt = f"Produce a short vuln report fragment similar to: {text}\nLabel:{label}\nReturn only the fragment."
        gen = try_gemini_generate(prompt)
        if gen:
            new_text = gen.strip()
        else:
            new_text = simple_augment(text)
        generated.append({"text": new_text, "label": label})
    # append to out (create file if missing)
    with out.open("a", encoding="utf-8") as fh:
        for g in generated:
            fh.write(json.dumps(g, ensure_ascii=False) + "\n")
    print(f"Appended {len(generated)} examples to {out}")

if __name__ == "__main__":
    main()
