# scripts/train_seed.py
#!/usr/bin/env python3
import sys, json, os
from modules.ai.trainer import train_from_examples

def load_jsonl(path):
    ex = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            obj=json.loads(line)
            ex.append((obj.get("text",""), obj.get("label","unknown")))
    return ex

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: PYTHONPATH=. python3 scripts/train_seed.py <train.jsonl> [--keyword-only] [--run-dir runs/local_ai_train]")
        sys.exit(1)
    data = sys.argv[1]
    keyword_only = "--keyword-only" in sys.argv
    run_dir = "runs/local_ai_train"
    for i,a in enumerate(sys.argv):
        if a == "--run-dir" and i+1 < len(sys.argv):
            run_dir = sys.argv[i+1]
    os.makedirs(os.path.join(run_dir, "generated"), exist_ok=True)
    ex = load_jsonl(data)
    res = train_from_examples(run_dir, ex, keyword_only=keyword_only)
    print("train result:", res)
