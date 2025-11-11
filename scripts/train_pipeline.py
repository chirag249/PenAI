#!/usr/bin/env python3
# scripts/train_pipeline.py
from __future__ import annotations
import argparse
import yaml
import os
import json
import random
from typing import List, Tuple
from modules.ai.trainer import train_from_examples
from pathlib import Path

def read_jsonl(path: str, text_field="text", label_field="label"):
    examples = []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    for L in p.read_text(encoding="utf-8").splitlines():
        if not L.strip():
            continue
        try:
            j = json.loads(L)
        except Exception:
            continue
        t = j.get(text_field) or j.get("evidence") or j.get("text") or ""
        l = j.get(label_field) or j.get("label") or j.get("vuln_type") or "unknown"
        if t and l:
            examples.append((str(t), str(l)))
    return examples

def augment_examples(examples: List[Tuple[str,str]], replicate:int=1, shuffle_tokens:bool=False):
    out = []
    for text,label in examples:
        out.append((text, label))
        for i in range(replicate-1):
            t = text
            if shuffle_tokens:
                toks = t.split()
                if len(toks) > 3:
                    random.shuffle(toks)
                    t = " ".join(toks)
            out.append((t, label))
    random.shuffle(out)
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config/train.yaml")
    p.add_argument("--dataset", default=None)
    p.add_argument("--model-dir", default=None, help="Override PENTEST_AI_MODEL_DIR")
    p.add_argument("--use-transformer", action="store_true", help="Use transformer-based model instead of traditional sklearn")
    p.add_argument("--keyword-only", action="store_true", help="Only generate keyword map, skip model training")
    args = p.parse_args()

    cfgpath = args.config
    cfg = {}
    if os.path.exists(cfgpath):
        with open(cfgpath, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}

    dataset_cfg = cfg.get("dataset", {})
    dataset_path = args.dataset or dataset_cfg.get("path") or "datasets/train.jsonl"
    text_field = dataset_cfg.get("text_field", "text")
    label_field = dataset_cfg.get("label_field", "label")

    aug_cfg = cfg.get("augmentation", {})
    replicate = int(aug_cfg.get("replicate", 1))
    shuffle_tokens = bool(aug_cfg.get("shuffle_tokens", False))

    print("Loading dataset:", dataset_path)
    examples = read_jsonl(dataset_path, text_field=text_field, label_field=label_field)
    if not examples:
        raise SystemExit("No examples loaded; please provide dataset file in jsonl format.")

    if replicate > 1 or shuffle_tokens:
        examples = augment_examples(examples, replicate=replicate, shuffle_tokens=shuffle_tokens)
    print("Examples after augmentation:", len(examples))

    model_dir = args.model_dir or os.getenv("PENTEST_AI_MODEL_DIR") or os.path.expanduser("~/.pentest_ai/models")
    os.makedirs(model_dir, exist_ok=True)

    # call trainer
    # call trainer
    # call trainer (legacy signature: train_from_examples(run_dir, examples))
    run_dir = os.path.dirname(model_dir.rstrip("/")) if model_dir.endswith("/generated") else model_dir
    res = train_from_examples(run_dir, examples, keyword_only=args.keyword_only, use_transformer=args.use_transformer)
    print("train result:", res)
    print("model saved to:", os.path.join(run_dir, "generated"))


if __name__ == "__main__":
    main()

