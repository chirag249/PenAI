#!/usr/bin/env python3
"""
scripts/score_model_sample.py
Usage:
  PYTHONPATH=. python3 scripts/score_model_sample.py <report.json> <model_dir>

Will print a CSV-ish table with text snippet, true heuristic label, model prediction (or keyword fallback).
"""
from __future__ import annotations
import sys
import json
import os
from pathlib import Path
from modules.ai.predictor import predict_findings  # uses meta attacher; we will also try direct model

def load_findings(report_path: Path):
    if not report_path.exists():
        print("report not found", report_path); sys.exit(2)
    rpt = json.load(open(report_path, "r", encoding="utf-8"))
    return rpt.get("findings", [])

def try_model_predict(texts, model_dir):
    import os
    try:
        import joblib
        model = joblib.load(os.path.join(model_dir, "ai_model.pkl"))
        vect = joblib.load(os.path.join(model_dir, "ai_vectorizer.pkl"))
        X = vect.transform(texts)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)
            preds = model.classes_[probs.argmax(axis=1)]
            confs = probs.max(axis=1)
            return list(zip(preds, confs))
        preds = model.predict(X)
        return [(p, 1.0) for p in preds]
    except Exception as e:
        return None

def keyword_fallback(texts, model_dir):
    # load ai_keyword_map.json
    km = {}
    try:
        km = json.load(open(os.path.join(model_dir, "ai_keyword_map.json"), "r", encoding="utf-8"))
    except Exception:
        km = {}
    out=[]
    for t in texts:
        scores={}
        for tok, labs in km.items():
            if tok in t.lower():
                for lab,c in labs.items():
                    scores[lab]=scores.get(lab,0)+int(c)
        if scores:
            lab = max(scores.items(), key=lambda x:x[1])[0]
            out.append((lab, float(max(scores.values()))/(sum(scores.values())+1.0)))
        else:
            out.append(("unknown", 0.0))
    return out

def main():
    if len(sys.argv) < 3:
        print("Usage: score_model_sample.py <report.json> <model_dir>")
        sys.exit(2)
    rpt = Path(sys.argv[1])
    model_dir = Path(sys.argv[2])
    findings = load_findings(rpt)
    texts = []
    true_labels = []
    for f in findings:
        txt = " ".join([str(f.get(k,"")) for k in ("evidence","description","type")])[:400]
        texts.append(txt)
        true_labels.append(f.get("meta",{}).get("ai_prediction",{}).get("vuln_type") or f.get("type") or "unknown")
    model_preds = try_model_predict(texts, str(model_dir))
    if model_preds is None:
        model_preds = keyword_fallback(texts, str(model_dir))
    print("idx\ttrue\tpred\tconf\tsnippet")
    for i,(t,p) in enumerate(zip(true_labels, model_preds)):
        pred, conf = p
        snippet = texts[i][:80].replace("\n", " ")
        print(f"{i}\t{t}\t{pred}\t{conf:.2f}\t{snippet}")

if __name__ == "__main__":
    main()
