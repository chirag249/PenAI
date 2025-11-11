# modules/ai/transformer_predictor.py
"""
Transformer-based predictor for vuln-type classification using DistilBERT.
"""

from __future__ import annotations
import os
import json
from typing import List, Dict, Any, Optional

# Default artifact names for transformer model
TRANSFORMER_MODEL_NAME = "ai_model_transformer.pkl"
TOKENIZER_NAME = "ai_tokenizer.pkl"
LABEL_ENCODER_NAME = "label_encoder.pkl"

def _artifact_path(run_dir: str, name: str) -> str:
    envdir = os.environ.get("PENTEST_AI_MODEL_DIR")
    if envdir:
        p = os.path.join(envdir, name)
        if os.path.isfile(p):
            return p
    return os.path.join(run_dir, "generated", name)

def _transformer_model_path(run_dir: str) -> str:
    return _artifact_path(run_dir, TRANSFORMER_MODEL_NAME)

def _tokenizer_path(run_dir: str) -> str:
    return _artifact_path(run_dir, TOKENIZER_NAME)

def _label_encoder_path(run_dir: str) -> str:
    return _artifact_path(run_dir, LABEL_ENCODER_NAME)

def _try_load_pickle(path: str):
    try:
        import joblib
        return joblib.load(path)
    except ImportError:
        try:
            import pickle
            with open(path, "rb") as fh:
                return pickle.load(fh)
        except Exception:
            return None
    except Exception:
        return None

def _try_load_transformer_model(run_dir: str):
    p = _transformer_model_path(run_dir)
    if not os.path.isfile(p):
        return None
    return _try_load_pickle(p)

def _try_load_tokenizer(run_dir: str):
    p = _tokenizer_path(run_dir)
    if not os.path.isfile(p):
        return None
    return _try_load_pickle(p)

def _try_load_label_encoder(run_dir: str):
    p = _label_encoder_path(run_dir)
    if not os.path.isfile(p):
        return None
    return _try_load_pickle(p)

def _safe_text_from_finding(f: Dict[str, Any]) -> str:
    parts: List[str] = []
    for k in ("evidence", "description", "request", "response", "raw", "used_payload", "parameter"):
        v = f.get(k)
        if isinstance(v, str) and v.strip():
            parts.append(v.strip())
        elif isinstance(v, dict):
            for val in v.values():
                if isinstance(val, str) and val.strip():
                    parts.append(val.strip())
    parts.append(str(f.get("type", "") or ""))
    if f.get("target"):
        parts.append(str(f["target"]))
    return " ".join(parts).lower()[:10000]

def predict_findings_with_transformer(
    findings: List[Dict[str, Any]],
    run_dir: str = ".",
    limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Attach AI prediction to each finding using transformer model (adds keys:
      - finding['ai'] = {'vuln_type','confidence','explanation'}
      - finding['meta']['ai_prediction'] mirrors the same dict
    Priority:
      1) Transformer model (and tokenizer + label encoder)
      2) Traditional model (and optional vectorizer)
      3) Keyword map (ai_keyword_map.json)
      4) Gemini (if API key + helper present)
      5) Heuristics (xss/sqli)
    """
    if not isinstance(findings, list):
        return findings

    # Try to load transformer components
    transformer_model = _try_load_transformer_model(run_dir)
    tokenizer = _try_load_tokenizer(run_dir)
    label_encoder = _try_load_label_encoder(run_dir)
    
    # Load fallback components
    from modules.ai.predictor import _try_load_model, _try_load_vectorizer, _load_keyword_map, _try_gemini
    traditional_model = _try_load_model(run_dir)
    vectorizer = _try_load_vectorizer(run_dir)
    keymap = _load_keyword_map(run_dir)

    n = 0
    for f in findings:
        if limit is not None and n >= limit:
            break
        if not isinstance(f, dict):
            n += 1
            continue

        text = _safe_text_from_finding(f)
        ai: Dict[str, Any] = {"vuln_type": "unknown", "confidence": 0.0, "explanation": "no-model"}

        # 1) Transformer model-first
        if transformer_model is not None and tokenizer is not None and label_encoder is not None:
            try:
                # Import required libraries (with error handling)
                try:
                    import torch
                    import numpy as np
                except ImportError as e:
                    ai = {"vuln_type": "unknown", "confidence": 0.0, "explanation": f"transformer-error: Required libraries not installed: {str(e)}"}
                else:
                    # Tokenize text
                    encodings = tokenizer(
                        text,
                        truncation=True,
                        padding=True,
                        max_length=512,
                        return_tensors="pt"
                    )
                    
                    # Get prediction
                    with torch.no_grad():
                        outputs = transformer_model(**encodings)
                        predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
                        confidence, predicted = torch.max(predictions, dim=1)
                        
                        # Convert prediction back to label
                        predicted_label = label_encoder.inverse_transform([predicted.item()])[0]
                        ai = {
                            "vuln_type": str(predicted_label),
                            "confidence": float(confidence.item()),
                            "explanation": "transformer-model"
                        }
            except Exception as e:
                ai = {"vuln_type": "unknown", "confidence": 0.0, "explanation": f"transformer-error: {str(e)}"}

        # 2) Traditional model if transformer failed or low confidence
        if (transformer_model is None or ai.get("confidence", 0.0) < 0.30) and traditional_model is not None:
            try:
                if vectorizer is not None:
                    X = vectorizer.transform([text])
                else:
                    # works if model is a Pipeline or raw-text model
                    X = [text]
                if hasattr(traditional_model, "predict_proba"):
                    probs = traditional_model.predict_proba(X)[0]
                    classes = list(traditional_model.classes_)
                    import numpy as _np
                    idx = int(_np.argmax(probs))
                    ai = {"vuln_type": str(classes[idx]), "confidence": float(probs[idx]), "explanation": "model.prob"}
                else:
                    pred = traditional_model.predict(X)[0]
                    ai = {"vuln_type": str(pred), "confidence": 1.0, "explanation": "model.predict"}
            except Exception:
                ai = {"vuln_type": "unknown", "confidence": 0.0, "explanation": "model-error"}

        # 3) keyword-map if (no model) or (low confidence)
        if (traditional_model is None or ai.get("confidence", 0.0) < 0.30) and keymap:
            scores: Dict[str, int] = {}
            txt = text
            for token, labcounts in keymap.items():
                if token and token in txt:
                    for lab, cnt in labcounts.items():
                        scores[lab] = scores.get(lab, 0) + int(cnt)
            if scores:
                best_lab, best_score = max(scores.items(), key=lambda x: x[1])
                total = max(sum(scores.values()), 1)
                ai = {"vuln_type": best_lab, "confidence": float(best_score) / float(total), "explanation": "keyword-map"}

        # 4) Gemini fallback (optional)
        if ai.get("confidence", 0.0) < 0.30:
            g = _try_gemini(text)
            if g:
                ai = g

        # 5) heuristics
        if ai.get("vuln_type") == "unknown":
            if "xss" in text or "cross-site" in text:
                ai = {"vuln_type": "xss", "confidence": 0.5, "explanation": "heuristic"}
            elif "sql" in text or "sql injection" in text:
                ai = {"vuln_type": "sqli", "confidence": 0.5, "explanation": "heuristic"}

        # attach
        f["ai"] = ai
        if "meta" not in f or not isinstance(f.get("meta"), dict):
            f["meta"] = f.get("meta", {})
        f["meta"]["ai_prediction"] = ai

        n += 1

    return findings