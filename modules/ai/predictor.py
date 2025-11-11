#!/usr/bin/env python3
# modules/ai/predictor.py
from __future__ import annotations
import os
import json
from typing import List, Dict, Any, Optional

# Default artifact names
MODEL_NAME = "ai_model.pkl"
VECT_NAME  = "ai_vectorizer.pkl"
KEYMAP_NAME = "ai_keyword_map.json"

# -------- path helpers (prefer central dir if provided) --------
def _artifact_path(run_dir: str, name: str) -> str:
    envdir = os.environ.get("PENTEST_AI_MODEL_DIR")
    if envdir:
        p = os.path.join(envdir, name)
        if os.path.isfile(p):
            return p
    return os.path.join(run_dir, "generated", name)

def _model_path(run_dir: str) -> str:
    return _artifact_path(run_dir, MODEL_NAME)

def _vectorizer_path(run_dir: str) -> str:
    return _artifact_path(run_dir, VECT_NAME)

def _keymap_path(run_dir: str) -> str:
    return _artifact_path(run_dir, KEYMAP_NAME)

# -------- loaders --------
def _load_keyword_map(run_dir: str) -> Dict[str, Dict[str, int]]:
    p = _keymap_path(run_dir)
    if not os.path.isfile(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}

def _try_load_pickle(path: str):
    try:
        import joblib  # type: ignore
        return joblib.load(path)
    except Exception:
        try:
            import pickle  # type: ignore
            with open(path, "rb") as fh:
                return pickle.load(fh)
        except Exception:
            return None

def _try_load_model(run_dir: str):
    p = _model_path(run_dir)
    if not os.path.isfile(p):
        return None
    return _try_load_pickle(p)

def _try_load_vectorizer(run_dir: str):
    p = _vectorizer_path(run_dir)
    if not os.path.isfile(p):
        return None
    return _try_load_pickle(p)

# -------- text prep --------
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

# -------- optional Gemini fallback --------
def _try_gemini(text: str) -> Optional[Dict[str, Any]]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None
    mod = None
    try:
        from modules.ai import gemini_client as mod  # type: ignore
    except Exception:
        try:
            from modules.ai import gemini_post as mod  # type: ignore
        except Exception:
            return None

    for fn_name in ("classify_vuln_text", "predict_label", "classify", "analyze_vuln"):
        fn = getattr(mod, fn_name, None)
        if callable(fn):
            try:
                res = fn(text)
                if isinstance(res, tuple) and len(res) >= 2:
                    label = str(res[0])
                    conf = float(res[1]) if res[1] is not None else 0.6
                    expl = (res[2] if len(res) > 2 else "") or "gemini"
                    return {"vuln_type": label, "confidence": conf, "explanation": expl}
                if isinstance(res, dict):
                    label = str(res.get("vuln_type") or res.get("label") or "unknown")
                    conf = float(res.get("confidence") or 0.6)
                    expl = str(res.get("explanation") or "gemini")
                    return {"vuln_type": label, "confidence": conf, "explanation": expl}
            except Exception:
                return None
    return None

# -------- transformer predictor --------
def _try_transformer_predictor(findings: List[Dict[str, Any]], run_dir: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Try to use transformer predictor if available."""
    try:
        from modules.ai.transformer_predictor import predict_findings_with_transformer
        return predict_findings_with_transformer(findings, run_dir, limit)
    except ImportError:
        # Transformer predictor not available, return findings unchanged
        return findings
    except Exception:
        # Error in transformer predictor, return findings unchanged
        return findings

# -------- main --------
def predict_findings(
    findings: List[Dict[str, Any]],
    run_dir: str = ".",
    limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Attach AI prediction to each finding (adds keys:
      - finding['ai'] = {'vuln_type','confidence','explanation'}
      - finding['meta']['ai_prediction'] mirrors the same dict
    Priority:
      1) Transformer model (if available)
      2) Trained model (and optional vectorizer)
      3) Keyword map (ai_keyword_map.json)
      4) Gemini (if API key + helper present)
      5) Heuristics (xss/sqli)
    """
    if not isinstance(findings, list):
        return findings

    # Try transformer predictor first (if available)
    transformer_result = _try_transformer_predictor(findings, run_dir, limit)
    # If transformer predictor was successful, return its result
    if transformer_result != findings:
        return transformer_result

    model = _try_load_model(run_dir)
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

        # 1) model-first (handle both Pipeline and separate vectorizer cases)
        if model is not None:
            try:
                if vectorizer is not None:
                    X = vectorizer.transform([text])
                else:
                    # works if model is a Pipeline or raw-text model
                    X = [text]
                if hasattr(model, "predict_proba"):
                    probs = model.predict_proba(X)[0]
                    classes = list(model.classes_)
                    import numpy as _np  # type: ignore
                    idx = int(_np.argmax(probs))
                    ai = {"vuln_type": str(classes[idx]), "confidence": float(probs[idx]), "explanation": "model.prob"}
                else:
                    pred = model.predict(X)[0]
                    ai = {"vuln_type": str(pred), "confidence": 1.0, "explanation": "model.predict"}
            except Exception:
                ai = {"vuln_type": "unknown", "confidence": 0.0, "explanation": "model-error"}

        # 2) keyword-map if (no model) or (low confidence)
        if (model is None or ai.get("confidence", 0.0) < 0.30) and keymap:
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

        # 3) Gemini fallback (optional)
        if ai.get("confidence", 0.0) < 0.30:
            g = _try_gemini(text)
            if g:
                ai = g

        # 4) heuristics
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
