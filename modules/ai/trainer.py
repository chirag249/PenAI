# modules/ai/trainer.py
"""
Trainer for vuln-type classifier.

Outputs under <run_dir>/generated/:
  - ai_model.pkl              (sklearn pipeline: TfidfVectorizer + LogisticRegression)
  - ai_vectorizer.pkl         (kept for compatibility; same vectorizer from the pipeline)
  - ai_keyword_map.json       (fallback map; always written)
"""

from __future__ import annotations
import os
import json
from typing import List, Tuple

DEFAULT_MODEL_NAME = "ai_model.pkl"
DEFAULT_VECT_NAME = "ai_vectorizer.pkl"
FALLBACK_MAP = "ai_keyword_map.json"


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _build_keyword_map(examples: List[Tuple[str, str]]) -> dict:
    km = {}
    for text, label in examples:
        toks = set((text or "").lower().split())
        for t in toks:
            d = km.setdefault(t, {})
            d[label] = d.get(label, 0) + 1
    return km


def train_from_examples(run_dir: str, examples: List[Tuple[str, str]], keyword_only: bool = False, use_transformer: bool = False):
    """
    Train a text classifier from (text, label) pairs.

    If use_transformer=True and required libraries are available, trains a transformer model.
    Otherwise, if scikit-learn is available and keyword_only=False, saves a pipeline model:
      - generated/ai_model.pkl
      - generated/ai_vectorizer.pkl
    In ALL cases, also writes:
      - generated/ai_keyword_map.json   (fallback used by predictor when model is missing)
    """
    gen = os.path.join(run_dir, "generated")
    _ensure_dir(gen)

    # Always produce keyword fallback first (so we have something even if training fails)
    keyword_map = _build_keyword_map(examples)
    with open(os.path.join(gen, FALLBACK_MAP), "w", encoding="utf-8") as f:
        json.dump(keyword_map, f, indent=2, ensure_ascii=False)

    if keyword_only:
        return {"status": "trained_fallback_only", "model": os.path.join("generated", FALLBACK_MAP)}

    # Try transformer training if requested
    if use_transformer:
        try:
            from modules.ai.transformer_trainer import train_transformer_model
            return train_transformer_model(run_dir, examples, keyword_only)
        except ImportError:
            # Transformer trainer not available, fall back to sklearn
            pass
        except Exception as e:
            # Transformer training failed, fall back to sklearn
            pass

    # Try sklearn pipeline
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        import joblib

        texts = [t for t, _ in examples]
        labels = [l for _, l in examples]

        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(max_features=2000, ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=1000)),
        ])
        pipe.fit(texts, labels)

        # Save pipeline (predictor expects joblib/pickle loadable object with predict/predict_proba/classes_)
        joblib.dump(pipe, os.path.join(gen, DEFAULT_MODEL_NAME))

        # Also store vectorizer separately for backward compatibility
        vect = pipe.named_steps["tfidf"]
        joblib.dump(vect, os.path.join(gen, DEFAULT_VECT_NAME))

        return {"status": "trained_sklearn", "model": os.path.join("generated", DEFAULT_MODEL_NAME)}
    except Exception as e:
        # We already wrote the keyword map; return fallback status
        return {"status": "trained_fallback", "model": os.path.join("generated", FALLBACK_MAP)}
