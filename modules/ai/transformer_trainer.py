# modules/ai/transformer_trainer.py
"""
Transformer-based trainer for vuln-type classifier using DistilBERT.

Outputs under <run_dir>/generated/:
  - ai_model_transformer.pkl     (transformer model)
  - ai_tokenizer.pkl             (tokenizer)
  - ai_keyword_map.json          (fallback map; always written)
"""

from __future__ import annotations
import os
import json
from typing import List, Tuple

DEFAULT_MODEL_NAME = "ai_model_transformer.pkl"
DEFAULT_TOKENIZER_NAME = "ai_tokenizer.pkl"
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

def train_transformer_model(run_dir: str, examples: List[Tuple[str, str]], keyword_only: bool = False):
    """
    Train a transformer-based text classifier from (text, label) pairs.
    
    This function requires transformers and torch libraries to be installed.
    If not available, it will fall back to the keyword map approach.
    
    Outputs:
      - generated/ai_model_transformer.pkl    (transformer model)
      - generated/ai_tokenizer.pkl            (tokenizer)
      - generated/ai_keyword_map.json         (fallback used by predictor when model is missing)
    """
    gen = os.path.join(run_dir, "generated")
    _ensure_dir(gen)
    
    # Always produce keyword fallback first (so we have something even if transformer training fails)
    keyword_map = _build_keyword_map(examples)
    with open(os.path.join(gen, FALLBACK_MAP), "w", encoding="utf-8") as f:
        json.dump(keyword_map, f, indent=2, ensure_ascii=False)
    
    if keyword_only:
        return {"status": "trained_fallback_only", "model": os.path.join("generated", FALLBACK_MAP)}
    
    # Try transformer-based training
    try:
        # Import required libraries (with error handling)
        try:
            import torch
            from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
            from transformers import Trainer, TrainingArguments
            from sklearn.preprocessing import LabelEncoder
            import joblib
            import numpy as np
        except ImportError as e:
            # If required libraries are not available, fall back to keyword map
            return {
                "status": "trained_fallback", 
                "model": os.path.join("generated", FALLBACK_MAP),
                "error": f"Required libraries not installed: {str(e)}"
            }
        
        # Prepare data
        texts = [t for t, _ in examples]
        labels = [l for _, l in examples]
        
        # Encode labels
        label_encoder = LabelEncoder()
        encoded_labels = label_encoder.fit_transform(labels)
        num_labels = len(label_encoder.classes_)
        
        # Log the vulnerability types found
        print(f"Training model with {num_labels} vulnerability types: {list(label_encoder.classes_)}")
        
        # Initialize tokenizer and model
        tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased', 
                                                                   num_labels=num_labels)
        
        # Tokenize texts
        encodings = tokenizer(texts, truncation=True, padding=True, max_length=512)
        
        # Create dataset class
        class VulnDataset(torch.utils.data.Dataset):
            def __init__(self, encodings, labels):
                self.encodings = encodings
                self.labels = labels

            def __getitem__(self, idx):
                item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
                item['labels'] = torch.tensor(self.labels[idx])
                return item

            def __len__(self):
                return len(self.labels)
        
        # Create dataset
        dataset = VulnDataset(encodings, encoded_labels)
        
        # Define training arguments
        training_args = TrainingArguments(
            output_dir=os.path.join(gen, 'tmp_trainer'),
            num_train_epochs=3,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir=os.path.join(gen, 'logs'),
            save_strategy="no",  # Don't save checkpoints, we'll save the final model
        )
        
        # Create trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=dataset,
            tokenizer=tokenizer,
        )
        
        # Train model
        trainer.train()
        
        # Save model and tokenizer
        model.save_pretrained(os.path.join(gen, "transformer_model"))
        tokenizer.save_pretrained(os.path.join(gen, "transformer_tokenizer"))
        
        # Save label encoder for prediction
        joblib.dump(label_encoder, os.path.join(gen, "label_encoder.pkl"))
        
        # Also save simplified versions for compatibility
        joblib.dump(model, os.path.join(gen, DEFAULT_MODEL_NAME))
        joblib.dump(tokenizer, os.path.join(gen, DEFAULT_TOKENIZER_NAME))
        
        return {
            "status": "trained_transformer", 
            "model": os.path.join("generated", DEFAULT_MODEL_NAME),
            "classes": label_encoder.classes_.tolist()
        }
    except Exception as e:
        # We already wrote the keyword map; return fallback status
        return {
            "status": "trained_fallback", 
            "model": os.path.join("generated", FALLBACK_MAP),
            "error": str(e)
        }