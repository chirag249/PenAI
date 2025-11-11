#!/usr/bin/env python3
# scripts/train_enhanced_model.py
"""
Comprehensive training script for the enhanced AI model with transformer-based approach.
"""

import argparse
import os
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def main():
    parser = argparse.ArgumentParser(description="Train enhanced AI model for vulnerability classification")
    parser.add_argument("--data-file", default="datasets/enhanced_training_data.jsonl",
                        help="Path to training data file")
    parser.add_argument("--model-dir", default="models",
                        help="Directory to save trained models")
    parser.add_argument("--use-transformer", action="store_true",
                        help="Use transformer-based model (requires transformers library)")
    parser.add_argument("--sample-size", type=int, default=1000,
                        help="Number of samples to use for training (default: 1000)")
    parser.add_argument("--quick-test", action="store_true",
                        help="Run a quick test with minimal data")
    
    args = parser.parse_args()
    
    # Create directories
    Path(args.model_dir).mkdir(parents=True, exist_ok=True)
    Path("datasets").mkdir(parents=True, exist_ok=True)
    
    print("Enhanced AI Model Training Pipeline")
    print("==================================")
    
    # Step 1: Generate training data if it doesn't exist
    if not os.path.exists(args.data_file):
        print(f"\nStep 1: Generating training data...")
        from scripts.generate_enhanced_training_data import main as generate_data
        generate_data()
    else:
        print(f"\nStep 1: Using existing training data at {args.data_file}")
    
    # Step 2: Train the model
    print(f"\nStep 2: Training model...")
    if args.use_transformer:
        print("Using transformer-based model (DistilBERT)")
        try:
            from modules.ai.transformer_trainer import train_transformer_model
            # Load sample data
            examples = []
            with open(args.data_file, 'r') as f:
                for i, line in enumerate(f):
                    if args.quick_test and i >= 100:
                        break
                    if i >= args.sample_size:
                        break
                    import json
                    example = json.loads(line)
                    examples.append((example['text'], example['label']))
            
            print(f"Training on {len(examples)} examples...")
            result = train_transformer_model(args.model_dir, examples, keyword_only=False)
            print(f"Training result: {result}")
        except ImportError as e:
            print(f"Transformer libraries not available: {e}")
            print("Falling back to traditional model...")
            args.use_transformer = False
        except Exception as e:
            print(f"Error training transformer model: {e}")
            print("Falling back to traditional model...")
            args.use_transformer = False
    
    if not args.use_transformer:
        print("Using traditional scikit-learn model")
        try:
            from modules.ai.trainer import train_from_examples
            # Load sample data
            examples = []
            with open(args.data_file, 'r') as f:
                for i, line in enumerate(f):
                    if args.quick_test and i >= 100:
                        break
                    if i >= args.sample_size:
                        break
                    import json
                    example = json.loads(line)
                    examples.append((example['text'], example['label']))
            
            print(f"Training on {len(examples)} examples...")
            result = train_from_examples(args.model_dir, examples, keyword_only=False)
            print(f"Training result: {result}")
        except Exception as e:
            print(f"Error training traditional model: {e}")
    
    print(f"\nModel training complete!")
    print(f"Models saved to: {os.path.join(args.model_dir, 'generated')}")

if __name__ == "__main__":
    main()