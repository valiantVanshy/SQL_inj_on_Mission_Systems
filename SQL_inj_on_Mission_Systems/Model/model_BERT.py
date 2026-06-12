from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

MODEL_NAME  = "distilbert-base-uncased"
NUM_LABELS  = 2
OUTPUT_DIR  = "model_output"
LABEL_NAMES = {0: "Safe", 1: "SQL Injection Attack"}


def build_model():

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=NUM_LABELS,
    )
    total_params = sum(p.numel() for p in model.parameters()) / 1e6
    trainable    = sum(p.numel() for p in model.parameters() if p.requires_grad) / 1e6
    print(f"[Model] BERT loaded | Total params: {total_params:.1f}M | Trainable: {trainable:.1f}M")
    return model


def load_saved_model(model_dir: str = OUTPUT_DIR):
    """Load a previously fine-tuned model from disk."""
    model     = AutoModelForSequenceClassification.from_pretrained(model_dir)
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model.eval()
    print(f"[Model] Loaded saved model from '{model_dir}'")
    return model, tokenizer


def count_parameters(model) -> dict:
    total     = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return {"total": total, "trainable": trainable, "frozen": total - trainable}


if __name__ == "__main__":
    model = build_model()
    params = count_parameters(model)
    print(f"[Model] Parameters — Total: {params['total']:,} | Trainable: {params['trainable']:,}")
