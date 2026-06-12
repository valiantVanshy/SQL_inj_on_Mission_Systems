import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_DIR  = "model_output"
MAX_LENGTH = 128
LABELS     = {0: "SAFE", 1: "SQL INJECTION ATTACK"}

def load_model():
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model     = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.eval()
    return model, tokenizer

def predict(query, model, tokenizer):
    inputs = tokenizer(
        query.lower().strip(),
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH,
    )
    with torch.no_grad():
        logits = model(**inputs).logits
    probs      = torch.softmax(logits, dim=-1).squeeze()
    label      = torch.argmax(probs).item()
    confidence = round(probs[label].item() * 100, 2)
    return {"query": query, "label": label, "verdict": LABELS[label], "confidence": confidence}

if __name__ == "__main__":
    print("Loading model...")
    model, tokenizer = load_model()

    test_queries = [
        "SELECT * FROM missions WHERE id = 42",
        "SELECT telemetry FROM satellites WHERE sat_id = 7",
        "UPDATE orbit_params SET altitude = 550 WHERE id = 3",
        "' OR '1'='1",
        "SELECT * FROM operators WHERE username = 'admin' --",
        "1; DROP TABLE satellites; --",
        "' UNION SELECT username, password FROM operators --",
        "'; EXEC xp_cmdshell('whoami') --",
    ]

    print("\n" + "="*55)
    print("  SATELLITE MISSION CONTROL - SQL INJECTION DETECTOR")
    print("="*55)

    for q in test_queries:
        r = predict(q, model, tokenizer)
        icon = "  [SAFE]  " if r["label"] == 0 else "[ATTACK]"
        print(f"\n{icon}  {q[:60]}")
        print(f"           Confidence: {r['confidence']}%")
    print("\n" + "="*55)