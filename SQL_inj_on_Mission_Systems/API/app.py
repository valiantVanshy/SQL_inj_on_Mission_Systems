import time, sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

app = FastAPI(
    title="Satellite Mission Control — SQL Injection Detector",
    description="Fine-tuned DistilBERT model protecting satellite databases from SQL injection attacks.",
    version="1.0.0",
)

MODEL_DIR  = "model_output"
MAX_LENGTH = 128
LABELS     = {0: "SAFE", 1: "SQL INJECTION ATTACK"}

print("[API] Loading model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model     = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()
print("[API] Ready.")


class QueryRequest(BaseModel):
    query: str

class PredictionResponse(BaseModel):
    query: str
    label: int
    verdict: str
    confidence: float
    latency_ms: float


def predict(query: str) -> dict:
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


@app.get("/", tags=["Health"])
def root():
    return {"status": "online", "model": "distilbert-sql-injection-detector"}

@app.post("/predict", response_model=PredictionResponse, tags=["Detection"])
def predict_query(req: QueryRequest):
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    t0 = time.time()
    r  = predict(req.query)
    return PredictionResponse(
        query=r["query"],
        label=r["label"],
        verdict=r["verdict"],
        confidence=r["confidence"],
        latency_ms=round((time.time()-t0)*1000, 2)
    )

@app.post("/predict/batch", tags=["Detection"])
def predict_batch(queries: List[str]):
    results = [predict(q) for q in queries[:100]]
    attacks = sum(1 for r in results if r["label"] == 1)
    return {"total": len(results), "attacks_detected": attacks, "predictions": results}