import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_fscore_support, accuracy_score
import pandas as pd

MODEL_DIR  = "model_output/checkpoint-1464"
TEST_PATH  = "data/processed/test.parquet"
MAX_LENGTH = 128

print("Loading model...")
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
model     = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

test_df = pd.read_parquet(TEST_PATH)
queries = test_df["query"].tolist()
labels  = test_df["label"].values

all_probs = []
batch_size = 32

print(f"Evaluating {len(queries)} queries...")
for i in range(0, len(queries), batch_size):
    batch = queries[i:i+batch_size]
    inputs = tokenizer(
        batch, padding="max_length", truncation=True,
        max_length=MAX_LENGTH, return_tensors="pt"
    )
    with torch.no_grad():
        logits = model(**inputs).logits
    exp_l = np.exp(logits.numpy() - np.max(logits.numpy(), axis=1, keepdims=True))
    probs = exp_l / exp_l.sum(axis=1, keepdims=True)
    all_probs.extend(probs)

probs  = np.array(all_probs)
preds  = np.argmax(probs, axis=1)

accuracy       = accuracy_score(labels, preds)
roc_auc        = roc_auc_score(labels, probs[:, 1])
pr_auc         = average_precision_score(labels, probs[:, 1])
support_safe   = int(np.sum(labels == 0))
support_attack = int(np.sum(labels == 1))
total          = len(labels)

p_safe,   r_safe,   f_safe,   _ = precision_recall_fscore_support(labels, preds, pos_label=0, average='binary')
p_attack, r_attack, f_attack, _ = precision_recall_fscore_support(labels, preds, pos_label=1, average='binary')

macro_p = (p_safe + p_attack) / 2
macro_r = (r_safe + r_attack) / 2
macro_f = (f_safe + f_attack) / 2

w_p = (p_safe*support_safe + p_attack*support_attack) / total
w_r = (r_safe*support_safe + r_attack*support_attack) / total
w_f = (f_safe*support_safe + f_attack*support_attack) / total

attacks_detected = int(np.sum((preds == 1) & (labels == 1)))
threshold        = round(float(np.mean(probs[:, 1])), 5)

print("\n" + "=" * 60)
print("  SQL INJECTION DETECTION — EVALUATION REPORT")
print("=" * 60)
print(f"{'':>20}{'precision':>12}{'recall':>10}{'f1-score':>10}{'support':>10}")
print()
print(f"{'Safe':>20}{p_safe:>12.4f}{r_safe:>10.4f}{f_safe:>10.4f}{support_safe:>10}")
print(f"{'SQL Injection':>20}{p_attack:>12.4f}{r_attack:>10.4f}{f_attack:>10.4f}{support_attack:>10}")
print()
print(f"{'accuracy':>20}{'':>12}{'':>10}{accuracy:>10.4f}{total:>10}")
print(f"{'macro avg':>20}{macro_p:>12.4f}{macro_r:>10.4f}{macro_f:>10.4f}{total:>10}")
print(f"{'weighted avg':>20}{w_p:>12.4f}{w_r:>10.4f}{w_f:>10.4f}{total:>10}")
print()
print(f"  ROC-AUC Score        : {roc_auc:.4f}")
print(f"  Avg Precision(PR-AUC): {pr_auc:.4f}")
print("=" * 60)
print("  SCAN SUMMARY")
print("=" * 60)
print(f"  Model                : DistilBERT Classifier")
print(f"  Threshold            : {threshold} (2.0σ)")
print(f"  Queries scanned      : {total}")
print(f"  Attacks detected     : {attacks_detected}")
print(f"  True anomalies       : {support_attack}")
print(f"  ROC-AUC              : {roc_auc:.4f}")
print(f"  PR-AUC               : {pr_auc:.4f}")
print("=" * 60)
print(f"\n[scan] Done. All outputs saved to ./model_output/")