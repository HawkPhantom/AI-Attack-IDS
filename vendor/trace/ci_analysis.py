#!/usr/bin/env python3
"""Compute confidence intervals and statistical tests for TRACE paper.
Addresses peer review M2: CI on core CV claims + significance testing."""

import json, warnings
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (f1_score, accuracy_score, confusion_matrix,
                             classification_report)
from sklearn.neighbors import KNeighborsClassifier
from scipy import stats

warnings.filterwarnings("ignore")

BASE = Path(r"./data/eval_ready_data")
FAMILIES = ["claude_opus", "gpt54", "gemini31", "deepseek", "qwen", "kimi", "glm5"]
SCAFFOLDS = ["CC", "PGPT", "ReAct"]
FAMILY_NORM = {
    "claude_opus": "claude_opus", "claude": "claude_opus",
    "gpt54": "gpt54", "gpt-5.4": "gpt54", "gpt": "gpt54",
    "gemini31": "gemini31", "gemini": "gemini31",
    "deepseek": "deepseek", "qwen": "qwen", "kimi": "kimi",
    "glm5": "glm5", "glm": "glm5",
}


def load_sessions(subset="both"):
    sessions = []
    skipped = defaultdict(int)
    subsets = ["clean", "dpi"] if subset == "both" else [subset]
    for sub in subsets:
        search_path = BASE / sub
        if not search_path.exists():
            continue
        for f in search_path.rglob("*.json"):
            try:
                d = json.loads(f.read_text(errors="replace"))
                family = FAMILY_NORM.get(d.get("family", "?"), d.get("family", "?"))
                if family not in FAMILIES:
                    skipped["unknown_family"] += 1
                    continue
                scaffold = d.get("scaffold", "?")
                if scaffold not in SCAFFOLDS:
                    skipped["unknown_scaffold"] += 1
                    continue
                bash = [e for e in d.get("entries", [])
                        if isinstance(e, dict) and e.get("type") != "plan"
                        and (e.get("command") or "").strip()]
                if len(bash) < 5:
                    skipped["too_short"] += 1
                    continue
                cmds = " ".join((e["command"] or "") for e in bash)
                sessions.append({
                    "family": family, "scaffold": scaffold,
                    "commands": cmds, "n_cmds": len(bash), "file": str(f),
                })
            except Exception:
                skipped["parse_error"] += 1
    print(f"Loaded {len(sessions)} sessions ({subset}), skipped: {dict(skipped)}")
    return pd.DataFrame(sessions)


def make_tfidf_svc():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def make_contrastive_knn():
    """Adapted LLMmap baseline: TF-IDF features + contrastive-learned embeddings + kNN.
    Simplified: we use the same TF-IDF features + kNN (the contrastive part
    was already shown in Table 7). For the paired test, we compare TF-IDF+SVC
    vs TF-IDF+kNN fold-by-fold."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", KNeighborsClassifier(n_neighbors=5)),
    ])


print("=" * 70)
print("TRACE CI ANALYSIS — Peer Review M2")
print("=" * 70)

# ═══════════════════════════════════════════════════════════════
# 1. Main result: 5-fold CV on 2,028 sessions with per-fold F1
# ═══════════════════════════════════════════════════════════════
print("\n[1] 5-fold stratified CV on full dataset (clean + DPI)...")
df_all = load_sessions("both")
X = df_all["commands"].values
y = df_all["family"].values
labels = sorted(df_all["family"].unique())

skf5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
fold_f1s_svc = []
fold_accs_svc = []
y_pred_all = np.empty(len(y), dtype=object)

for fold_i, (train_idx, test_idx) in enumerate(skf5.split(X, y)):
    pipe = make_tfidf_svc()
    pipe.fit(X[train_idx], y[train_idx])
    preds = pipe.predict(X[test_idx])
    y_pred_all[test_idx] = preds
    f1 = f1_score(y[test_idx], preds, labels=labels, average="macro")
    acc = accuracy_score(y[test_idx], preds)
    fold_f1s_svc.append(f1)
    fold_accs_svc.append(acc)
    print(f"  Fold {fold_i+1}: F1={f1:.4f}, Acc={acc:.4f}")

mean_f1 = np.mean(fold_f1s_svc)
std_f1 = np.std(fold_f1s_svc, ddof=1)
mean_acc = np.mean(fold_accs_svc)
std_acc = np.std(fold_accs_svc, ddof=1)

# 95% CI using t-distribution (df=4 for 5 folds)
t_val = stats.t.ppf(0.975, df=4)
ci_f1 = t_val * std_f1 / np.sqrt(5)
ci_acc = t_val * std_acc / np.sqrt(5)

print(f"\n  *** 5-fold CV (2,028 sessions) ***")
print(f"  Macro F1: {mean_f1:.4f} ± {std_f1:.4f} (95% CI: [{mean_f1-ci_f1:.4f}, {mean_f1+ci_f1:.4f}])")
print(f"  Accuracy: {mean_acc:.4f} ± {std_acc:.4f} (95% CI: [{mean_acc-ci_acc:.4f}, {mean_acc+ci_acc:.4f}])")

# Full confusion matrix from aggregated predictions
cm = confusion_matrix(y, y_pred_all, labels=labels)
print(f"\n  Confusion matrix (aggregated across folds):")
header = "".join(f"{l:>13}" for l in labels)
print(f"  {'':>13}{header}")
for i, label in enumerate(labels):
    row = "".join(f"{cm[i][j]:>13}" for j in range(len(labels)))
    print(f"  {label:>13}{row}")

# Per-class report
print(f"\n  Per-class report:")
print(classification_report(y, y_pred_all, labels=labels, digits=3))

# ═══════════════════════════════════════════════════════════════
# 2. LLMmap baseline: same folds, paired comparison
# ═══════════════════════════════════════════════════════════════
print("\n[2] LLMmap-adapted baseline (TF-IDF + 5-NN) on same folds...")
fold_f1s_knn = []

for fold_i, (train_idx, test_idx) in enumerate(skf5.split(X, y)):
    pipe = make_contrastive_knn()
    pipe.fit(X[train_idx], y[train_idx])
    preds = pipe.predict(X[test_idx])
    f1 = f1_score(y[test_idx], preds, labels=labels, average="macro")
    fold_f1s_knn.append(f1)
    print(f"  Fold {fold_i+1}: kNN F1={f1:.4f}  (SVC F1={fold_f1s_svc[fold_i]:.4f})")

mean_knn = np.mean(fold_f1s_knn)
std_knn = np.std(fold_f1s_knn, ddof=1)

print(f"\n  kNN Macro F1: {mean_knn:.4f} ± {std_knn:.4f}")
print(f"  SVC Macro F1: {mean_f1:.4f} ± {std_f1:.4f}")
print(f"  Difference:   {mean_f1 - mean_knn:.4f}")

# Paired t-test across folds
diffs = np.array(fold_f1s_svc) - np.array(fold_f1s_knn)
t_stat, p_value = stats.ttest_rel(fold_f1s_svc, fold_f1s_knn)
print(f"\n  Paired t-test: t={t_stat:.3f}, p={p_value:.4f}")
print(f"  Per-fold diffs: {[f'{d:.4f}' for d in diffs]}")
print(f"  Mean diff: {np.mean(diffs):.4f} ± {np.std(diffs, ddof=1):.4f}")
if p_value < 0.05:
    print(f"  => Difference IS statistically significant (p < 0.05)")
else:
    print(f"  => Difference is NOT statistically significant (p >= 0.05)")

# ═══════════════════════════════════════════════════════════════
# 3. Scaffold-LOSO with per-scaffold CI
# ═══════════════════════════════════════════════════════════════
print("\n[3] Scaffold-LOSO...")
for held_out in SCAFFOLDS:
    train_mask = df_all["scaffold"] != held_out
    test_mask = df_all["scaffold"] == held_out
    pipe = make_tfidf_svc()
    pipe.fit(X[train_mask], y[train_mask])
    preds = pipe.predict(X[test_mask])
    f1 = f1_score(y[test_mask], preds, labels=labels, average="macro")
    acc = accuracy_score(y[test_mask], preds)
    n_train = train_mask.sum()
    n_test = test_mask.sum()
    print(f"  Held-out {held_out:>5}: train={n_train}, test={n_test}, "
          f"Acc={acc:.4f}, Macro F1={f1:.4f}")

print("\nDone.")
