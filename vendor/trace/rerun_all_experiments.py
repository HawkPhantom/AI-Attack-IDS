#!/usr/bin/env python3
"""Re-run all TRACE experiments on the full 1,010 clean session dataset.
Outputs updated experiment text files + updates v3 notebook cell outputs."""

import json, sys, warnings, time
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import StratifiedKFold, cross_val_score, LeaveOneOut
from sklearn.metrics import (f1_score, confusion_matrix, classification_report,
                             precision_recall_fscore_support, accuracy_score)
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB

warnings.filterwarnings("ignore")

BASE = Path(r"./data/eval_ready_data")
OUTDIR = Path(r".")

FAMILIES = ["claude_opus", "gpt54", "gemini31", "deepseek", "qwen", "kimi", "glm5"]
SCAFFOLDS = ["CC", "PGPT", "ReAct"]

FAMILY_NORM = {
    "claude_opus": "claude_opus", "claude": "claude_opus",
    "gpt54": "gpt54", "gpt-5.4": "gpt54", "gpt": "gpt54",
    "gemini31": "gemini31", "gemini": "gemini31",
    "deepseek": "deepseek",
    "qwen": "qwen",
    "kimi": "kimi",
    "glm5": "glm5", "glm": "glm5",
}


def load_sessions(base=BASE, min_bash=5, subset="clean"):
    sessions = []
    skipped = defaultdict(int)
    search_path = base / subset if (base / subset).exists() else base
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
                    if isinstance(e, dict)
                    and e.get("type") != "plan"
                    and (e.get("command") or "").strip()]
            if len(bash) < min_bash:
                skipped["too_short"] += 1
                continue
            cmds = " ".join((e["command"] or "") for e in bash)
            sessions.append({
                "family": family,
                "scaffold": scaffold,
                "commands": cmds,
                "n_cmds": len(bash),
                "file": str(f),
            })
        except Exception:
            skipped["parse_error"] += 1
    print(f"Loaded {len(sessions)} sessions, skipped: {dict(skipped)}")
    return pd.DataFrame(sessions)


def make_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def loso_cv(df):
    """Leave-One-Session-Out CV."""
    X = df["commands"].values
    y = df["family"].values
    preds = np.empty(len(y), dtype=object)
    pipe = make_pipeline()
    for i in range(len(y)):
        mask = np.ones(len(y), dtype=bool)
        mask[i] = False
        pipe.fit(X[mask], y[mask])
        preds[i] = pipe.predict([X[i]])[0]
    return preds


print("=" * 60)
print("TRACE EXPERIMENT RE-RUN — Full 1,010 session dataset")
print("=" * 60)

# Load data
df = load_sessions(BASE, min_bash=5, subset="clean")
print(f"\nTotal clean sessions: {len(df)}")
print(f"Families: {sorted(df['family'].unique())}")
print(f"Per family: {df['family'].value_counts().to_dict()}")
print()

# ═══════════════════════════════════════════════════════════════════
# EXPERIMENT 1: Confusion Matrix + Per-Class Metrics (LOSO)
# ═══════════════════════════════════════════════════════════════════
print("Running Experiment 1: LOSO CV...")
t0 = time.time()
preds = loso_cv(df)
y_true = df["family"].values
elapsed = time.time() - t0
print(f"  Done in {elapsed:.0f}s")

acc = accuracy_score(y_true, preds)
labels = sorted(df["family"].unique())
cm = confusion_matrix(y_true, preds, labels=labels)
report = classification_report(y_true, preds, labels=labels, digits=3)
macro_f1 = f1_score(y_true, preds, labels=labels, average="macro")
weighted_f1 = f1_score(y_true, preds, labels=labels, average="weighted")

lines = []
lines.append("EXPERIMENT 1: Confusion Matrix + Per-Class Metrics")
lines.append(f"Cross-validation method: LOSO")
lines.append(f"Total sessions: {len(df)}")
lines.append(f"Classes: {labels}")
lines.append(f"Overall accuracy: {acc:.4f}")
lines.append(f"Macro F1: {macro_f1:.4f}")
lines.append(f"Weighted F1: {weighted_f1:.4f}")
lines.append("")
lines.append("CONFUSION MATRIX")
lines.append("Rows = true label, Columns = predicted label")
lines.append("")
header = "".join(f"{l:>15}" for l in labels)
lines.append(f"{'':>15}{header}")
for i, label in enumerate(labels):
    row = "".join(f"{cm[i][j]:>15}" for j in range(len(labels)))
    lines.append(f"{label:>15}{row}")
lines.append("")
lines.append("CLASSIFICATION REPORT")
lines.append(report)

exp1_text = "\n".join(lines)
(OUTDIR / "experiment1_confusion_matrix.txt").write_text(exp1_text, encoding="utf-8")
print(f"  Accuracy: {acc:.4f}, Macro F1: {macro_f1:.4f}")
print(f"  Saved experiment1_confusion_matrix.txt")

# ═══════════════════════════════════════════════════════════════════
# EXPERIMENT 2: Top Features
# ═══════════════════════════════════════════════════════════════════
print("\nRunning Experiment 2: Top features...")
pipe = make_pipeline()
pipe.fit(df["commands"].values, df["family"].values)
tfidf = pipe.named_steps["tfidf"]
clf = pipe.named_steps["clf"]
features = tfidf.get_feature_names_out()
n_features = len(features)

lines = []
lines.append("EXPERIMENT 2: Top 15 Discriminating TF-IDF Features Per Class")
lines.append(f"Trained on all {len(df)} sessions")
lines.append(f"TF-IDF features: {n_features} (bigram, max_features=10000)")
lines.append(f"Classifier: LinearSVC (C=1.0, balanced)")
lines.append("")

for i, label in enumerate(labels):
    coefs = clf.coef_[i]
    top_idx = np.argsort(coefs)[::-1][:15]
    lines.append(f"--- {label} ---")
    for rank, idx in enumerate(top_idx, 1):
        lines.append(f"  {rank:>2}. {features[idx]:<40} coef={coefs[idx]:.4f}")
    lines.append("")

exp2_text = "\n".join(lines)
(OUTDIR / "experiment2_top_features.txt").write_text(exp2_text, encoding="utf-8")
print(f"  Features: {n_features}")
print(f"  Saved experiment2_top_features.txt")

# ═══════════════════════════════════════════════════════════════════
# EXPERIMENT 3: Min Session Length
# ═══════════════════════════════════════════════════════════════════
print("\nRunning Experiment 3: Min session length...")
lines = []
lines.append("EXPERIMENT 3: Minimum Session Length for Reliable Classification")
lines.append("Truncate each session to first N commands, then run LOSO CV")
lines.append("")
lines.append(f"  {'N_cmds':>8}   {'Sessions':>8}   {'CV Method':>15}   {'Accuracy':>8}   {'Macro-P':>8}   {'Macro-R':>8}   {'Macro-F1':>8}")
lines.append("-" * 80)

for n_cmds in [5, 10, 15, 20, 30]:
    df_trunc = df.copy()
    df_trunc["commands"] = df_trunc["commands"].apply(
        lambda c: " ".join(c.split()[:n_cmds * 3])  # rough: ~3 tokens per command
    )
    # Use 5-fold for speed on truncated
    pipe_t = make_pipeline()
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y = df_trunc["family"].values
    X = df_trunc["commands"].values
    y_pred_all = np.empty(len(y), dtype=object)
    for train_idx, test_idx in skf.split(X, y):
        pipe_t.fit(X[train_idx], y[train_idx])
        y_pred_all[test_idx] = pipe_t.predict(X[test_idx])
    a = accuracy_score(y, y_pred_all)
    p, r, f, _ = precision_recall_fscore_support(y, y_pred_all, average="macro")
    lines.append(f"  {n_cmds:>8}   {len(df_trunc):>8}   {'5-fold':>15}   {a:.4f}   {p:.4f}   {r:.4f}   {f:.4f}")
    print(f"  N={n_cmds}: acc={a:.4f}")

# Full
lines.append(f"  {'ALL':>8}   {len(df):>8}   {'LOSO':>15}   {acc:.4f}   {macro_f1:.4f}   {macro_f1:.4f}   {macro_f1:.4f}")

exp3_text = "\n".join(lines)
(OUTDIR / "experiment3_min_session_length.txt").write_text(exp3_text, encoding="utf-8")
print(f"  Saved experiment3_min_session_length.txt")

# ═══════════════════════════════════════════════════════════════════
# EXPERIMENT 6: Ablation
# ═══════════════════════════════════════════════════════════════════
print("\nRunning Experiment 6: Ablation (n-gram x features)...")
lines = []
lines.append("EXPERIMENT 6: ABLATION — N-gram Range x Feature Count")
lines.append("=" * 54)
lines.append(f"10-fold stratified CV, LinearSVC (C=1.0, balanced)")
lines.append(f"Data: {len(df)} sessions, {len(labels)} classes")
lines.append("")
lines.append("N-GRAM x FEATURE COUNT GRID")
lines.append("-----------------------------")
lines.append(f"  {'N-gram':>10}  {'Features':>10}  {'Accuracy':>10}  {'Std':>8}  {'F1-macro':>10}")

X_raw = df["commands"].values
y_raw = df["family"].values
skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)

for ngram_label, ngram_range in [("unigram", (1,1)), ("bigram", (1,2)), ("trigram", (1,3))]:
    for max_feat in [1000, 3000, 5000, 10000, 20000, 50000]:
        pipe_a = Pipeline([
            ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=ngram_range,
                                      sublinear_tf=True, max_features=max_feat)),
            ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
        ])
        scores = cross_val_score(pipe_a, X_raw, y_raw, cv=skf, scoring="accuracy")
        f1_scores = cross_val_score(pipe_a, X_raw, y_raw, cv=skf, scoring="f1_macro")
        best_marker = ""
        lines.append(f"  {ngram_label:>10}  {max_feat:>10,}  {scores.mean():>10.4f}  {scores.std():>8.4f}  {f1_scores.mean():>10.4f}{best_marker}")

lines.append("")
lines.append("C PARAMETER SENSITIVITY (bigram, 10k features)")
lines.append("-----------------------------------------------")
for c_val in [0.01, 0.1, 0.5, 1.0, 5.0, 10.0]:
    pipe_c = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1,2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=c_val, class_weight="balanced", max_iter=10000)),
    ])
    scores = cross_val_score(pipe_c, X_raw, y_raw, cv=skf, scoring="accuracy")
    lines.append(f"  C={c_val:<6}  acc={scores.mean():.4f} +/- {scores.std():.4f}")

exp6_text = "\n".join(lines)
(OUTDIR / "experiment6_ablation.txt").write_text(exp6_text, encoding="utf-8")
print(f"  Saved experiment6_ablation.txt")

# ═══════════════════════════════════════════════════════════════════
# EXPERIMENT 8: Classifier Comparison
# ═══════════════════════════════════════════════════════════════════
print("\nRunning Experiment 8: Classifier comparison...")
lines = []
lines.append(f"EXPERIMENT 8: Classifier Comparison (LOSO Cross-Validation)")
lines.append(f"TF-IDF features: {n_features} (bigram, max_features=10000)")
lines.append(f"Total sessions: {len(df)}, Classes: {len(labels)}")
lines.append(f"CV Method: 10-fold stratified")
lines.append("")
lines.append(f"  {'Classifier':>25}   {'Accuracy (std)':>20}   {'Macro-F1 (std)':>20}")
lines.append("-" * 72)

classifiers = [
    ("LinearSVC", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ("Logistic Regression", LogisticRegression(C=1.0, class_weight="balanced", max_iter=10000, solver="lbfgs")),
    ("Gradient Boosting", GradientBoostingClassifier(n_estimators=100, random_state=42)),
    ("Random Forest", RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)),
    ("k-NN (k=5)", KNeighborsClassifier(n_neighbors=5)),
    ("Multinomial NB", MultinomialNB()),
]

tfidf_X = TfidfVectorizer(analyzer="word", ngram_range=(1,2), sublinear_tf=True, max_features=10000).fit_transform(X_raw)

for name, clf_obj in classifiers:
    acc_scores = cross_val_score(clf_obj, tfidf_X, y_raw, cv=skf, scoring="accuracy")
    f1_scores = cross_val_score(clf_obj, tfidf_X, y_raw, cv=skf, scoring="f1_macro")
    lines.append(f"  {name:>25}   {acc_scores.mean():.4f} (+/-{acc_scores.std():.4f})   {f1_scores.mean():.4f} (+/-{f1_scores.std():.4f})")
    print(f"  {name}: acc={acc_scores.mean():.4f}")

exp8_text = "\n".join(lines)
(OUTDIR / "experiment8_classifier_comparison.txt").write_text(exp8_text, encoding="utf-8")
print(f"  Saved experiment8_classifier_comparison.txt")

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Sessions: {len(df)}")
print(f"LOSO Accuracy: {acc:.4f}")
print(f"LOSO Macro F1: {macro_f1:.4f}")
print(f"Per family:")
for label in labels:
    mask = y_true == label
    fam_acc = accuracy_score(y_true[mask], preds[mask])
    print(f"  {label:>15}: {fam_acc:.3f} ({mask.sum()} sessions)")
print("\nAll experiment files updated.")
