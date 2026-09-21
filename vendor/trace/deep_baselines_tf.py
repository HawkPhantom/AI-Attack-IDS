#!/usr/bin/env python3
"""Deep learning baselines for TRACE: BiLSTM and 1D-CNN (TensorFlow/Keras).
Tests whether sequential context improves over TF-IDF bag-of-bigrams."""

import json, warnings, os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Force CPU
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

from pathlib import Path
from collections import Counter

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")
tf.random.set_seed(42)
np.random.seed(42)

# ── Load data ──
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

sessions = []
for sub in ["clean", "dpi"]:
    sp = BASE / sub
    if not sp.exists():
        continue
    for f in sp.rglob("*.json"):
        try:
            d = json.loads(f.read_text(errors="replace"))
            fam = FAMILY_NORM.get(d.get("family", "?"), d.get("family", "?"))
            sc = d.get("scaffold", "?")
            if fam not in FAMILIES or sc not in SCAFFOLDS:
                continue
            bash = [e for e in d.get("entries", [])
                    if isinstance(e, dict) and e.get("type") != "plan"
                    and (e.get("command") or "").strip()]
            if len(bash) < 5:
                continue
            cmds = [(e["command"] or "").strip() for e in bash]
            cmd_str = " ".join(cmds)
            sessions.append({
                "family": fam, "scaffold": sc, "commands": cmds, "cmd_str": cmd_str,
            })
        except Exception:
            pass

print(f"Loaded {len(sessions)} sessions")

# Labels
label2idx = {f: i for i, f in enumerate(sorted(FAMILIES))}
X_str = [s["cmd_str"] for s in sessions]
X_seq = [s["commands"] for s in sessions]
y = np.array([label2idx[s["family"]] for s in sessions])
n_classes = len(label2idx)

# ── Build vocabulary for sequence models ──
all_tokens = []
for cmds in X_seq:
    for cmd in cmds:
        all_tokens.extend(cmd.split())

token_counts = Counter(all_tokens)
vocab = {t: i + 2 for i, (t, _) in enumerate(token_counts.most_common(5000))}
PAD_IDX = 0
UNK_IDX = 1
VOCAB_SIZE = len(vocab) + 2
MAX_LEN = 256


def tokenize_session(cmds, max_len=MAX_LEN):
    tokens = []
    for cmd in cmds:
        tokens.extend([vocab.get(t, UNK_IDX) for t in cmd.split()])
    if len(tokens) > max_len:
        tokens = tokens[:max_len]
    else:
        tokens = tokens + [PAD_IDX] * (max_len - len(tokens))
    return tokens


X_tok = np.array([tokenize_session(cmds) for cmds in X_seq], dtype=np.int32)


def build_bilstm(vocab_size, embed_dim=32, hidden_dim=64, n_classes=7):
    inp = keras.Input(shape=(MAX_LEN,), dtype="int32")
    x = layers.Embedding(vocab_size, embed_dim, mask_zero=True)(inp)
    x = layers.SpatialDropout1D(0.3)(x)
    x = layers.Bidirectional(layers.LSTM(hidden_dim, return_sequences=True, dropout=0.2, recurrent_dropout=0.2))(x)
    x = layers.Bidirectional(layers.LSTM(hidden_dim, dropout=0.2, recurrent_dropout=0.2))(x)
    x = layers.Dropout(0.5)(x)
    out = layers.Dense(n_classes, activation="softmax")(x)
    model = keras.Model(inp, out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss="sparse_categorical_crossentropy",
                  metrics=["accuracy"])
    return model


def build_cnn1d(vocab_size, embed_dim=32, n_filters=64, n_classes=7):
    inp = keras.Input(shape=(MAX_LEN,), dtype="int32")
    x = layers.Embedding(vocab_size, embed_dim)(inp)
    x = layers.SpatialDropout1D(0.3)(x)
    # Multi-kernel CNN
    c3 = layers.Conv1D(n_filters, 3, activation="relu", padding="same")(x)
    c3 = layers.GlobalMaxPooling1D()(c3)
    c5 = layers.Conv1D(n_filters, 5, activation="relu", padding="same")(x)
    c5 = layers.GlobalMaxPooling1D()(c5)
    c7 = layers.Conv1D(n_filters, 7, activation="relu", padding="same")(x)
    c7 = layers.GlobalMaxPooling1D()(c7)
    cat = layers.Concatenate()([c3, c5, c7])
    cat = layers.Dropout(0.5)(cat)
    out = layers.Dense(n_classes, activation="softmax")(cat)
    model = keras.Model(inp, out)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss="sparse_categorical_crossentropy",
                  metrics=["accuracy"])
    return model


# ── 5-fold CV ──
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

print("\n" + "=" * 70)
print("DEEP LEARNING BASELINES — 5-fold Stratified CV")
print(f"Sessions: {len(sessions)}, Vocab: {VOCAB_SIZE}, MaxLen: {MAX_LEN}")
print("=" * 70)

results = {}

# 1. TF-IDF + LinearSVC (reference)
print("\n[1] TF-IDF + LinearSVC (reference)...")
fold_f1s = []
for fold_i, (train_idx, test_idx) in enumerate(skf.split(X_str, y)):
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])
    pipe.fit([X_str[i] for i in train_idx], y[train_idx])
    preds = pipe.predict([X_str[i] for i in test_idx])
    f1 = f1_score(y[test_idx], preds, average="macro")
    acc = accuracy_score(y[test_idx], preds)
    fold_f1s.append(f1)
    print(f"  Fold {fold_i+1}: F1={f1:.4f}, Acc={acc:.4f}")
results["TF-IDF+SVC"] = fold_f1s
print(f"  Mean F1: {np.mean(fold_f1s):.4f} +/- {np.std(fold_f1s, ddof=1):.4f}")

# 2. BiLSTM
print("\n[2] BiLSTM (2-layer, bidirectional, hidden=64)...")
fold_f1s = []
for fold_i, (train_idx, test_idx) in enumerate(skf.split(X_tok, y)):
    tf.keras.backend.clear_session()
    model = build_bilstm(VOCAB_SIZE, embed_dim=32, hidden_dim=64, n_classes=n_classes)
    model.fit(X_tok[train_idx], y[train_idx],
              epochs=20, batch_size=32, verbose=0,
              validation_split=0.1,
              callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)])
    preds = model.predict(X_tok[test_idx], verbose=0).argmax(axis=1)
    f1 = f1_score(y[test_idx], preds, average="macro")
    acc = accuracy_score(y[test_idx], preds)
    fold_f1s.append(f1)
    print(f"  Fold {fold_i+1}: F1={f1:.4f}, Acc={acc:.4f}")
results["BiLSTM"] = fold_f1s
print(f"  Mean F1: {np.mean(fold_f1s):.4f} +/- {np.std(fold_f1s, ddof=1):.4f}")

# 3. 1D-CNN
print("\n[3] 1D-CNN (filters=64, kernels=3,5,7)...")
fold_f1s = []
for fold_i, (train_idx, test_idx) in enumerate(skf.split(X_tok, y)):
    tf.keras.backend.clear_session()
    model = build_cnn1d(VOCAB_SIZE, embed_dim=32, n_filters=64, n_classes=n_classes)
    model.fit(X_tok[train_idx], y[train_idx],
              epochs=20, batch_size=32, verbose=0,
              validation_split=0.1,
              callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)])
    preds = model.predict(X_tok[test_idx], verbose=0).argmax(axis=1)
    f1 = f1_score(y[test_idx], preds, average="macro")
    acc = accuracy_score(y[test_idx], preds)
    fold_f1s.append(f1)
    print(f"  Fold {fold_i+1}: F1={f1:.4f}, Acc={acc:.4f}")
results["1D-CNN"] = fold_f1s
print(f"  Mean F1: {np.mean(fold_f1s):.4f} +/- {np.std(fold_f1s, ddof=1):.4f}")

# ── Summary ──
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"{'Method':<25} {'Mean F1':>10} {'Std':>8} {'vs SVC':>10}")
print("-" * 55)

svc_mean = np.mean(results["TF-IDF+SVC"])
for name, folds in results.items():
    mean = np.mean(folds)
    std = np.std(folds, ddof=1)
    diff = mean - svc_mean
    print(f"{name:<25} {mean:>10.4f} {std:>8.4f} {diff:>+10.4f}")

# Paired t-tests
from scipy import stats
print("\nPaired t-tests vs TF-IDF+SVC:")
for name in ["BiLSTM", "1D-CNN"]:
    t, p = stats.ttest_rel(results["TF-IDF+SVC"], results[name])
    print(f"  {name}: t={t:.3f}, p={p:.4f} {'*' if p < 0.05 else 'n.s.'}")

# ── Scaffold-LOSO for deep models ──
print("\n" + "=" * 70)
print("SCAFFOLD-LOSO (deep models)")
print("=" * 70)

scaffolds_arr = np.array([s["scaffold"] for s in sessions])

for held_out in SCAFFOLDS:
    train_mask = scaffolds_arr != held_out
    test_mask = scaffolds_arr == held_out
    train_idx = np.where(train_mask)[0]
    test_idx = np.where(test_mask)[0]

    # BiLSTM
    tf.keras.backend.clear_session()
    model = build_bilstm(VOCAB_SIZE, n_classes=n_classes)
    model.fit(X_tok[train_idx], y[train_idx], epochs=20, batch_size=32, verbose=0,
              validation_split=0.1,
              callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)])
    preds_lstm = model.predict(X_tok[test_idx], verbose=0).argmax(axis=1)
    f1_lstm = f1_score(y[test_idx], preds_lstm, average="macro")

    # 1D-CNN
    tf.keras.backend.clear_session()
    model = build_cnn1d(VOCAB_SIZE, n_classes=n_classes)
    model.fit(X_tok[train_idx], y[train_idx], epochs=20, batch_size=32, verbose=0,
              validation_split=0.1,
              callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)])
    preds_cnn = model.predict(X_tok[test_idx], verbose=0).argmax(axis=1)
    f1_cnn = f1_score(y[test_idx], preds_cnn, average="macro")

    # TF-IDF+SVC
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])
    pipe.fit([X_str[i] for i in train_idx], y[train_idx])
    preds_svc = pipe.predict([X_str[i] for i in test_idx])
    f1_svc = f1_score(y[test_idx], preds_svc, average="macro")

    print(f"  Held-out {held_out:>5}: SVC={f1_svc:.3f}  BiLSTM={f1_lstm:.3f}  CNN={f1_cnn:.3f}")

print("\nDone.")
