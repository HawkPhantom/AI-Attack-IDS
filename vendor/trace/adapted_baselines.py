#!/usr/bin/env python3
"""Adapted baseline comparisons for TRACE paper.

1. LLMmap-adapted: Supervised contrastive learning on TF-IDF features + kNN
   (LLMmap uses contrastive learning on response embeddings + kNN for open-set)
2. Palisade-adapted: Binary AI-vs-human detection features applied to multi-class
3. Our method: TF-IDF bigram + LinearSVC

All evaluated on the same 2,028-session combined dataset via 10-fold stratified CV.
"""

import json, warnings, numpy as np, pandas as pd
from pathlib import Path
from collections import defaultdict

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder
from scipy.sparse import issparse

warnings.filterwarnings("ignore")

# ── Data loading ──────────────────────────────────────────────────────────────
FAMILIES = ["claude_opus", "gpt54", "gemini31", "deepseek", "qwen", "kimi", "glm5"]
SCAFFOLDS = ["CC", "PGPT", "ReAct"]
FAMILY_NORM = {
    "claude_opus": "claude_opus", "claude": "claude_opus",
    "gpt54": "gpt54", "gpt-5.4": "gpt54", "gpt": "gpt54",
    "gemini31": "gemini31", "gemini": "gemini31",
    "deepseek": "deepseek", "qwen": "qwen", "kimi": "kimi",
    "glm5": "glm5", "glm": "glm5",
}

def load_sessions(base, subsets):
    sessions = []
    for subset in subsets:
        search = base / subset if (base / subset).exists() else base
        for f in search.rglob("*.json"):
            try:
                d = json.loads(f.read_text(errors="replace"))
                family = FAMILY_NORM.get(d.get("family", "?"), d.get("family", "?"))
                if family not in FAMILIES: continue
                scaffold = d.get("scaffold", "?")
                if scaffold not in SCAFFOLDS: continue
                bash = [e for e in d.get("entries", [])
                        if isinstance(e, dict) and e.get("type") != "plan"
                        and (e.get("command") or "").strip()]
                if len(bash) < 5: continue
                cmds = " ".join((e["command"] or "") for e in bash)
                sessions.append({"family": family, "commands": cmds})
            except:
                pass
    return pd.DataFrame(sessions)

base = Path(r"./data/eval_ready_data")
df = load_sessions(base, ["clean", "dpi"])
print(f"Loaded {len(df)} sessions")
print(f"Per family: {df['family'].value_counts().to_dict()}")

X_text = df["commands"].values
le = LabelEncoder()
y = le.fit_transform(df["family"].values)
n_classes = len(le.classes_)
print(f"Classes: {list(le.classes_)}\n")

# ── TF-IDF features (shared) ─────────────────────────────────────────────────
tfidf = TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                        sublinear_tf=True, max_features=10000)
X_tfidf = tfidf.fit_transform(X_text)


# ── Baseline 1: LLMmap-adapted (Supervised Contrastive + kNN) ────────────────
class ContrastiveEncoder(nn.Module):
    """MLP encoder that maps TF-IDF features to a contrastive embedding space."""
    def __init__(self, input_dim, embed_dim=128):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, embed_dim),
        )

    def forward(self, x):
        z = self.net(x)
        return nn.functional.normalize(z, dim=1)


class SupConLoss(nn.Module):
    """Supervised contrastive loss (Khosla et al., 2020)."""
    def __init__(self, temperature=0.07):
        super().__init__()
        self.temperature = temperature

    def forward(self, features, labels):
        device = features.device
        batch_size = features.shape[0]
        labels = labels.contiguous().view(-1, 1)
        mask = torch.eq(labels, labels.T).float().to(device)

        # Compute similarity
        anchor_dot_contrast = torch.div(
            torch.matmul(features, features.T), self.temperature)
        # For numerical stability
        logits_max, _ = torch.max(anchor_dot_contrast, dim=1, keepdim=True)
        logits = anchor_dot_contrast - logits_max.detach()

        # Mask out self-contrast
        logits_mask = torch.scatter(
            torch.ones_like(mask), 1,
            torch.arange(batch_size).view(-1, 1).to(device), 0)
        mask = mask * logits_mask

        # Compute log_prob
        exp_logits = torch.exp(logits) * logits_mask
        log_prob = logits - torch.log(exp_logits.sum(1, keepdim=True) + 1e-8)

        # Mean of log-likelihood over positive
        mask_pos_pairs = mask.sum(1)
        mask_pos_pairs = torch.clamp(mask_pos_pairs, min=1)
        mean_log_prob_pos = (mask * log_prob).sum(1) / mask_pos_pairs

        loss = -mean_log_prob_pos.mean()
        return loss


def train_contrastive(X_train, y_train, input_dim, embed_dim=128,
                      epochs=50, batch_size=128, lr=1e-3):
    """Train contrastive encoder on training data."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    encoder = ContrastiveEncoder(input_dim, embed_dim).to(device)
    criterion = SupConLoss(temperature=0.07)
    optimizer = optim.Adam(encoder.parameters(), lr=lr, weight_decay=1e-4)

    if issparse(X_train):
        X_train = X_train.toarray()
    X_t = torch.FloatTensor(X_train).to(device)
    y_t = torch.LongTensor(y_train).to(device)

    dataset = TensorDataset(X_t, y_t)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True)

    encoder.train()
    for epoch in range(epochs):
        for batch_x, batch_y in loader:
            z = encoder(batch_x)
            loss = criterion(z, batch_y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

    encoder.eval()
    return encoder, device


def llmmap_adapted_predict(X_train, y_train, X_test, input_dim, k=5):
    """LLMmap-adapted: contrastive embedding + kNN classification."""
    encoder, device = train_contrastive(X_train, y_train, input_dim)

    with torch.no_grad():
        if issparse(X_train):
            X_train = X_train.toarray()
        if issparse(X_test):
            X_test = X_test.toarray()
        z_train = encoder(torch.FloatTensor(X_train).to(device)).cpu().numpy()
        z_test = encoder(torch.FloatTensor(X_test).to(device)).cpu().numpy()

    knn = KNeighborsClassifier(n_neighbors=k)
    knn.fit(z_train, y_train)
    return knn.predict(z_test)


# ── Evaluation ────────────────────────────────────────────────────────────────
skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
input_dim = X_tfidf.shape[1]

results = {
    "TF-IDF + LinearSVC (ours)": {"acc": [], "f1": []},
    "LLMmap-adapted (SupCon + kNN)": {"acc": [], "f1": []},
    "TF-IDF + kNN (no contrastive)": {"acc": [], "f1": []},
}

print("Running 10-fold stratified CV...")
for fold, (train_idx, test_idx) in enumerate(skf.split(X_tfidf, y)):
    print(f"  Fold {fold+1}/10...", end=" ", flush=True)

    X_tr, X_te = X_tfidf[train_idx], X_tfidf[test_idx]
    y_tr, y_te = y[train_idx], y[test_idx]

    # Our method: TF-IDF + LinearSVC
    svc = LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)
    svc.fit(X_tr, y_tr)
    p_svc = svc.predict(X_te)
    results["TF-IDF + LinearSVC (ours)"]["acc"].append(accuracy_score(y_te, p_svc))
    results["TF-IDF + LinearSVC (ours)"]["f1"].append(f1_score(y_te, p_svc, average="macro"))

    # LLMmap-adapted: SupCon + kNN
    p_llmmap = llmmap_adapted_predict(X_tr, y_tr, X_te, input_dim, k=5)
    results["LLMmap-adapted (SupCon + kNN)"]["acc"].append(accuracy_score(y_te, p_llmmap))
    results["LLMmap-adapted (SupCon + kNN)"]["f1"].append(f1_score(y_te, p_llmmap, average="macro"))

    # Ablation: TF-IDF + kNN (to isolate contrastive learning effect)
    knn_plain = KNeighborsClassifier(n_neighbors=5)
    knn_plain.fit(X_tr, y_tr)
    p_knn = knn_plain.predict(X_te)
    results["TF-IDF + kNN (no contrastive)"]["acc"].append(accuracy_score(y_te, p_knn))
    results["TF-IDF + kNN (no contrastive)"]["f1"].append(f1_score(y_te, p_knn, average="macro"))

    print(f"SVC={results['TF-IDF + LinearSVC (ours)']['acc'][-1]:.3f}  "
          f"SupCon={results['LLMmap-adapted (SupCon + kNN)']['acc'][-1]:.3f}  "
          f"kNN={results['TF-IDF + kNN (no contrastive)']['acc'][-1]:.3f}")

# ── Report ────────────────────────────────────────────────────────────────────
print("\n" + "=" * 72)
print("ADAPTED BASELINE COMPARISON (10-fold stratified CV, 2,028 sessions)")
print("=" * 72)
print(f"\n{'Method':<35} {'Accuracy':>12} {'Macro F1':>12}")
print("-" * 62)
for name, vals in results.items():
    acc_m, acc_s = np.mean(vals["acc"]), np.std(vals["acc"])
    f1_m, f1_s = np.mean(vals["f1"]), np.std(vals["f1"])
    print(f"{name:<35} {acc_m:.4f}±{acc_s:.4f}  {f1_m:.4f}±{f1_s:.4f}")

# Save
lines = ["ADAPTED BASELINE COMPARISON", "=" * 50,
         f"Dataset: {len(df)} sessions, {n_classes} classes",
         f"CV: 10-fold stratified", ""]
lines.append(f"{'Method':<35} {'Accuracy':>12} {'Macro F1':>12}")
lines.append("-" * 62)
for name, vals in results.items():
    acc_m, acc_s = np.mean(vals["acc"]), np.std(vals["acc"])
    f1_m, f1_s = np.mean(vals["f1"]), np.std(vals["f1"])
    lines.append(f"{name:<35} {acc_m:.4f}±{acc_s:.4f}  {f1_m:.4f}±{f1_s:.4f}")

lines.append("")
lines.append("LLMmap-adapted: Supervised contrastive loss (Khosla et al. 2020)")
lines.append("  on TF-IDF features -> 128-dim embedding -> 5-NN classifier")
lines.append("  (LLMmap uses contrastive learning on text response embeddings + kNN)")
lines.append("  Adapted by replacing text responses with command-sequence TF-IDF features")

Path("experiment_baselines.txt").write_text("\n".join(lines), encoding="utf-8")
print("\nSaved experiment_baselines.txt")
