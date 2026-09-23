#!/usr/bin/env python3
"""Hat H, graph variant: a GNN over the command-transition graph.

Motivation. The TF-IDF + LinearSVC detector generalizes to unseen model
families (leave-one-model-out recall 0.76-1.00), but its weakest point is
gemma3 held-out at 0.76. TF-IDF keys on specific command tokens, so an unseen
model that uses different tokens is harder to place. This GNN instead reads the
*structure* of the session:

  - each session -> a directed command-transition graph
    node   = a distinct binary used in the session
    edge   = an observed transition cmd_i -> cmd_{i+1}, weight = count
  - node features are BEHAVIORAL CATEGORIES, not the command name
    (state-check / enumerate / network / privilege / process / package / other)
    plus structural degree/frequency/self-loop signals.

Because nodes carry behavioral category rather than identity, the model learns
the reconnaissance *topology* (e.g. a state-check hub re-queried every step),
which should transfer to models whose exact commands were never seen. The whole
point is to test whether that lifts the 0.76 floor.

Evaluated under the SAME leave-one-model-out protocol as ids_model_generalization.py
(held-out AI model recall), with the LinearSVC baseline reported side by side.
The SVC-only pipeline is the ablation.
"""
from __future__ import annotations
import json, re, random, sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline

SEED = 42
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)

# ---- behavioral categories (command-name-agnostic node features) ------------
CATS = ["state", "enum", "network", "privilege", "process", "package", "other"]
CAT_MAP = {
    "state": {"pwd", "whoami", "id", "uname", "hostname", "w", "who", "groups", "tty", "logname"},
    "enum": {"ls", "find", "cat", "less", "more", "head", "tail", "stat", "file",
             "tree", "dir", "grep", "awk", "sed", "wc", "readlink", "realpath", "locate"},
    "network": {"ssh", "scp", "sftp", "nmap", "ping", "nc", "ncat", "netstat", "ss",
                "ip", "ifconfig", "route", "arp", "telnet", "ftp", "curl", "wget",
                "traceroute", "host", "dig", "nslookup", "masscan", "hping3"},
    "privilege": {"sudo", "su", "chmod", "chown", "passwd", "usermod", "useradd",
                  "chattr", "setcap", "getcap"},
    "process": {"ps", "top", "htop", "kill", "pkill", "systemctl", "service",
                "crontab", "jobs", "nohup", "kill"},
    "package": {"apt", "apt-get", "dpkg", "yum", "rpm", "pip", "pip3", "snap", "dnf"},
}
BIN2CAT = {b: c for c, s in CAT_MAP.items() for b in s}


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def cat_of(binary):
    return BIN2CAT.get(binary, "other")


# ---- data loading (shared loader; empty-container AI + frontier + MUNI) ------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ids_data import load_ai, load_human_malicious  # noqa: E402


def load():
    # empty-container AI (incl. Gemini frontier + scaled grid_v2), no evasion
    rows = [{"cmds": r["cmds"], "model": r["model"], "origin": "ai"}
            for r in load_ai(envs=("empty",), include_evasion=False)]
    rows += [{"cmds": r["cmds"], "model": "human", "origin": "human"}
             for r in load_human_malicious()]
    return rows


def bootstrap_ci(indicators, B=3000, seed=SEED):
    a = np.asarray(indicators, dtype=float)
    if len(a) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    return (float(np.percentile(a[rng.integers(0, len(a), (B, len(a)))].mean(1), 2.5)),
            float(np.percentile(a[rng.integers(0, len(a), (B, len(a)))].mean(1), 97.5)))


# ---- graph construction -----------------------------------------------------
def to_graph(cmds, cap=40):
    seq = [head(c) for c in cmds[:cap] if head(c)]
    if len(seq) < 2:
        return None
    nodes = sorted(set(seq))
    idx = {b: i for i, b in enumerate(nodes)}
    N = len(nodes)
    A = np.zeros((N, N), dtype=np.float32)
    for a, b in zip(seq[:-1], seq[1:]):
        A[idx[a], idx[b]] += 1.0
    # per-binary stats
    freq = Counter(seq)
    args_ratio = {}
    for c in cmds[:cap]:
        b = head(c)
        if not b:
            continue
        args_ratio.setdefault(b, []).append(1.0 if len(c.split()) > 1 else 0.0)
    X = np.zeros((N, len(CATS) + 5), dtype=np.float32)
    outdeg = A.sum(1); indeg = A.sum(0)
    mx = max(outdeg.max(), indeg.max(), 1.0)
    for b, i in idx.items():
        X[i, CATS.index(cat_of(b))] = 1.0                       # behavioral category
        X[i, len(CATS) + 0] = freq[b] / len(seq)                # usage frequency
        X[i, len(CATS) + 1] = outdeg[i] / mx                    # out-degree
        X[i, len(CATS) + 2] = indeg[i] / mx                     # in-degree
        X[i, len(CATS) + 3] = 1.0 if A[i, i] > 0 else 0.0       # self-loop (repeat)
        X[i, len(CATS) + 4] = float(np.mean(args_ratio.get(b, [0.0])))  # args ratio
    # row-normalized adjacency for mean aggregation (+ self connection)
    A = A + np.eye(N, dtype=np.float32)
    A = A / A.sum(1, keepdims=True)
    return torch.tensor(X), torch.tensor(A)


# ---- model ------------------------------------------------------------------
class SAGELayer(nn.Module):
    def __init__(self, i, o):
        super().__init__()
        self.self_lin = nn.Linear(i, o)
        self.neigh_lin = nn.Linear(i, o)

    def forward(self, x, A):
        return F.relu(self.self_lin(x) + self.neigh_lin(A @ x))


class GNN(nn.Module):
    def __init__(self, in_dim, hid=32, n_class=2):
        super().__init__()
        self.c1 = SAGELayer(in_dim, hid)
        self.c2 = SAGELayer(hid, hid)
        self.drop = nn.Dropout(0.4)
        self.head = nn.Sequential(nn.Linear(2 * hid, hid), nn.ReLU(),
                                  nn.Dropout(0.4), nn.Linear(hid, n_class))

    def forward(self, x, A):
        h = self.c1(x, A)
        h = self.drop(h)
        h = self.c2(h, A)
        pooled = torch.cat([h.mean(0), h.max(0).values])   # [2*hid]
        return self.head(pooled)


def train_eval(train, test, in_dim, epochs=120, lr=5e-3):
    y_tr = torch.tensor([1 if r["origin"] == "ai" else 0 for r in train])
    w = torch.tensor([1.0 / max((y_tr == 0).sum(), 1), 1.0 / max((y_tr == 1).sum(), 1)])
    w = w / w.sum() * 2
    model = GNN(in_dim)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(len(train))
        opt.zero_grad()
        loss = 0.0
        for i in perm:
            r = train[i]
            logit = model(r["g"][0], r["g"][1]).unsqueeze(0)
            loss = loss + F.cross_entropy(logit, y_tr[i:i + 1], weight=w)
        (loss / len(train)).backward()
        opt.step()
    model.eval()
    preds = []
    with torch.no_grad():
        for r in test:
            p = model(r["g"][0], r["g"][1]).argmax().item()
            preds.append("ai" if p == 1 else "human")
    return preds


# SVC in the SAME fair space as ids_model_generalization.py (this is where the
# 0.76 floor comes from): common binaries only, no args, first 20, network removed.
NETW = {"ssh", "scp", "ping", "arp", "nmap", "netstat", "ss", "ip", "ifconfig",
        "route", "traceroute", "telnet", "ftp", "nc"}


def gnn_predict_scores(model, graphs):
    model.eval()
    out = []
    with torch.no_grad():
        for g in graphs:
            p = F.softmax(model(g[0], g[1]), dim=-1)[1].item()  # P(ai)
            out.append(p)
    return out


def train_model(train, in_dim, epochs=120, lr=5e-3):
    y_tr = torch.tensor([1 if r["origin"] == "ai" else 0 for r in train])
    w = torch.tensor([1.0 / max((y_tr == 0).sum(), 1), 1.0 / max((y_tr == 1).sum(), 1)])
    w = w / w.sum() * 2
    model = GNN(in_dim)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)
    for ep in range(epochs):
        model.train(); opt.zero_grad(); loss = 0.0
        for i in torch.randperm(len(train)):
            logit = model(train[i]["g"][0], train[i]["g"][1]).unsqueeze(0)
            loss = loss + F.cross_entropy(logit, y_tr[i:i + 1], weight=w)
        (loss / len(train)).backward(); opt.step()
    return model


def main():
    rows = [r for r in load()]
    for r in rows:
        r["g"] = to_graph(r["cmds"])
    rows = [r for r in rows if r["g"] is not None]
    in_dim = len(CATS) + 5
    by_model = Counter(r["model"] for r in rows if r["origin"] == "ai")
    ai_rows = [r for r in rows if r["origin"] == "ai"]
    hu_rows = [r for r in rows if r["origin"] == "human"]
    print("=" * 78)
    print("GNN vs LinearSVC vs ENSEMBLE — leave-one-MODEL-out (held-out AI recall)")
    print("=" * 78)
    print(f"  AI sessions: {dict(by_model)}   human: {len(hu_rows)}")
    print(f"  GNN node features: {in_dim}-dim behavioral ({', '.join(CATS)} + freq/out/in/self/args)")
    print(f"  SVC space: common binaries, no args, first-20, network removed (the 0.76-floor setting)\n")

    # common binaries between AI and human, minus network -> SVC fair vocab
    acnt = Counter(head(c) for r in ai_rows for c in r["cmds"])
    hcnt = Counter(head(c) for r in hu_rows for c in r["cmds"])
    vocab = (set(acnt) & set(hcnt)) - NETW

    def svc_doc(r):
        return " ".join(head(c) for c in r["cmds"][:20] if head(c) in vocab)

    order = ["gemma3", "gemma4", "llama", "qwen", "gemini3pro", "geminiflash",
             "gemini25pro", "gemini25flash"]
    models = [m for m in order if by_model.get(m, 0) >= 2] + \
             [m for m in by_model if m not in order and by_model[m] >= 2]
    rng = random.Random(SEED)
    print(f"  {'held-out':<12}{'SVC':>7}{'GNN':>7}{'ENSEMBLE':>10}{'ens 95% CI':>16}{'humFP':>8}")
    svc_s, gnn_s, ens_s, fp_s = [], [], [], []
    for held in models:
        train = [r for r in rows if not (r["origin"] == "ai" and r["model"] == held)]
        test_ai = [r for r in rows if r["origin"] == "ai" and r["model"] == held]
        # hold out 25% of humans (not in training) to measure ensemble false positives
        hu_idx = list(range(len(hu_rows))); rng.shuffle(hu_idx)
        hu_test = [hu_rows[i] for i in hu_idx[:max(20, len(hu_rows) // 4)]]
        hu_test_set = set(id(r) for r in hu_test)
        train = [r for r in train if not (r["origin"] == "human" and id(r) in hu_test_set)]

        # SVC (fair space)
        pipe = Pipeline([("tf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=10000)),
                         ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])
        Xtr = [svc_doc(r) for r in train if len(svc_doc(r).split()) >= 3]
        ytr = [r["origin"] for r in train if len(svc_doc(r).split()) >= 3]
        pipe.fit(Xtr, ytr)
        svc_ai = ["ai" if p == "ai" else "human" for p in pipe.predict([svc_doc(r) for r in test_ai])]
        svc_hu = pipe.predict([svc_doc(r) for r in hu_test])

        # GNN
        gmodel = train_model(train, in_dim)
        gnn_ai = ["ai" if s >= 0.5 else "human" for s in gnn_predict_scores(gmodel, [r["g"] for r in test_ai])]
        gnn_hu = ["ai" if s >= 0.5 else "human" for s in gnn_predict_scores(gmodel, [r["g"] for r in hu_test])]

        # ENSEMBLE = OR (recall-oriented): AI if either detector says AI
        ens_ai = ["ai" if (a == "ai" or b == "ai") else "human" for a, b in zip(svc_ai, gnn_ai)]
        ens_hu = ["ai" if (a == "ai" or b == "ai") else "human" for a, b in zip(svc_hu, gnn_hu)]

        svc_rec = np.mean([p == "ai" for p in svc_ai])
        gnn_rec = np.mean([p == "ai" for p in gnn_ai])
        ens_ind = [1 if p == "ai" else 0 for p in ens_ai]
        ens_rec = float(np.mean(ens_ind))
        elo, ehi = bootstrap_ci(ens_ind)
        ens_fp = np.mean([p == "ai" for p in ens_hu])
        svc_s.append(svc_rec); gnn_s.append(gnn_rec); ens_s.append(ens_rec); fp_s.append(ens_fp)
        fr = "*" if held.startswith("gemini") else " "
        print(f" {fr}{held:<11}{svc_rec:>7.2f}{gnn_rec:>7.2f}{ens_rec:>10.2f}"
              f"   [{elo:.2f},{ehi:.2f}]{ens_fp:>8.2f}   (n={len(test_ai)})")
    print("  " + "-" * 62)
    print(f"  {'MEAN':<11}{np.mean(svc_s):>7.2f}{np.mean(gnn_s):>7.2f}{np.mean(ens_s):>10.2f}"
          f"{'':>16}{np.mean(fp_s):>8.2f}")
    print(f"  {'FLOOR':<11}{min(svc_s):>7.2f}{min(gnn_s):>7.2f}{min(ens_s):>10.2f}")
    print(f"\n  (* = frontier Gemini family, never in training)")
    print(f"  >> SVC floor {min(svc_s):.2f} -> Ensemble floor {min(ens_s):.2f} "
          f"({min(ens_s)-min(svc_s):+.2f}), at {np.mean(fp_s):.2f} mean human FP rate.")


if __name__ == "__main__":
    print("Historical evaluator superseded: running the corrected host-v2 protocol.")
    from evaluate_host_v2 import main as corrected_main
    corrected_main()
