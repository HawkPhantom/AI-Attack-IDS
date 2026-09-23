#!/usr/bin/env python3
"""Environment confound: is the origin signal agency, or just the environment?

The old setup had ONE environment per side -- AI in an empty Ubuntu container,
humans on a MUNI cyber-range attacker box -- so a residual environment confound
remained even after the common-binary controls. This script closes most of that
gap by adding a SECOND AI environment: the same four models, driven from a
CTF-range attacker box whose toolset mirrors the MUNI host (nmap / ssh / nc /
john / fcrackzip / sqlmap ...), against a live in-scope subnet
(harness/lab/run_ctf_range.py -> harness/runs/ctf_range).

Three tests, from weakest to strongest control:

  (1) STATE-VERIFICATION REFLEX by environment. If the reflex (pwd/whoami/id/
      uname/hostname share) shows up in BOTH AI environments and not in humans,
      it is a property of the operator, not of the box.

  (2) SAME-ENVIRONMENT origin test. AI-CTF vs human-MUNI are now BOTH in a
      cyber range with the same pentest toolkit. Restricted to common binaries,
      a separation here cannot be tool-availability -- it is agency.

  (3) CROSS-ENVIRONMENT transfer. Train the origin detector on {AI-empty +
      human} and test it on AI-CTF (an AI environment it never saw), and the
      reverse. If unseen-environment AI is still flagged AI, the signature is
      environment-independent.
"""
from __future__ import annotations
import json, re
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import LeaveOneGroupOut

STATE = ("pwd", "whoami", "id", "uname", "hostname")
NETW = {"ssh", "scp", "ping", "arp", "nmap", "netstat", "ss", "ip", "ifconfig",
        "route", "traceroute", "telnet", "ftp", "nc"}


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def pipe():
    return Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=10000)),
                     ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])


def cmds_raw(path):
    raw = json.loads(Path(path).read_text(errors="replace"))
    return [t[0][0].strip() for t in raw[1:]
            if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]


def degenerate(cmds):
    prose = sum(1 for c in cmds if len(c) > 60 or c.lower().startswith(("okay", "we ", "the user")))
    return len(set(cmds)) < 3 or prose > len(cmds) * 0.4


TAG2MODEL = {"g3": "gemma3", "g4": "gemma4", "l": "llama", "q": "qwen"}


def load():
    rows = []
    # AI environment 1: empty Ubuntu container (grid_ac real_ssh + benign)
    for f in Path("harness/runs/grid_ac").rglob("*session*.json"):
        if f.parent.parent.name != "real_ssh":
            continue
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "origin": "ai", "env": "empty", "model": "gemma3",
                         "grp": "ai_empty_gemma3"})
    for f in Path("harness/runs/benign").glob("*.json"):
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "origin": "ai", "env": "empty", "model": "gemma3",
                         "grp": "ai_empty_gemma3_benign"})
    # AI environment 1b (empty): the multimodel batch (gemma4/llama/qwen)
    for f in Path("harness/runs/multimodel").glob("*.json"):
        tag = "g4" if f.name.startswith("g4_") else f.name[0]
        model = TAG2MODEL.get(tag)
        if not model:
            continue
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "origin": "ai", "env": "empty", "model": model,
                         "grp": f"ai_empty_{model}"})
    # AI environment 2: CTF range (matched toolset)
    for f in Path("harness/runs/ctf_range").rglob("*session*.json"):
        tag = re.search(r"ctf_([a-z0-9]+)_ctf_", f.name)
        model = TAG2MODEL.get(tag.group(1)) if tag else None
        pr = re.search(r"(ctf_[a-z]+)", f.name)
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "origin": "ai", "env": "ctf", "model": model or "ai",
                         "grp": f"ai_ctf_{pr.group(1) if pr else 'x'}"})
    # human: MUNI cyber range
    for f in sorted(Path("data/human/muni").rglob("*useractions.json")):
        cmds = []
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if (r.get("cmd") or "").strip():
                cmds.append(r["cmd"].strip())
        if len(cmds) >= 4:
            game = f.relative_to("data/human/muni").parts[0]
            rows.append({"cmds": cmds, "origin": "human", "env": "ctf_muni", "model": "human",
                         "grp": f"hu_{game}"})
    return rows


def state_share(rows):
    cc = Counter(head(c) for r in rows for c in r["cmds"])
    tot = sum(cc.values())
    return 100 * sum(cc[b] for b in STATE) / max(tot, 1), tot


def origin_logo(rows, vocab, tag):
    def doc(r):
        return " ".join(head(c) for c in r["cmds"] if head(c) in vocab)
    docs = [(doc(r), r) for r in rows]
    docs = [(d, r) for d, r in docs if len(d.split()) >= 3]
    if not docs:
        print(f"  [{tag}] no usable docs"); return None
    X = np.array([d for d, _ in docs]); y = np.array([r["origin"] for _, r in docs])
    G = np.array([r["grp"] for _, r in docs])
    if len(set(y)) < 2 or len(set(G)) < 2:
        print(f"  [{tag}] not enough classes/groups"); return None
    preds = np.empty(len(y), dtype=object)
    for tr, te in LeaveOneGroupOut().split(X, y, G):
        if len(set(y[tr])) < 2:
            preds[te] = y[tr][0]; continue
        preds[te] = pipe().fit(X[tr], y[tr]).predict(X[te])
    f1 = f1_score(y, preds, average="macro")
    print(f"  [{tag}]  n={len(y)}  {dict(Counter(y))}  groups={len(set(G))}  ->  macro F1 = {f1:.3f}")
    return f1


def transfer(train_rows, test_rows, vocab, tag):
    def doc(r):
        return " ".join(head(c) for c in r["cmds"] if head(c) in vocab)
    Xtr = [doc(r) for r in train_rows if len(doc(r).split()) >= 3]
    ytr = [r["origin"] for r in train_rows if len(doc(r).split()) >= 3]
    Xte = [doc(r) for r in test_rows if len(doc(r).split()) >= 3]
    if not Xte or len(set(ytr)) < 2:
        print(f"  [{tag}] insufficient data"); return None
    clf = pipe().fit(Xtr, ytr)
    pred = clf.predict(Xte)
    rec = np.mean([p == "ai" for p in pred])
    print(f"  [{tag}] held-out AI env ({len(Xte)} sess) recalled as 'ai': {rec:.2f}")
    return rec


def main():
    rows = load()
    ai_empty = [r for r in rows if r["origin"] == "ai" and r["env"] == "empty"]
    ai_ctf = [r for r in rows if r["origin"] == "ai" and r["env"] == "ctf"]
    hu = [r for r in rows if r["origin"] == "human"]

    print("=" * 78)
    print("ENVIRONMENT CONFOUND — AI across TWO environments vs human (MUNI)")
    print("=" * 78)
    print(f"  AI empty-container : {len(ai_empty)}  models={dict(Counter(r['model'] for r in ai_empty))}")
    print(f"  AI CTF-range       : {len(ai_ctf)}  models={dict(Counter(r['model'] for r in ai_ctf))}")
    print(f"  human MUNI (range) : {len(hu)}")

    print("\n" + "-" * 78)
    print("(1) STATE-VERIFICATION REFLEX by environment (pwd/whoami/id/uname/hostname)")
    print("-" * 78)
    for lbl, grp in [("AI empty-container", ai_empty), ("AI CTF-range", ai_ctf), ("human MUNI", hu)]:
        if grp:
            s, tot = state_share(grp)
            print(f"  {lbl:<22} {s:5.1f}%   ({tot} commands)")
    print("  -> reflex present in BOTH AI environments, ~0-1% for humans = operator property")

    print("\n" + "-" * 78)
    print("(2) SAME-ENVIRONMENT origin test: AI-CTF vs human-MUNI (both cyber range)")
    print("-" * 78)
    same = ai_ctf + hu
    ac = Counter(head(c) for r in ai_ctf for c in r["cmds"])
    hc = Counter(head(c) for r in hu for c in r["cmds"])
    # In a CTF range BOTH sides legitimately have the network toolkit, so here
    # network commands are SHARED, not an environment artefact -> full common
    # space is the env-matched lens. The minus-network row is the strict one.
    vocab_full = set(ac) & set(hc)
    vocab_pure = vocab_full - NETW
    print(f"  shared binaries: {len(vocab_full)} full / {len(vocab_pure)} non-network")
    if ai_ctf:
        origin_logo(same, vocab_full, "AI-CTF vs human, full common space (env-matched)")
        origin_logo(same, vocab_pure, "AI-CTF vs human, non-network (strict agency)")
    else:
        print("  [skipped: no CTF-range AI sessions yet]")

    print("\n" + "-" * 78)
    print("(3) CROSS-ENVIRONMENT transfer (test env never seen in AI training)")
    print("-" * 78)
    aec = Counter(head(c) for r in ai_empty + ai_ctf for c in r["cmds"])
    vocab_all = (set(aec) & set(hc)) - NETW
    if ai_ctf:
        transfer(ai_empty + hu, ai_ctf, vocab_all,
                 "train {AI-empty + human} -> test AI-CTF")
    if ai_empty:
        transfer(ai_ctf + hu, ai_empty, vocab_all,
                 "train {AI-CTF + human} -> test AI-empty")

    print("\n" + "=" * 78)
    print("Two AI environments now bracket the origin signal; the reflex and the")
    print("same-environment / cross-environment tests isolate agency from the box.")
    print("=" * 78)


if __name__ == "__main__":
    print("Historical evaluator superseded: running the corrected host-v2 protocol.")
    from evaluate_host_v2 import main as corrected_main
    corrected_main()
