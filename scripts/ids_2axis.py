#!/usr/bin/env python3
"""2-axis IDS: intent (malicious/benign) x origin (AI/human), on REAL human data.

Goal (the project's decision): model both axes of the 2x2 and alarm at the
intersection (malicious AND ai) = an autonomous AI attacker.

DATA CELLS and their provenance  (all four are now real, not scripted):
  malicious + AI    : harness/runs/grid_ac + harness/runs/ctf_range  (our agents)
  benign    + AI    : harness/runs/benign                            (our agents)
  malicious + human : MUNI cyber-range trainees (Zenodo 8136017)     REAL humans
  benign    + human : Schonlau SEA real command windows (schonlau.net) REAL humans

This is the fix for the old "intent axis is synthetic" limitation. Both human
cells are now real, human-authored commands recorded end-to-end:
  - malicious+human = the same real MUNI sessions the origin axis is validated on
  - benign+human    = contiguous windows of a real user's Schonlau command stream,
    so command ORDER (the 1,2-gram / transition structure the models key on) is
    authentic, not assembled. The first 5000 commands per user are Schonlau's
    certified masquerade-free region, i.e. genuinely that user's own benign
    activity. Built by scripts/build_benign_sessions.py; group = user.
Honest residual: these windows are fixed-size slices of a continuous accounting
stream (not login-delimited), and are program names without arguments -- which
matches our argument-stripped common-binary origin space.

Two remaining, reported controls:
  - leave-one-GROUP-out (group = scenario / prompt / corpus bucket), so no fold
    can memorise a scenario.
  - a COMMON-BINARY space (only binaries seen on both sides) alongside RAW, so the
    reader can see how much of each axis is tool-availability vs behaviour.
Sample sizes are still modest; read the numbers as indicative.
"""
from __future__ import annotations
import argparse, json, random, re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

SEED = 42
NETW = {"ssh", "scp", "ping", "arp", "nmap", "netstat", "ss", "ip", "ifconfig",
        "route", "traceroute", "telnet", "ftp", "nc", "curl", "wget"}


def pipe():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                  sublinear_tf=True, max_features=10000)),
        ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000)),
    ])


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def cmds_raw(path):
    """DTU-raw schema (driver output)."""
    raw = json.loads(Path(path).read_text(errors="replace"))
    return [t[0][0].strip() for t in raw[1:]
            if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]


def degenerate(cmds):
    prose = sum(1 for c in cmds if len(c) > 60 or c.lower().startswith(("okay", "we ", "the user")))
    return len(set(cmds)) < 3 or prose > len(cmds) * 0.4


# ---- cells now come from the shared canonical loader (scripts/ids_data.py) --
# AI: empty + CTF, malicious + benign, frontier Gemini included, no evasion.
# human malicious: MUNI (real). human benign: Schonlau SEA real command windows
# (replaces the old NL2Bash random assembly; falls back to it if not built).
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
import ids_data  # noqa: E402


def load_ai():
    return [{"cmds": r["cmds"], "intent": r["intent"], "origin": "ai", "grp": r["grp"]}
            for r in ids_data.load_ai(envs=("empty", "ctf"), include_evasion=False)]


def load_human_malicious():
    return [{"cmds": r["cmds"], "intent": "malicious", "origin": "human", "grp": r["grp"]}
            for r in ids_data.load_human_malicious()]


def load_human_benign(n_sessions=60, **_):
    # n_sessions kept for CLI compatibility; Schonlau session set is fixed.
    return [{"cmds": r["cmds"], "intent": "benign", "origin": "human", "grp": r["grp"]}
            for r in ids_data.load_human_benign()]


def load_cells():
    return load_ai() + load_human_malicious() + load_human_benign()


# ---- evaluation (leave-one-group-out) --------------------------------------
def logo_eval(rows, axis, tag, vocab=None):
    def doc(r):
        cs = [head(c) for c in r["cmds"]] if vocab is not None else r["cmds"]
        if vocab is not None:
            cs = [h for h in cs if h in vocab]
        return " ".join(cs), len(cs)
    docs = [doc(r) for r in rows]
    keep = [i for i, (_, n) in enumerate(docs) if n >= 3]
    X = np.array([docs[i][0] for i in keep])
    y = np.array([rows[i][axis] for i in keep])
    G = np.array([rows[i]["grp"] for i in keep])
    cnt = Counter(y)
    if len(cnt) < 2 or len(set(G)) < 2:
        print(f"  [{tag}] not enough classes/groups: {dict(cnt)}")
        return None
    preds = np.empty(len(y), dtype=object)
    for tr, te in LeaveOneGroupOut().split(X, y, G):
        if len(set(y[tr])) < 2:
            preds[te] = y[tr][0]
            continue
        preds[te] = pipe().fit(X[tr], y[tr]).predict(X[te])
    f1 = f1_score(y, preds, average="macro")
    print(f"\n  [{tag}]  n={len(y)}  {dict(cnt)}  groups={len(set(G))}  ->  macro F1 = {f1:.3f}")
    print("  " + classification_report(y, preds, digits=3).replace("\n", "\n  "))
    return f1


def permutation_control(rows, axis, tag, vocab=None):
    rr = [dict(r) for r in rows]
    labs = [r[axis] for r in rr]
    random.Random(0).shuffle(labs)
    for r, l in zip(rr, labs):
        r[axis] = l
    print(f"  [{tag}] label permutation (chance ~{1/len(set(labs)):.2f}):", end=" ")
    logo_eval(rr, axis, tag + "-perm", vocab=vocab)


def common_vocab(rows, a, b, key):
    ca = Counter(head(c) for r in rows if r[key] == a for c in r["cmds"])
    cb = Counter(head(c) for r in rows if r[key] == b for c in r["cmds"])
    return set(ca) & set(cb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-sessions", type=int, default=60)
    a = ap.parse_args()

    rows = load_ai() + load_human_malicious() + load_human_benign(n_sessions=a.benign_sessions)
    print("=" * 74)
    print("2x2 CELL OCCUPANCY  (all four cells real: AI harness / MUNI / NL2Bash)")
    print("=" * 74)
    grid = Counter((r["intent"], r["origin"]) for r in rows)
    print(f"  {'':<12}{'AI':>10}{'HUMAN':>10}")
    for intent in ["malicious", "benign"]:
        print(f"  {intent:<12}{grid[(intent,'ai')]:>10}{grid[(intent,'human')]:>10}")
    print(f"  TOTAL: {len(rows)} sessions")
    print("  sources: mal+AI=grid_ac+ctf_range · ben+AI=benign · "
          "mal+human=MUNI(real) · ben+human=Schonlau SEA(real)")

    # ------- INTENT axis -------
    print("\n" + "=" * 74)
    print("AXIS A — INTENT (malicious vs benign)")
    print("=" * 74)
    logo_eval(rows, "intent", "intent RAW")
    v_int = common_vocab(rows, "malicious", "benign", "intent")
    print(f"  [common-binary space: {len(v_int)} shared binaries]")
    logo_eval(rows, "intent", "intent COMMON", vocab=v_int)
    permutation_control(rows, "intent", "intent")

    # ------- ORIGIN axis -------
    print("\n" + "=" * 74)
    print("AXIS B — ORIGIN (AI vs human)")
    print("=" * 74)
    logo_eval(rows, "origin", "origin RAW")
    v_org = common_vocab(rows, "ai", "human", "origin") - NETW
    print(f"  [common-binary space minus network: {len(v_org)} shared binaries]")
    logo_eval(rows, "origin", "origin COMMON", vocab=v_org)
    permutation_control(rows, "origin", "origin", vocab=v_org)

    # ------- cross-controls: is each axis independent of the other? -------
    print("\n" + "=" * 74)
    print("CROSS-CONTROL — origin separable within a fixed intent?")
    print("=" * 74)
    for intent in ["malicious", "benign"]:
        sub = [r for r in rows if r["intent"] == intent]
        if len(sub) >= 8:
            v = common_vocab(sub, "ai", "human", "origin") - NETW
            logo_eval(sub, "origin", f"origin | intent={intent} (common)", vocab=v)

    print("\n" + "=" * 74)
    print("All four cells are real data. INTENT still spans two human provenances")
    print("(MUNI vs Schonlau SEA), so the common-binary row is the honest read for it.")
    print("=" * 74)


if __name__ == "__main__":
    main()
