#!/usr/bin/env python3
"""2-axis IDS: intent (malicious/benign) x origin (AI/human), on REAL human data.

Goal (the project's decision): model both axes of the 2x2 and alarm at the
intersection (malicious AND ai) = an autonomous AI attacker.

DATA CELLS and their provenance  (all four are now real, not scripted):
  malicious + AI    : harness/runs/grid_ac + harness/runs/ctf_range  (our agents)
  benign    + AI    : harness/runs/benign                            (our agents)
  malicious + human : MUNI cyber-range trainees (Zenodo 8136017)     REAL humans
  benign    + human : NL2Bash real shell one-liners (TellinaTool)    REAL humans

This is the fix for the old "intent axis is synthetic" limitation. Previously the
human cells were keystroke-replay of fixed scripted lists I wrote, so the intent
classifier largely learned "scripted list vs LLM generation". Both human cells
are now real, human-authored commands:
  - malicious+human = the same real MUNI sessions the origin axis is validated on
  - benign+human    = real NL2Bash commands (real selection + real argument style)
NL2Bash ships as independent one-liners, so a benign-human *session* is assembled
by sampling real commands (per-session head cap keeps them from collapsing onto
`find`, which is 60% of the corpus). Command text is real; only the grouping into
sessions is assembled -- an honest step up from wholly synthetic sessions.

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


# ---- AI cells ---------------------------------------------------------------
def load_ai():
    rows = []
    for f in Path("harness/runs/grid_ac").rglob("*session*.json"):
        if f.parent.parent.name != "real_ssh":
            continue
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            pr = re.search(r"(prompt_\d)", f.name)
            rows.append({"cmds": c, "intent": "malicious", "origin": "ai",
                         "grp": f"ai_mal_{pr.group(1) if pr else '?'}"})
    for f in Path("harness/runs/ctf_range").rglob("*session*.json"):
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            pr = re.search(r"(ctf_[a-z]+)", f.name)
            rows.append({"cmds": c, "intent": "malicious", "origin": "ai",
                         "grp": f"ai_mal_{pr.group(1) if pr else 'ctf'}"})
    for f in Path("harness/runs/benign").glob("*.json"):
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            pr = re.search(r"(benign_\d)", f.name)
            rows.append({"cmds": c, "intent": "benign", "origin": "ai",
                         "grp": f"ai_ben_{pr.group(1) if pr else '?'}"})
    return rows


# ---- human malicious: MUNI (real) ------------------------------------------
def load_human_malicious():
    rows = []
    for f in sorted(Path("data/human/muni").rglob("*useractions.json")):
        cmds = []
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            c = (r.get("cmd") or "").strip()
            if c:
                cmds.append(c)
        if len(cmds) >= 4:
            game = f.relative_to("data/human/muni").parts[0]
            rows.append({"cmds": cmds, "intent": "malicious", "origin": "human",
                         "grp": f"hu_mal_{game}"})
    return rows


# ---- human benign: NL2Bash real commands, assembled into sessions ----------
def load_human_benign(n_sessions=60, lo=6, hi=12, head_cap=2, seed=SEED):
    lines = [l.strip() for l in Path("data/human/nl2bash_all.cm").read_text(errors="replace").splitlines()
             if l.strip()]
    rng = random.Random(seed)
    rng.shuffle(lines)
    rows = []
    i = 0
    for s in range(n_sessions):
        k = rng.randint(lo, hi)
        sess, per = [], Counter()
        # walk the shuffled pool, respecting a per-session cap on any one head
        scanned = 0
        while len(sess) < k and scanned < len(lines):
            c = lines[i % len(lines)]; i += 1; scanned += 1
            h = head(c)
            if per[h] >= head_cap:
                continue
            per[h] += 1
            sess.append(c)
        if len(sess) >= 4:
            rows.append({"cmds": sess, "intent": "benign", "origin": "human",
                         "grp": f"hu_ben_bucket{s % 6}"})
    return rows


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
          "mal+human=MUNI(real) · ben+human=NL2Bash(real)")

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
    print("(MUNI vs NL2Bash), so the common-binary row is the honest read for it.")
    print("=" * 74)


if __name__ == "__main__":
    main()
