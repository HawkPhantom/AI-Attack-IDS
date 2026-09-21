#!/usr/bin/env python3
"""Model-genelleme: '0.962' bir gemma imzasi miydi yoksa LLM-ajan imzasi mi?

Test: KOKEN ekseni (AI vs gercek insan), ama AI tarafi 4 model:
  gemma3:4b (grid_ac + benign), gemma4, llama3.1:8b, qwen3:4b(filtreli)
Insan tarafi: MUNI (gercek).

LEAVE-ONE-MODEL-OUT: her seferinde bir AI modelini TAMAMEN disarida birak,
kalan modeller + insanla egit, disarida kalan modeli tanimaya calis. Model
gorulmemis bir LLM'i 'AI' olarak yakalayabiliyorsa -> imza modele ozgu DEGIL,
LLM-ajan ortak izi -> bilinmeyen modele genellesir (projenin cekirdek iddiasi).

qwen3:4b oturumlarinin ~%75'i rambling'e cokuyor; 'cokmus' oturumlar filtrelenir
(gercek bir ajan gibi davranmadiklari icin). Bu filtre raporlanir.
"""
import json, glob, re
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import f1_score


def head(c):
    return (c.split() or [""])[0].split("/")[-1]


def cmds_raw(path):
    raw = json.loads(Path(path).read_text(errors="replace"))
    return [t[0][0].strip() for t in raw[1:]
            if t and t[0] and (t[0][0] or "").strip() not in ("", "<model_error>")]


def degenerate(cmds):
    prose = sum(1 for c in cmds if len(c) > 60 or c.lower().startswith(("okay", "we ", "the user")))
    return len(set(cmds)) < 3 or prose > len(cmds) * 0.4


def load_ai():
    rows = []
    # gemma3: grid_ac (malicious) + benign
    for f in Path("harness/runs/grid_ac").rglob("*session*.json"):
        if f.parent.parent.name != "real_ssh":
            continue
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "model": "gemma3", "origin": "ai"})
    for f in glob.glob("harness/runs/benign/*.json"):
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "model": "gemma3", "origin": "ai"})
    # multimodel: qwen(q), llama(l), gemma4(g4)
    tagmap = {"q": "qwen", "l": "llama", "g4": "gemma4"}
    for f in glob.glob("harness/runs/multimodel/*.json"):
        name = Path(f).name
        tag = "g4" if name.startswith("g4_") else name[0]
        model = tagmap.get(tag)
        if not model:
            continue
        c = cmds_raw(f)
        if len(c) >= 4 and not degenerate(c):
            rows.append({"cmds": c, "model": model, "origin": "ai"})
    return rows


def load_human():
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
            if (r.get("cmd") or "").strip():
                cmds.append(r["cmd"].strip())
        if len(cmds) >= 4:
            rows.append({"cmds": cmds, "model": "human", "origin": "human",
                         "grp": f.parent.name})
    return rows


def pipe():
    return Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=10000)),
                     ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])


def main():
    ai = load_ai()
    hu = load_human()
    print("=" * 74)
    print("MODEL-GENELLEME — KOKEN EKSENI, 4 AI modeli + gercek insan")
    print("=" * 74)
    by_model = Counter(r["model"] for r in ai)
    print(f"  AI oturum (cokmus filtrelendi): {dict(by_model)}  toplam={len(ai)}")
    print(f"  insan oturum (MUNI): {len(hu)}")

    # ortak binary uzayi + arguman yok + ilk 20 komut (onceki adil kurulum)
    acnt = Counter(head(c) for r in ai for c in r["cmds"])
    hcnt = Counter(head(c) for r in hu for c in r["cmds"])
    common = set(acnt) & set(hcnt)
    NETW = {"ssh", "scp", "ping", "arp", "nmap", "netstat", "ss", "ip", "ifconfig",
            "route", "traceroute", "telnet", "ftp", "nc"}
    vocab = common - NETW

    def doc(r):
        return " ".join(head(c) for c in r["cmds"][:20] if head(c) in vocab)

    print(f"\n  adil uzay: {len(vocab)} ortak binary (ag komutlari haric, argumansiz, ilk20)")

    print("\n" + "=" * 74)
    print("LEAVE-ONE-MODEL-OUT: gorulmemis LLM 'AI' olarak yakalaniyor mu?")
    print("=" * 74)
    models = [m for m in ["gemma3", "gemma4", "llama", "qwen"] if by_model.get(m, 0) >= 2]
    hu_docs = [(doc(r), "human") for r in hu]
    hu_docs = [d for d in hu_docs if len(d[0].split()) >= 3]
    for held in models:
        train = [r for r in ai if r["model"] != held]
        test = [r for r in ai if r["model"] == held]
        Xtr = [doc(r) for r in train if len(doc(r).split()) >= 3] + [d for d, _ in hu_docs]
        ytr = ["ai"] * sum(1 for r in train if len(doc(r).split()) >= 3) + ["human"] * len(hu_docs)
        clf = pipe().fit(Xtr, ytr)
        Xte = [doc(r) for r in test if len(doc(r).split()) >= 3]
        if not Xte:
            print(f"  {held:<8}: gecerli test oturumu yok")
            continue
        pred = clf.predict(Xte)
        recall = np.mean([p == "ai" for p in pred])
        print(f"  {held:<8} disarida ({len(Xte)} oturum, egitimde YOK) -> "
              f"'ai' olarak taninma orani: {recall:.2f}")

    print("\n" + "=" * 74)
    print("AILE-ICI: gemma3 vs gemma4 durum-dogrulama imzasi ayni mi?")
    print("=" * 74)
    for m in ["gemma3", "gemma4", "llama", "qwen"]:
        rows = [r for r in ai if r["model"] == m]
        if not rows:
            continue
        cc = Counter(head(c) for r in rows for c in r["cmds"])
        tot = sum(cc.values())
        state = sum(cc[b] for b in ("pwd", "whoami", "id", "uname", "hostname"))
        print(f"  {m:<8} durum-dogrulama (pwd/whoami/id/uname/hostname): "
              f"{100*state/max(tot,1):.1f}%  | top5: {[b for b,_ in cc.most_common(5)]}")
    hc = Counter(head(c) for r in hu for c in r["cmds"])
    htot = sum(hc.values())
    hstate = sum(hc[b] for b in ("pwd", "whoami", "id", "uname", "hostname"))
    print(f"  {'insan':<8} durum-dogrulama: {100*hstate/max(htot,1):.1f}%  | "
          f"top5: {[b for b,_ in hc.most_common(5)]}")


if __name__ == "__main__":
    main()
