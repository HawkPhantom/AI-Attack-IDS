#!/usr/bin/env python3
"""Model-genelleme: '0.962' bir gemma imzasi miydi yoksa LLM-ajan imzasi mi?

Test: KOKEN ekseni (AI vs gercek insan), AI tarafi ALTI model ailesi:
  gemma3:4b, gemma4, llama3.1:8b, qwen3:4b  (yerel, kucuk)  +
  gemini-3.1-pro, gemini-3.5-flash          (FRONTIER, uzak API)
Insan tarafi: MUNI (gercek).

LEAVE-ONE-MODEL-OUT: her seferinde bir AI modelini TAMAMEN disarida birak,
kalan modeller + insanla egit, disarida kalan modeli tanimaya calis. Gorulmemis
bir LLM 'AI' olarak yakalanabiliyorsa -> imza modele ozgu DEGIL. Frontier bir
aile (Gemini 3.x) hic egitimde yokken hala yakalaniyorsa, iddia en guclu halini
alir: bu bir 'kucuk-model' ya da 'gemma' izi degil, LLM-ajan izidir.

Her held-out recall'i icin bootstrap %95 GA raporlanir (kucuk n'de durustluk).
qwen3:4b oturumlarinin ~%75'i rambling'e cokuyor; 'cokmus' oturumlar filtrelenir.
"""
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ids_data import (load_ai, load_human_malicious, head, state_share, NETW)  # noqa: E402

SEED = 42


def pipe():
    return Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, max_features=10000)),
                     ("clf", LinearSVC(C=1.0, class_weight="balanced", max_iter=10000))])


def bootstrap_ci(indicators, B=3000, seed=SEED):
    """95% percentile CI for the mean of a 0/1 vector (held-out recall)."""
    a = np.asarray(indicators, dtype=float)
    if len(a) == 0:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    means = a[rng.integers(0, len(a), size=(B, len(a)))].mean(1)
    return float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def main():
    # empty-container AI only (the generalisation scope); no evasion sessions
    ai = load_ai(envs=("empty",), include_evasion=False)
    hu = load_human_malicious()
    print("=" * 74)
    print("MODEL-GENELLEME — KOKEN EKSENI, yerel + FRONTIER AI modelleri + gercek insan")
    print("=" * 74)
    by_model = Counter(r["model"] for r in ai)
    print(f"  AI oturum (cokmus filtrelendi): {dict(by_model)}  toplam={len(ai)}")
    print(f"  insan oturum (MUNI): {len(hu)}")

    acnt = Counter(head(c) for r in ai for c in r["cmds"])
    hcnt = Counter(head(c) for r in hu for c in r["cmds"])
    vocab = (set(acnt) & set(hcnt)) - NETW

    def doc(r):
        return " ".join(head(c) for c in r["cmds"][:20] if head(c) in vocab)

    print(f"\n  adil uzay: {len(vocab)} ortak binary (ag komutlari haric, argumansiz, ilk20)")

    print("\n" + "=" * 74)
    print("LEAVE-ONE-MODEL-OUT: gorulmemis LLM 'AI' olarak yakalaniyor mu?  [%95 GA]")
    print("=" * 74)
    order = ["gemma3", "gemma4", "llama", "qwen", "gemini3pro", "geminiflash",
             "gemini25pro", "gemini25flash"]
    models = [m for m in order if by_model.get(m, 0) >= 2] + \
             [m for m in by_model if m not in order and by_model[m] >= 2]
    hu_docs = [doc(r) for r in hu]
    hu_docs = [d for d in hu_docs if len(d.split()) >= 3]
    recalls = {}
    for held in models:
        train = [r for r in ai if r["model"] != held]
        test = [r for r in ai if r["model"] == held]
        Xtr = [doc(r) for r in train if len(doc(r).split()) >= 3] + hu_docs
        ytr = ["ai"] * sum(1 for r in train if len(doc(r).split()) >= 3) + ["human"] * len(hu_docs)
        clf = pipe().fit(Xtr, ytr)
        Xte = [doc(r) for r in test if len(doc(r).split()) >= 3]
        if not Xte:
            print(f"  {held:<12}: gecerli test oturumu yok")
            continue
        ind = [1 if p == "ai" else 0 for p in clf.predict(Xte)]
        recall = float(np.mean(ind))
        lo, hi = bootstrap_ci(ind)
        recalls[held] = recall
        frontier = " (FRONTIER)" if held.startswith("gemini") else ""
        print(f"  {held:<12} disarida ({len(Xte):>2} oturum) -> 'ai' taninma: "
              f"{recall:.2f}  [{lo:.2f}, {hi:.2f}]{frontier}")
    if recalls:
        floor = min(recalls.values())
        fmodel = min(recalls, key=recalls.get)
        print("  " + "-" * 58)
        print(f"  FLOOR = {floor:.2f}  ({fmodel})   MEAN = {np.mean(list(recalls.values())):.2f}")
        gem = {m: r for m, r in recalls.items() if m.startswith("gemini")}
        if gem:
            print(f"  frontier (Gemini) held-out recall: "
                  f"{', '.join(f'{m}={r:.2f}' for m, r in gem.items())}")

    print("\n" + "=" * 74)
    print("DURUM-DOGRULAMA REFLEKSI — model ailesine gore (frontier dahil)")
    print("=" * 74)
    for m in models:
        rows = [r for r in ai if r["model"] == m]
        cc = Counter(head(c) for r in rows for c in r["cmds"])
        tot = sum(cc.values())
        state = sum(cc[b] for b in ("pwd", "whoami", "id", "uname", "hostname"))
        print(f"  {m:<12} durum-dogrulama: {100*state/max(tot,1):>5.1f}%  | "
              f"top5: {[b for b,_ in cc.most_common(5)]}")
    hc = Counter(head(c) for r in hu for c in r["cmds"])
    htot = sum(hc.values())
    hstate = sum(hc[b] for b in ("pwd", "whoami", "id", "uname", "hostname"))
    print(f"  {'insan':<12} durum-dogrulama: {100*hstate/max(htot,1):>5.1f}%  | "
          f"top5: {[b for b,_ in hc.most_common(5)]}")


if __name__ == "__main__":
    print("Historical evaluator superseded: running the corrected host-v2 protocol.")
    from evaluate_host_v2 import main as corrected_main
    corrected_main()
